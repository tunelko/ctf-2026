#include <sys/syscall.h>
#include <unistd.h>
#include <string.h>

void ps(const char *s) { write(1, s, strlen(s)); }
void pn(long val) {
    char buf[24]; int i = 23; buf[i] = 0;
    int neg = 0;
    if (val < 0) { neg = 1; val = -val; }
    if (val == 0) { ps("0"); return; }
    while (val > 0) { buf[--i] = '0' + (val % 10); val /= 10; }
    if (neg) buf[--i] = '-';
    ps(buf + i);
}
void phex(unsigned char *buf, int len) {
    const char *h = "0123456789abcdef";
    for (int i = 0; i < len; i++) {
        char out[3] = {h[buf[i]>>4], h[buf[i]&0xf], ' '};
        write(1, out, 3);
    }
}

long do_ioctl(int fd, unsigned long cmd, void *arg) {
    return syscall(SYS_ioctl, fd, cmd, arg);
}
unsigned int rv(int fd, unsigned long cmd) {
    unsigned int val = 0;
    do_ioctl(fd, cmd, &val);
    return val;
}

#define R0 0x80046480
#define R1 0x80046481
#define R2 0x80046482
#define R3 0x80046483
#define R4 0x80046484
#define R5 0x80046485
#define R6 0x80046486
#define FLAG 0x80406487
#define W8 0x40046488
#define ACT 0x00006489

int opp(int d) {
    if (d < 4) return (d + 2) % 4;
    return d ^ 1;
}

// Use DFS with path-based state
// Keep track of: for each depth, which direction was tried
#define MAX_DEPTH 500

int path[MAX_DEPTH];
int tried[MAX_DEPTH]; // bitmask of tried directions at each depth
int path_len = 0;
unsigned int dirs_at[MAX_DEPTH]; // R6 at each depth

void replay(int fd) {
    do_ioctl(fd, ACT, 0);
    for (int i = 0; i < path_len; i++) {
        unsigned int d = path[i];
        do_ioctl(fd, W8, &d);
    }
}

int main() {
    int fd = syscall(SYS_openat, -100, "/dev/challenge", 2, 0);
    if (fd < 0) { ps("OPEN FAIL\n"); return 1; }

    do_ioctl(fd, ACT, 0);
    ps("R0="); pn(rv(fd,R0)); ps(" R1="); pn(rv(fd,R1));
    ps(" R2="); pn(rv(fd,R2)); ps(" R3="); pn(rv(fd,R3)); ps("\n");

    dirs_at[0] = rv(fd, R6);
    tried[0] = 0;
    path_len = 0;

    int total_nodes = 1;
    int found = 0;

    while (!found) {
        // Find next untried direction at current depth
        unsigned int avail = dirs_at[path_len];
        int parent_dir = path_len > 0 ? opp(path[path_len - 1]) : -1;
        int moved = 0;

        for (int d = 0; d < 6; d++) {
            if (!(avail & (1 << d))) continue;       // not available
            if (tried[path_len] & (1 << d)) continue; // already tried
            if (d == parent_dir) continue;             // don't go back

            tried[path_len] |= (1 << d);

            // Try moving
            unsigned int dir = d;
            long ret = do_ioctl(fd, W8, &dir);
            if (ret != 0) continue;

            unsigned int r5 = rv(fd, R5);
            if (r5 != 0) {
                ps("Goal r5="); pn(r5); ps(" depth="); pn(path_len + 1);
                ps(" steps="); pn(rv(fd, R4)); ps("\n");

                if (r5 == 1) {
                    // This is the real goal!
                    char flag[64] = {0};
                    long fret = do_ioctl(fd, FLAG, flag);
                    ps("FLAG ret="); pn(fret); ps("\n");
                    ps("FLAG hex: "); phex((unsigned char*)flag, 64); ps("\n");
                    ps("FLAG="); write(1, flag, 64); ps("\n");
                    found = 1;
                    break;
                }

                // Not the right goal, dead end (can't move from here)
                // Reset and replay to current position
                replay(fd);
                continue;
            }

            // Moved to new room, push onto path
            path[path_len] = d;
            path_len++;
            dirs_at[path_len] = rv(fd, R6);
            tried[path_len] = 0;
            total_nodes++;
            moved = 1;

            if (total_nodes % 100 == 0) {
                ps("nodes="); pn(total_nodes);
                ps(" depth="); pn(path_len); ps("\n");
            }

            if (path_len >= MAX_DEPTH) {
                ps("Max depth reached\n");
                // Backtrack
                path_len--;
                replay(fd);
                moved = 0;
            }

            break;
        }

        if (found) break;

        if (!moved) {
            // Backtrack
            if (path_len == 0) {
                ps("Exhausted all paths! nodes="); pn(total_nodes); ps("\n");
                break;
            }
            path_len--;
            replay(fd);
        }
    }

    syscall(SYS_close, fd);
    return 0;
}
