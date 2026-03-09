#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    time_t now = time(NULL);
    time_t window = now / 300;
    srand((unsigned int)window);
    int r1 = rand();
    int r2 = rand();
    int r3 = rand();
    printf("ctf-%08x-%08x-%08x\n", r1, r2, r3);
    return 0;
}
