#include <stdio.h>
#include <stdlib.h>
#include <limits.h>

int n;
int dist[25][25];
int dp[1<<20][20];

int solve_tsp() {
    int full = (1 << n) - 1;
    for (int mask = 0; mask <= full; mask++)
        for (int i = 0; i < n; i++)
            dp[mask][i] = INT_MAX/2;
    
    dp[1][0] = 0;
    
    for (int mask = 1; mask <= full; mask++) {
        for (int u = 0; u < n; u++) {
            if (!(mask & (1 << u))) continue;
            if (dp[mask][u] >= INT_MAX/2) continue;
            for (int v = 0; v < n; v++) {
                if (mask & (1 << v)) continue;
                int nm = mask | (1 << v);
                int nc = dp[mask][u] + dist[u][v];
                if (nc < dp[nm][v])
                    dp[nm][v] = nc;
            }
        }
    }
    
    // TSP: return to start
    int tour = INT_MAX;
    for (int u = 0; u < n; u++)
        if (dp[full][u] + dist[u][0] < tour)
            tour = dp[full][u] + dist[u][0];
    
    // Also compute path (no return)
    int path = INT_MAX;
    for (int u = 0; u < n; u++)
        if (dp[full][u] < path)
            path = dp[full][u];
    
    fprintf(stderr, "tour=%d path=%d\n", tour, path);
    printf("%d\n", tour);
    fflush(stdout);
    return tour;
}

int main() {
    while (scanf("%d", &n) == 1) {
        for (int i = 0; i < n; i++)
            for (int j = 0; j < n; j++)
                scanf("%d", &dist[i][j]);
        solve_tsp();
    }
    return 0;
}
