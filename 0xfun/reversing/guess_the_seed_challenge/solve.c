#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main() {
    srand(time(NULL));
    printf("%d %d %d %d %d\n",
        rand() % 1000,
        rand() % 1000,
        rand() % 1000,
        rand() % 1000,
        rand() % 1000);
    return 0;
}
