# Mr. Worldwide — DawgCTF 2026 (MISC)

## TL;DR
TSP (Traveling Salesman Problem) solver. Receive adjacency matrix, compute minimum tour distance, reply fast.

## Approach
- Held-Karp exact TSP algorithm in C (O(n² × 2^n))
- n=20 → ~400M ops, runs in <1s in C
- Python was too slow (18s), C solved it instantly

## Flag
```
DawgCTF{wh4t_l4ngu4ag3_d1d_y0u_us3?}
```
