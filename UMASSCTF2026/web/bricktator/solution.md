# Bricktator

| Campo | Valor |
|-------|-------|
| Plataforma | UMassCTF 2026 |
| Categoría | web / crypto |
| Puntos | 416 |
| Solves | 47 |

## TL;DR
Shamir polynomial recovery (3 known points) + JVM heapdump hprof parsing para encontrar YANKEE_WHITE sessions + 5-party override approval.

## Attack Chain
1. Login bricktator/goldeagle -> session ID (5001, p(5001))
2. Actuator /sessions?username=john_doe,jane_doe -> 2 more polynomial points
3. Lagrange interpolation mod 2^31-1 -> all 5001 session IDs
4. /actuator/heapdump -> parse hprof: MapSession -> ConcurrentHashMap -> Node[] -> Node.val -> String("YANKEE_WHITE")
5. Override approval with 5 YANKEE_WHITE sessions -> flag

## Flag
UMASS{stUx_n3T_a1nt_g0T_n0th1nG_0N_th15}

## Key Lessons
- Actuator heapdump expone toda la memoria JVM
- Shamir threshold=3 se rompe con 3 puntos (login + actuator)
- Spring Session usa Base64 estandar con padding, no URL-safe
