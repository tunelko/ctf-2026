# Bricktator v2

| Campo | Valor |
|-------|-------|
| Plataforma | UMassCTF 2026 |
| Categoría | web / crypto |
| Puntos | 460 |
| Solves | 33 |

## TL;DR
Misma Shamir recovery pero sin heapdump. Timing side channel en CommandWorkFilter: BCrypt(strength=13) ~1.15s para YANKEE_WHITE vs ~0.30s para Q_CLEARANCE.

## Diferencias con v1
- Actuator: solo health,info,sessions (no heapdump)
- Accesslog endpoint disabled
- PRIME "corrupted" en source (sigue siendo 2^31-1)

## Attack Chain
1. Confirmar PRIME=2^31-1 probando session IDs generados
2. Timing side channel: GET /command con cada session cookie, medir response time
3. YANKEE_WHITE: ~1.15s (BCrypt) vs Q_CLEARANCE: ~0.30s (skip)
4. Escaneo secuencial 5000 sesiones (~25 min, dentro de ventana 30 min reset)
5. Override con 5 YANKEE_WHITE -> flag

## Flag
UMASS{stUx_n3T_a1nt_g0T_n0th1nG_0N_th15_v2!!!randomNoiseAndStuff}

## Key Lessons
- Deshabilitar endpoint no deshabilita la logica: BCrypt sigue ejecutandose
- Timing side channel: 850ms de diferencia es trivialmente detectable
- "Secret corrupted" != secret changed: probar valor original
