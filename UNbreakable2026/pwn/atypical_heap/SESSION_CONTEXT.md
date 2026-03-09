# Session Context — 2026-03-06

## Retos trabajados
- **atypical_heap**: resuelto (local Docker), parcial remoto

## Resumen tecnico
- musl 1.2.5 mallocng heap exploitation
- 4 fases: heap meta leak -> meta corruption -> libc leak -> RCE
- Over-read en NOTE_READ (sz checks MAX_NOTE_SIZE not note.size)
- Unlimited arb write via NOTE_MAGIC (hidden option 5, no else/break after flag set)
- RCE via __stdio_exit: close_file calls f->write(f,0,0) bypassing F_ERR check
- Flag in distributed Docker files: `CTF{0h_s0_y0u_kn0w_h0w_t0_expl01t_mus1_t00_huh!?_c9c4ad670ecbd791}`

## Decisiones clave
- Used __stdio_exit path instead of atexit: more portable across page granularities
- Computed data_shift from dual libc pointer sets for remote compatibility
- Blind sendline after stdout corruption (F_ERR kills output but scanf still works)

## Pendientes / Next steps
- [ ] Remote exploit produces no shell output - investigate socat + system() interaction
- [ ] Alternative: use execve() or ORW chain instead of system() for remote

## Notas para la proxima sesion
- Remote server has 64KB pages -> 0x6000 shift between libc text and data
- atexit approach (builtin at libc+0xa36a0) works local but needs shift for remote
- close_file path confirmed working local, verified via disassembly at libc+0x4ba09
