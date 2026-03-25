# Inheritance

| Campo | Valor |
|-------|-------|
| **CTF** | BSidesSF CTF 2026 |
| **Categoria** | Pwn |
| **Puntos** | 856 |
| **Flag** | `CTF{0_cl03x3c_1s_y0ur_fr13nd_f0r_fd_l34ks}` |

---

## TL;DR

File descriptor inheritance: the binary loads `flag.txt` into a `memfd_create()` FD (FD 6), then calls `system()` with user input. The FD is inherited by the child process. Bypass keyword filter ("flag", "proc", "fd", ".txt") and redirection filter ("<", ">") using `bash -c 'read -u6 l;echo $l'`.

---

## Analisis

El binario:
1. `fopen("flag.txt", "r")` → lee la flag (128 bytes)
2. `memfd_create("secret_config", 0)` → crea FD anonimo en memoria
3. `write(fd, flag_content, len)` → escribe la flag al memfd
4. `lseek(fd, 0, 0)` → rebobina el FD
5. Imprime `"Secret configuration securely loaded into memory (FD %d)"` → revela el numero de FD (6)
6. Lee comando del usuario (max 32 chars)
7. Filtra: `<` y `>` (redirecciones bloqueadas)
8. Filtra palabras: `"flag"`, `"proc"`, `"fd"`, `".txt"` via `strstr()`
9. Si pasa los filtros, ejecuta `system(command)`

## Vulnerabilidad

**FD Inheritance** (CWE-403): el file descriptor del memfd NO se cierra antes de `system()`, y NO tiene `O_CLOEXEC`. El proceso hijo hereda el FD abierto.

## Explotacion

`bash -c 'read -u6 l;echo $l'` (28 chars):
- `bash` tiene el built-in `read -u FD` que lee de un FD especifico sin usar redirecciones shell
- No contiene ninguna keyword bloqueada ("flag", "proc", "fd", ".txt")
- No usa `<` ni `>` (los caracteres de redireccion bloqueados)
- `sh` (dash) no soporta `-u`, pero `bash` si

## Flag

```
CTF{0_cl03x3c_1s_y0ur_fr13nd_f0r_fd_l34ks}
```

("O_CLOEXEC is your friend for FD leaks")
