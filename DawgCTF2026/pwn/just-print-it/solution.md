# Just Print It — DawgCTF 2026 (PWN)

## TL;DR
Format string vulnerability in `printf(buffer)` → overwrite `puts@GOT` with `win()` address.

## Analysis
- Binary compiled with: `-fno-stack-protector -no-pie -z execstack`
- Partial RELRO → GOT is writable
- No PIE → fixed addresses
- `main()` reads 128 bytes with `fgets`, then calls `printf(buffer)` directly (format string vuln)
- After `printf`, calls `puts("\nGoodbye!")` — perfect GOT overwrite target
- `win()` function reads and prints `flag.txt`

## Vulnerability
**CWE-134: Use of Externally-Controlled Format String**

`printf(buffer)` where `buffer` is user-controlled input. Allows arbitrary memory writes via `%n` format specifier.

## Exploit Strategy
1. Buffer starts at format string offset **6**
2. Use `fmtstr_payload(6, {puts_got: win})` to craft a `%n`-based write
3. Overwrite `puts@GOT` (`0x404000`) with `win()` (`0x401196`)
4. When `main` calls `puts("\nGoodbye!")`, execution redirects to `win()`
5. `win()` opens `flag.txt` and prints the flag

## Key Addresses
| Symbol | Address |
|--------|---------|
| `win()` | `0x401196` |
| `puts@GOT` | `0x404000` |

## Flag
```
DawgCTF{s3v3r_PWNed!}
```
