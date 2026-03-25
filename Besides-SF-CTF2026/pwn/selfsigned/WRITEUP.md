# SELFsigned

| Campo | Valor |
|-------|-------|
| **CTF** | BSidesSF CTF 2026 |
| **Categoria** | Web Pwn |
| **Puntos** | 925 |
| **Flag** | `CTF{sections_and_segments_r_same_right?}` |

---

## TL;DR

The ELF signing spec hashes section headers/contents (ALLOC only) and the ELF file header, but **NOT the program headers**. Inject shellcode into a non-ALLOC section, convert `PT_GNU_STACK` to `PT_LOAD` mapping it over the entry point. Signature remains valid.

---

## Vulnerabilidad

The SELF-Signed spec computes the file hash from:
1. ELF File Header
2. Section headers (ALLOC sections only)
3. Section contents hashes (ALLOC, non-NOBITS sections only)

**Program headers (segments) are NOT included in the hash.** This is the critical gap between ELF sections and segments - the spec signs sections but the OS loads segments.

## Explotacion

```python
# 1. Put shellcode (open+read+write /home/ctf/flag.txt) into 
#    non-ALLOC section data (appended to file, page-aligned)
# 2. Convert PT_GNU_STACK → PT_LOAD pointing to shellcode at entry point vaddr
# 3. Signature still valid because program headers aren't hashed!
```

The modified binary:
- Passes signature verification (sections unchanged)
- Executes our shellcode (segments redirect entry point to our code)

## Flag

```
CTF{sections_and_segments_r_same_right?}
```

("Sections and segments are the same, right?" - they're NOT, and that's the vulnerability)
