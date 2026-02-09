# 247CTF Challenges - Organización por Categoría

**Fecha de organización:** 2026-02-05
**Total de challenges:** 40

---

## Estructura

```
/root/ctf/
├── crypto/          (8 challenges)  - Criptografía
├── web/             (3 challenges)  - Web Exploitation
├── pwn/             (12 challenges) - Binary Exploitation
├── reversing/       (5 challenges)  - Reverse Engineering
├── network/         (6 challenges)  - Network & Protocols
└── misc/            (3 challenges)  - Miscellaneous
```

---

## Crypto (8 challenges)

**Ubicación:** `/root/ctf/crypto/`

| Challenge | Tipo |
|-----------|------|
| hmac_forge | HMAC Manipulation |
| exclusive_key | XOR Cipher |
| not_my_modulus | RSA Attack |
| suspicious_caesar_cipher | RSA with Caesar Twist |
| encrypted_usb | Encryption Analysis |
| nonexistent_functionality | Padding Oracle Attack |
| spn_challenge | Substitution-Permutation Network |
| predictable_iv | IV Prediction |

---

## Web (3 challenges)

**Ubicación:** `/root/ctf/web/`

| Challenge | Tipo |
|-----------|------|
| meme_upload | File Upload Exploit |
| wasm_secret | WebAssembly Reversing |
| mturk | Web Logic Flaw |

---

## Pwn (12 challenges)

**Ubicación:** `/root/ctf/pwn/`

| Challenge | Tipo |
|-----------|------|
| cookiemonster | Stack Canary Bypass (Buffer Overflow) |
| confused_env_read | Environment Variable Read |
| confused_environment_write | Environment Variable Write |
| empty_read | Buffer Mismanagement |
| executable_stack | Shellcode Injection |
| flag_store | Heap/Stack Exploit |
| heaped_notes | Heap Exploitation |
| hidden_flag_function | Hidden Function Call |
| hidden_flag_function_simple | ret2win |
| less_confused_environment_write | Environment Exploit |
| non_executable_stack | ROP Chain |
| stack_pivot | Stack Pivot Technique |

---

## Reversing (5 challenges)

**Ubicación:** `/root/ctf/reversing/`

| Challenge | Tipo |
|-----------|------|
| angry_revers | Binary Analysis |
| flag_api_key | API Key Extraction |
| flag_auth | Authentication Bypass |
| flag_bootloader | Bootloader Analysis |
| flag_keygen | Keygen Reversing |
| flag_errata | Windows Error Codes (Environment-dependent) |

---

## Network (5 challenges)

**Ubicación:** `/root/ctf/network/`

| Challenge | Tipo |
|-----------|------|
| commutative_payload | PCAP Analysis (SMB/XOR) |
| icmp_error | ICMP Protocol Analysis |
| multiplication_tables | Network Logic/Math |
| webshell | Shell Upload/Injection |
| follow_the_sequence | Algorithm Reversing |
| 00ps_my_wifi_disconnected | 00ps, my WiFi disconnected |

---

## Misc (3 challenges)

**Ubicación:** `/root/ctf/misc/`

| Challenge | Tipo |
|-----------|------|
| completely_turing | Brainfuck/Turing-complete Programming |
| flag_canary | flag_canary |
| leaky_libraries | Library Leak |
