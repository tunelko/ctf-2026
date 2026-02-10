# 247CTF Challenges - Organized by Category

Platform: https://247ctf.com/dashboard

![247CTF](247.png)

<pre>
247CTF/
│
├── pwn/
│   ├── <a href="pwn/cookiemonster/cookiemonster_writeup.md">cookiemonster/</a>
│   │   ├── Overflow stack canary on 32-bit binary to call hidden flag function
│   │   └── Learn: Stack overflow, canary exploitation, 32-bit binary exploitation
│   │
│   ├── <a href="pwn/confused_env_read/confused_env_read_writeup.md">confused_env_read/</a>
│   │   ├── Exploit format string to read arbitrary stack memory and leak addresses
│   │   ├── Learn: Format string vulnerability, memory leakage, stack pivoting
│   │   └── <a href="pwn/confused_env_read/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="pwn/confused_environment_write/confused_environment_write_writeup.md">confused_environment_write/</a>
│   │   ├── Exploit format string for arbitrary write primitive with 63-byte limit
│   │   ├── Learn: Format string vulnerability, GOT overwrites, write primitives
│   │   └── <a href="pwn/confused_environment_write/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="pwn/empty_read/empty_read_writeup.md">empty_read/</a>
│   │   ├── Exploit out-of-bounds read in email service to leak heap addresses
│   │   └── Learn: Heap exploitation, OOB read, use-after-free
│   │
│   ├── <a href="pwn/executable_stack/executable_stack_writeup.md">executable_stack/</a>
│   │   ├── Custom shellcode on executable stack for code execution on 32-bit binary
│   │   ├── Learn: Shellcode crafting, executable stack exploitation, ROP gadgets
│   │   └── <a href="pwn/executable_stack/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="pwn/flag_store/flag_store_writeup.md">flag_store/</a>
│   │   ├── Exploit use-after-free in custom flag storage application
│   │   └── Learn: UAF exploitation, heap spraying, free() abuse
│   │
│   ├── <a href="pwn/heaped_notes/heaped_notes_writeup.md">heaped_notes/</a>
│   │   ├── Trigger flag function using heap feng-shui with 3 identical chunks
│   │   ├── Learn: Heap spraying, heap fragmentation, size class manipulation
│   │   └── <a href="pwn/heaped_notes/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="pwn/hidden_flag_function/hidden_flag_function_writeup.md">hidden_flag_function/</a>
│   │   ├── Stack overflow to redirect flow to hidden flag() function
│   │   └── Learn: Stack overflow, function redirection, 32-bit exploitation
│   │
│   ├── <a href="pwn/hidden_flag_function_simple/hidden_flag_function_simple_writeup.md">hidden_flag_function_simple/</a>
│   │   ├── Stack overflow to call hidden flag() with correct parameters
│   │   ├── Learn: Stack overflow with parameter control, ROP chains, 32-bit ABI
│   │   └── <a href="pwn/hidden_flag_function_simple/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="pwn/less_confused_environment_write/less_confused_environment_write_writeup.md">less_confused_environment_write/</a>
│   │   ├── Single-shot format string write with GOT overwrite under strict constraints
│   │   ├── Learn: Format string (limited attempts), 32-bit exploitation, GOT redirection
│   │   └── <a href="pwn/less_confused_environment_write/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="pwn/non_executable_stack/non_executable_stack_writeup.md">non_executable_stack/</a>
│   │   ├── Stack overflow with NX enabled using ROP chain to system shell
│   │   ├── Learn: ROP gadget chaining, NX bypass, address-space layout evasion
│   │   └── <a href="pwn/non_executable_stack/solve.py">💻 Exploit</a>
│   │
│   └── <a href="pwn/stack_pivot/stack_pivot_writeup.md">stack_pivot/</a>
│       ├── Pivot stack pointer to attacker-controlled memory for ROP on 64-bit
│       ├── Learn: Stack pivot gadgets, 64-bit ROP, memory layout manipulation
│       └── <a href="pwn/stack_pivot/solve.py">💻 Exploit</a>
│
├── web/
│   ├── <a href="web/flag_auth/flag_auth_writeup.md">flag_auth/</a>
│   │   ├── Forge JWT token with admin identity to bypass authentication
│   │   ├── Learn: JWT vulnerabilities, token forgery, algorithm confusion
│   │   └── <a href="web/flag_auth/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="web/meme_upload/meme_upload_writeup.md">meme_upload/</a>
│   │   ├── Combine XXE and PHAR deserialization with polyglot files for RCE
│   │   └── Learn: XXE injection, PHAR deserialization, polyglot files, PHP object injection
│   │
│   ├── <a href="web/mturk/mturk_writeup.md">mturk/</a>
│   │   ├── Solve 100 CAPTCHAs in 30 seconds using OCR and image preprocessing
│   │   └── Learn: Image processing, OCR (Tesseract), automated CAPTCHA solving
│   │
│   └── <a href="web/wasm_secret/wasm_secret_writeup.md">wasm_secret/</a>
│       ├── Extract secret from WebAssembly module by analyzing WASM bytecode
│       ├── Learn: WebAssembly analysis, WASM decompilation, Emscripten reversing
│       └── <a href="web/wasm_secret/solve.py">💻 Exploit</a>
│
├── crypto/
│   ├── <a href="crypto/exclusive_key/exclusive_key_writeup.md">exclusive_key/</a>
│   │   ├── Recover XOR password using known plaintext attack with flag format
│   │   ├── Learn: Known plaintext attack, XOR encryption, cyclic key recovery
│   │   └── <a href="crypto/exclusive_key/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="crypto/hmac_forge/hmac_forge_writeup.md">hmac_forge/</a>
│   │   ├── Forge HMAC request abusing non-standard implementation via length extension
│   │   ├── Learn: Hash length extension attack, HMAC vulnerabilities, SHA-256
│   │   └── <a href="crypto/hmac_forge/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="crypto/nonexistent_functionality/nonexistent_functionality_writeup.md">nonexistent_functionality/</a>
│   │   ├── Decrypt flag via padding oracle attack against AES-CBC
│   │   ├── Learn: Padding oracle attack, AES-CBC vulnerabilities, oracle-based decryption
│   │   └── <a href="crypto/nonexistent_functionality/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="crypto/not_my_modulus/not_my_modulus_writeup.md">not_my_modulus/</a>
│   │   ├── Identify correct RSA private key from 1000 candidates via TLS pcap modulus
│   │   └── Learn: RSA modulus matching, TLS certificate extraction, pcap analysis
│   │
│   ├── <a href="crypto/predictable_iv/predictable_iv_writeup.md">predictable_iv/</a>
│   │   ├── Exploit predictable IV in AES-CBC reusing last ciphertext bytes
│   │   ├── Learn: BEAST attack, AES-CBC IV predictability, chosen plaintext
│   │   └── <a href="crypto/predictable_iv/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="crypto/spn_challenge/spn_challenge_writeup.md">spn_challenge/</a>
│   │   ├── Reverse SPN encryption exploiting weak random key generation
│   │   ├── Learn: SPN cryptanalysis, S-box analysis, weak key generation
│   │   └── <a href="crypto/spn_challenge/solve.py">💻 Exploit</a>
│   │
│   └── <a href="crypto/suspicious_caesar_cipher/suspicious_caesar_cipher_writeup.md">suspicious_caesar_cipher/</a>
│       ├── Recover RSA encrypted flag exploiting small message space
│       ├── Learn: RSA vulnerability analysis, cubic root decryption, weak exponent
│       └── <a href="crypto/suspicious_caesar_cipher/solve.py">💻 Exploit</a>
│
├── reversing/
│   ├── <a href="reversing/angry_revers/angry_revers_writeup.md">angry_revers/</a>
│   │   ├── Use angr symbolic execution to find valid path through validation
│   │   ├── Learn: Symbolic execution with angr, binary analysis, path finding
│   │   └── <a href="reversing/angry_revers/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="reversing/encrypted_usb/encrypted_usb_writeup.md">encrypted_usb/</a>
│   │   ├── Decrypt BitLocker USB drive and reverse ransomware encryption
│   │   └── Learn: BitLocker decryption, ransomware analysis, encryption reversal
│   │
│   ├── <a href="reversing/flag_api_key/flag_api_key_writeup.md">flag_api_key/</a>
│   │   ├── Exploit API endpoint flaws to brute-force admin password
│   │   ├── Learn: API security, brute-force attacks, endpoint logic bypass
│   │   └── <a href="reversing/flag_api_key/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="reversing/flag_bootloader/flag_bootloader_writeup.md">flag_bootloader/</a>
│   │   ├── Reverse DOS/MBR bootloader (512 bytes) to find hidden boot sequence
│   │   ├── Learn: x86 assembly, bootloader analysis, MBR reverse engineering
│   │   └── <a href="reversing/flag_bootloader/solve.py">💻 Exploit</a>
│   │
│   └── <a href="reversing/flag_keygen/flag_keygen_writeup.md">flag_keygen/</a>
│       ├── Reverse 64-bit binary to understand key validation and generate valid keys
│       ├── Learn: 64-bit binary reversing, algorithm reconstruction, keygen development
│       └── <a href="reversing/flag_keygen/solve.py">💻 Exploit</a>
│
├── network/
│   ├── <a href="network/00ps_my_wifi_disconnected/00ps_my_wifi_disconnected_writeup.md">00ps_my_wifi_disconnected/</a>
│   │   ├── Decrypt WiFi traffic using Kr00k (CVE-2019-15126) with zeroed temporal key
│   │   └── Learn: Kr00k WiFi vulnerability, AES-CCM decryption, WiFi security
│   │
│   ├── <a href="network/commutative_payload/commutative_payload_writeup.md">commutative_payload/</a>
│   │   ├── Extract XOR-encoded payload from SMB traffic honeypot pcap
│   │   └── Learn: XOR cryptanalysis, pcap parsing, SMB protocol analysis
│   │
│   ├── <a href="network/follow_the_sequence/follow_the_sequence_writeup.md">follow_the_sequence/</a>
│   │   ├── Recover flag from MPTCP data across multiple subflows using DSN reordering
│   │   ├── Learn: MPTCP protocol analysis, sequence reordering, subflow reconstruction
│   │   └── <a href="network/follow_the_sequence/solve.py">💻 Exploit</a>
│   │
│   ├── <a href="network/icmp_error/icmp_error_writeup.md">icmp_error/</a>
│   │   ├── Extract JPEG image from ICMP echo reply payloads containing flag
│   │   └── Learn: ICMP payload analysis, JPEG recovery, packet dissection
│   │
│   ├── <a href="network/multiplication_tables/multiplication_tables_writeup.md">multiplication_tables/</a>
│   │   ├── Recover TLS private key from pcap analyzing client key exchange messages
│   │   ├── Learn: TLS decryption, key recovery, pcap analysis
│   │   └── <a href="network/multiplication_tables/solve.py">💻 Exploit</a>
│   │
│   └── <a href="network/webshell/webshell_writeup.md">webshell/</a>
│       ├── Analyze HTTP pcap of web server compromise to identify webshell commands
│       ├── Learn: HTTP traffic analysis, webshell detection, forensic analysis
│       └── <a href="network/webshell/solve.py">💻 Exploit</a>
│
└── misc/
    ├── <a href="misc/completely_turing/completely_turing_writeup.md">completely_turing/</a>
    │   ├── Extract encrypted flag from Brainfuck program via multiplication patterns
    │   └── Learn: Brainfuck programming, regex pattern analysis, encryption recognition
    │
    ├── <a href="misc/flag_canary/flag_canary_writeup.md">flag_canary/</a>
    │   ├── Bypass custom RC4-based canary protection with fixed buffer and secret check
    │   ├── Learn: RC4 cryptanalysis, canary bypass, buffer overflow techniques
    │   └── <a href="misc/flag_canary/solve.py">💻 Exploit</a>
    │
    └── <a href="misc/leaky_libraries/leaky_libraries_writeup.md">leaky_libraries/</a>
        ├── Exploit 1-byte memory leak to chain address leaks and write ROP chains
        ├── Learn: Memory leak exploitation, binary leak chaining, code execution
        └── <a href="misc/leaky_libraries/solve.py">💻 Exploit</a>
</pre>
