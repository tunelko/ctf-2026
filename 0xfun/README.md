# 0xFun CTF 2026 — Writeups

**Team:** 0xfun
**Challenges solved:** 33
**Categories:** Crypto, Forensics, Hardhack, Misc, PWN, Reversing, Web

---

## Flags

| # | Category | Challenge | Pts | Difficulty | Flag |
|---|----------|-----------|-----|------------|------|
| 1 | Crypto | BitStorm | 50 | Beginner | `0xfun{L1n34r_4lg3br4_W1th_Z3_1s_Aw3s0m3}` |
| 2 | Crypto | Delicious | 50 | Beginner | `0xfun{pls_d0nt_hur7_my_b4by(DLP)_AI_kun!:3}` |
| 3 | Crypto | Fortune Teller | 250 | Medium | `0xfun{trunc4t3d_lcg_f4lls_t0_lll}` |
| 4 | Crypto | Fortune Teller Revenge | 250 | Medium | `0xfun{r3v3ng3_0f_th3_f0rtun3_t3ll3r}` |
| 5 | Crypto | Hawk II | 100 | Easy | `0xfun{tOO_LLL_256_B_kkkkKZ_t4e_f14g_F14g}` |
| 6 | Crypto | Leonine Misbegotten | 50 | Beginner | `0xfun{p33l1ng_l4y3rs_l1k3_an_0n10n}` |
| 7 | Crypto | MeOwl ECC | 50 | Beginner | `0xfun{n0n_c4n0n1c4l_l1f7s_r_c00l}` |
| 8 | Crypto | Mersenne Roulette | 100 | Easy | `0xfun{m3rs3nn3_tw1st3r_unr4v3l3d}` |
| 9 | Crypto | Slot Whisperer | 250 | Medium | `0xfun{sl0t_wh1sp3r3r_lcg_cr4ck3d}` |
| 10 | Forensics | Bart64 | 50 | Beginner | `0xfun{secret_image_found!}` |
| 11 | Forensics | GCode | 100 | Easy | `0xfun{this_monkey_has_a_flag}` |
| 12 | Forensics | kd> | 100 | Easy | `0xfun{wh0_n33ds_sl33p_wh3n_y0u_h4v3_cr4sh_dumps}` |
| 13 | Forensics | Lines of Contact | 250 | Medium | `0xfun{g0ld3n_r3c0rd_1s_n0t_r4nd0m}` |
| 14 | Forensics | Nothing Expected | 50 | Beginner | `0xfun{th3_sw0rd_0f_k1ng_4rthur}` |
| 15 | Forensics | Pixel Rehab | 500 | Hard | `0xfun{FuN_PN9_f1Le_7z}` |
| 16 | Hardhack | Analog Nostalgia | 50 | Beginner | `0xfun{AN4L0G_IS_N0T_D3AD_JUST_BL4NKING}` |
| 17 | Hardhack | Digital Transition | 50 | Beginner | `0xfun{TMDS_D3CODED_LIKE_A_PRO}` |
| 18 | Misc | Deep Fried Data | 250 | Medium | `0xfun{d33p_fr13d_3nc0d1ng_0n10n}` |
| 19 | Misc | Spectrum | 50 | Beginner | `0xfun{50_345y_1_b3113v3}` |
| 20 | Misc | UART | 50 | Beginner | `0xfun{UART_82_M2_B392n9dn2}` |
| 21 | PWN | bit_flips | 250 | Medium | `0xfun{3_b1t5_15_4ll_17_74k35_70_g37_RC3_safhu8}` |
| 22 | PWN | FridgeNet | 100 | Easy | `0xfun{4_ch1ll1ng_d1sc0v3ry!p1x3l_b3at_r3v3l4ons_c0d3x_b1n4ry_s0rcery_unl3@sh3d!}` |
| 23 | PWN | Show me what you GOT! | 100 | Easy | `0xfun{g3tt1ng_schw1fty_w1th_g0t_0v3rwr1t3s_1384311_m4x1m4l}` |
| 24 | Reversing | Chip8 Emulator | 50 | Beginner | `0xfunCTF2025{N0w_y0u_h4v3_clear_1dea_H0w_3mulators_WoRK}` |
| 25 | Reversing | Guess the Seed | 50 | Beginner | `0xfun{W3l1_7h4t_w4S_Fun_4235328752619125}` |
| 26 | Reversing | Liminal | 500 | Hard | `0xfun{0x4c8e40be1e97f544}` |
| 27 | Reversing | Nanom Dynamite | 50 | Beginner | `0xfun{unr3adabl3_c0d3_is_s3cur3_c0d3_XD}` |
| 28 | Reversing | Pharaoh's Curse | 100 | Easy | `0xfun{ph4r40h_vm_1nc3pt10n}` |
| 29 | Reversing | PingPong | 50 | Beginner | `0xfun{h0mem4d3_f1rewall_305x908fsdJJ}` |
| 30 | Web | Jinja | 100 | Easy | `0xfun{Z3r0_7ru57_R3nd3r}` |
| 31 | Web | Perceptions | 50 | Beginner | `0xfun{p3rsp3c71v3.15.k3y}` |
| 32 | Web | Quantum (Schrodinger's Sandbox) | 250 | Medium | `0xfun{schr0d1ng3r_c4t_l34ks_thr0ugh_t1m3}` |
| 33 | Web | Shell | 50 | Beginner | `0xfun{h1dd3n_p4yl04d_1n_pl41n_51gh7}` |

---

## Structure

Each challenge folder contains:

- `WRITEUP.md` — Full analysis: description, reconnaissance, exploitation, and flag
- `solve.py` / `exploit.py` — Reproducible solution script (when applicable)
- Original challenge files (binaries, data, captures)

```
challenges/
├── crypto/
│   ├── bitstorm/           # Z3 SAT solver over GF(2)
│   ├── delicious/          # Discrete Log Problem (Pohlig-Hellman)
│   ├── fortune_revenge/    # Truncated LCG + LLL (revenge)
│   ├── fortune_teller/     # Truncated LCG + LLL
│   ├── hawk/               # Lattice-based crypto (LLL)
│   ├── leonine/            # Layered encoding (onion)
│   ├── meowl_ecc/          # ECC anomalous curve + non-canonical lifts
│   ├── roulette/           # Mersenne Twister state recovery
│   └── slot-whisperer/     # LCG cracking
├── forensics/
│   ├── bart64/             # Base64 + hidden image
│   ├── gcode_challenge/    # GCode 3D -> front projection X-Z
│   ├── kd/                 # Windows crash dump analysis
│   ├── lines_of_contact/   # Golden Record (Voyager) audio -> image
│   ├── nothing_expected/   # Steganography
│   └── pixel_rehab/        # Corrupt PNG repair
├── hardhack/
│   ├── Digital_Transition/ # TMDS (DVI/HDMI) signal decoding
│   └── analog_nostalgia/   # VGA raw signal -> frame rendering
├── misc/
│   ├── deep_fried_data/    # 100+ nested encoding/compression layers
│   ├── spectrum/           # Audio spectrogram -> visual flag
│   └── uart_extract/       # UART signal decoding (logic analyzer)
├── pwn/
│   ├── bit_flips/          # RC4 bit-flip attack
│   ├── fridgenet/          # Format string + buffer overflow
│   └── what-you-have/      # GOT overwrite
├── reversing/
│   ├── chip8_emulator/     # Hidden opcode FxFF -> AES decryption
│   ├── guess_the_seed_challenge/  # PRNG seed bruteforce
│   ├── liminal_challenge/  # SPN cipher + speculative execution side-channel
│   ├── nanom_dynamite/     # Obfuscated binary
│   ├── pharaohs_curse/     # Custom VM (hieroglyphic ISA)
│   └── pingpong_challenge/ # Custom firewall bypass
└── web/
    ├── jinja/              # SSTI via Pydantic EmailStr bypass
    ├── perceptions/        # SSH multiplexing + hidden credentials
    ├── quantum/            # Race condition (Schrodinger's sandbox)
    └── shell/              # CVE-2021-22204 ExifTool RCE
```

---

## By Category

### Crypto (9 challenges — 900 pts)
Main theme: PRNG attacks (Mersenne Twister, LCG), lattice reduction (LLL), ECC anomalous curves, DLP.

### Forensics (6 challenges — 1050 pts)
Main theme: format analysis (GCode, crash dumps, PNG), steganography, analog signals (Voyager Golden Record).

### Hardhack (2 challenges — 100 pts)
Main theme: video signal decoding (analog VGA, digital TMDS).

### Misc (3 challenges — 350 pts)
Main theme: signals (UART, spectrogram), encoding chains.

### PWN (3 challenges — 450 pts)
Main theme: buffer overflow, GOT overwrite, bit-flip attacks.

### Reversing (6 challenges — 800 pts)
Main theme: custom VMs, SPN cipher, side-channels, obfuscation, emulators.

### Web (4 challenges — 450 pts)
Main theme: SSTI, RCE (ExifTool), race conditions, SSH multiplexing.

---

## Tools Used

- **Reversing:** radare2, GDB+GEF, Python (struct, ctypes)
- **Crypto:** Python (pycryptodome, gmpy2, z3-solver), SageMath, RsaCtfTool
- **PWN:** pwntools, checksec, ROPgadget
- **Forensics:** binwalk, exiftool, zsteg, PIL/Pillow, volatility3
- **Web:** curl, requests, Burp Suite
- **Hardhack:** Python (numpy, PIL), signal analysis
- **Misc:** scipy (spectrogram), Python (gzip, bz2, lzma, base64)
