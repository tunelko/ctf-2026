# Data Needs Splitting — DawgCTF 2026 (REV)

## TL;DR
JAR file hidden in DNS TXT records. Decompile → XOR cipher with known target. Reverse to get flag.

## Step 1: Find the binary
- Domain `data-needs-splitting.umbccd.net` has 17 TXT records (prefixed 00-16)
- Concatenate, base64 decode → JAR file (3176 bytes)

## Step 2: Reverse the validator
- `Loader.class` loads `assets/file.dat` as a class at runtime
- `file.dat` is `Validator.class` — reads flag, XORs each char with two 64-bit key streams, concatenates decimal results
- Target string: `14551193924999719514544194455046717514553194254998722814540194365001720314545193465020724414565193465012716
9`

## XOR Keys (per position mod 4)
```
Key1 = 2194307438957234483, Key2 = 148527584754938272
Combined: [14483, 19361, 5104, 7292]
```

## Step 3: Reverse
Known prefix "DawgCTF{" confirms key. Recursive backtracking on decimal string splitting (1-5 digit numbers) with printable ASCII constraint.

## Flag
```
DawgCTF{J@v@_My_B3l0v3d}
```
