# Roar - BSidesSF 2026 CTF

## Challenge Info
- **Category**: Terminal
- **Author**: symmetric
- **Flag**: `CTF{cat_dot_tty}`

## TL;DR
`cat /home/ctf/flag.txt` outputs massive ANSI-colored braille art of a lion. The flag `CTF{cat_dot_tty}` is embedded within the art output, hidden among hundreds of colored braille characters.

## Description
> This kitty is a bit verbose
> Flag Path: /home/ctf/flag.txt

## Solution

### Step 1: Connect and read
```bash
nc roar-3e3282d2.challenges.bsidessf.net 1994
cat /home/ctf/flag.txt
```

The output is ~47KB of ANSI escape codes rendering a colored braille-art lion. The flag is buried in the middle of the art.

### Step 2: Extract flag
Strip ANSI escape codes and grep:
```bash
cat /home/ctf/flag.txt | sed 's/\x1b\[[0-9;]*m//g' | grep -i "CTF{"
```

Output:
```
CTF{cat_dot_tty}
```

## Flag
```
CTF{cat_dot_tty}
```

## Key Lessons
- "Verbose" was the hint — the flag is hidden in massive terminal art output
- Strip ANSI escape codes (`\x1b[...m`) to find text hidden in colored output
- `grep` through noisy output instead of trying to read it visually
- Flag name is a pun: `cat` (the command) + `.tty` (terminal device) = cat on a tty
