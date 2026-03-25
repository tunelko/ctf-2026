# Meow - BSidesSF 2026 CTF

## Challenge Info
- **Category**: Terminal
- **Author**: Daniel Pendolinio
- **Flag**: `CTF{SAY_AHHH_AND_GIVE_ME_THE_FLAG}`

## TL;DR
Connect to the terminal, `cat /home/ctf/flag.txt`. Done.

## Description
> Terminal Challenges Welcome
> Flag Path: /home/ctf/flag.txt
> Author: Daniel Pendolinio
> Web Terminal: https://meow-2ab5908d.term.challenges.bsidessf.net
> (or socat STDIO,raw,echo=0,escape=0x03 TCP:meow-2ab5908d.challenges.bsidessf.net:4445)

## Solution

### Step 1: Connect
```bash
nc meow-2ab5908d.challenges.bsidessf.net 4445
```

Banner:
```
Welcome to BSidesSF 2026 CtF - Terminal Challenges!

Time to go rooting for a discovery, the flag is around here somewhere.

The current working directory is: /home/ctf
You are logged in as: ctf
ctf@meow:~$
```

### Step 2: Read the flag
```bash
cat /home/ctf/flag.txt
```

Output:
```
              ##############
           ###      ##      ###
         ##       ######       ##
       ##    ###############    ##
      ##   ###################   ##
     ##   ####  Feed Me!  ####   ##
     ##   ###################   ##
      ##   ###################   ##
       ##    ###############    ##
         ##       ######       ##
           ###      ##      ###
              ##############
                    ||
              ____  ||  ____
             /    \ || /    \
            |      |||      |
             \____/ || \____/
                    ||
              ______|______
[x3]              |             |
             |_____________|

CTF{SAY_AHHH_AND_GIVE_ME_THE_FLAG}
```

## Flag
```
CTF{SAY_AHHH_AND_GIVE_ME_THE_FLAG}
```

## Key Lessons
- Always try the simplest approach first
- The flag was literally at the path specified in the challenge description
- No exploitation needed — just read the file
