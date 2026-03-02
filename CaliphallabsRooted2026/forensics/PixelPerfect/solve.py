#!/usr/bin/env python3
"""
Challenge: PixelPerfect
Category:  forensics
Platform:  caliphallabsRooted2026
"""
from pwn import *

HOST, PORT = "challs.caliphallabs.com", 53109

def exploit():
    io = remote(HOST, PORT)

    # All 12 answers derived from forensic analysis of Windows disk image
    answers = {
        1:  "nofts",                                          # Windows username
        2:  "niftski",                                        # First internet search (Edge keyword_search_terms)
        3:  "Nestopia140bin.zip",                              # First downloaded file (Edge downloads table)
        4:  "2026-02-24 00:44:16 GMT",                        # First emulator run (ActivitiesCache.db)
        5:  "1.40",                                           # Emulator version (nestopia.xml)
        6:  "GAME OVER",                                      # Screenshot message (screenshots/Super Mario Bros. (World)_001.png)
        7:  "installer.exe",                                  # Malicious binary (Edge downloads - Google Drive)
        8:  "Discord",                                        # App downloaded after frustration (DiscordSetup.exe)
        9:  "noftski",                                        # Real intended username (Discord LevelDB MultiAccountStore)
        10: "2",                                              # Number of Discord servers (renderer_js.log routes)
        11: "599131748143464459,1475665918297374916",          # Guild IDs sorted (renderer_js.log /channels/ routes)
        12: "Super Mario Speedrunning (8-bit)",               # Server with many members (Discord API invite KjAV9Xa)
    }

    for i in range(1, 13):
        data = io.recvuntil(b"> ", timeout=10)
        print(data.decode(errors="replace"), end="")
        io.sendline(answers[i].encode())
        print(answers[i])
        result = io.recvline(timeout=5)
        print(result.decode(errors="replace"), end="")

    # Receive flag
    remaining = io.recvall(timeout=10)
    print(remaining.decode(errors="replace"))
    io.close()

if __name__ == "__main__":
    exploit()
