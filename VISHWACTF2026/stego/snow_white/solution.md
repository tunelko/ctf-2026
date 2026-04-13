# Snow White — VishwaCTF 2026 (Stego)

## TL;DR
SNOW steganography - whitespace encoding (tabs/spaces) in trailing whitespace of output.txt. Password: `chance` (cracked from rockyou).

## Flag
`VishwaCTF{y0u_g07_ch4nc3😉}`

## Steps
1. `output.txt` has suspicious trailing whitespace (tabs and spaces)
2. Identified as SNOW steganography (tabs=1, spaces=0)
3. Password required → cracked with rockyou: `chance`
4. `stegsnow -C -p "chance" output.txt` → flag
