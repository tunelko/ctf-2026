# Click Here For Free Bricks — UMassCTF 2026 (FORENSICS)

## TL;DR
Extract malware from PCAP, decrypt NaCl-encrypted launcher using key from `installer.py`, get SHA256, look up virus name on VirusTotal.

## Analysis
- PCAP contains HTTP downloads from `156.234.52.16`: `fungame.jpg`, `cooldog.jpeg`, `installer.py`, `literallyme.jpeg`, `launcher`
- `installer.py` decrypts `launcher` using NaCl SecretBox with key derived from `sha256("38093248092rsjrwedoaw3")`
- Decrypted launcher is a FreeBSD/i386 ELF binary (virus with "Erasmus" SCCS tag)

## Steps
1. Export HTTP objects from PCAP: `tshark -r thedamage.pcapng --export-objects http,./exported`
2. Decrypt launcher:
```python
import hashlib, nacl.secret
key = hashlib.sha256(b"38093248092rsjrwedoaw3").digest()
box = nacl.secret.SecretBox(key)
decrypted = box.decrypt(open("launcher","rb").read())
open("launcher_dec","wb").write(decrypted)
```
3. SHA256 of decrypted: `e7a09064fc40dd4e5dd2e14aa8dad89b328ef1b1fdb3288e4ef04b0bd497ccae`
4. Look up on VirusTotal Details tab → name is `TheZoo_<sha256>`

## Flag
```
UMASS{TheZoo_e7a09064fc40dd4e5dd2e14aa8dad89b328ef1b1fdb3288e4ef04b0bd497ccae}
```
