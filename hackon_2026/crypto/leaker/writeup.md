# Leaker

**Category:** CRYPTO
**Difficulty:** Easy
**Points:** 100
**Flag:** `HackOn{Ar3_y0u_4_L3aKer?}`

## Description

> Siempre hemos confiado ciegamente en la robustez de nuestro sistema de RSA-2048 para proteger nuestros secretos. Es imposible factorizar una n tan grande. Aunque con la filtración masiva de datos de Hacienda y ComponentesPC espero que no estén nuestros datos por ahi perdidos...

## TL;DR

The RSA-2048 modulus `n` was composed of primes that had been previously leaked/submitted to FactorDB, making factorization trivial despite the large key size.

## Analysis

We are given:
- `rsa.py`: the encryption script using RSA with PKCS1_OAEP padding
- `output.txt`: containing `n`, `e=65537`, and the ciphertext in hex

The challenge description hints that the prime factors of `n` were leaked in some data breach. The challenge name "Leaker" reinforces this. The key insight is that even though RSA-2048 is normally secure, if the primes `p` and `q` are known (leaked), the encryption is trivially broken.

Checking FactorDB reveals that `n` is fully factored:
- `p = 9473814101884815134307381475115558806662649224148596904181805583446105537764268766905060215763993310334114926880878203044455646517298632532024114629108984814204970866184521898276216534916282018317922790829676171624550379724630682346429512380845326493654531107133000141582806299532269349795572651409350810534`
- `q = 14773306680214221022798816507116600541923933570825757597232824635980239204767121118440161440649821457722729369289469388044044353433857845871975021631869700478863955124529374976587942370531631522737486713809055341705848507337607057597044424049907476675198244232723771901119554778344822243004317592995200850229`

## Solution

### Prerequisites

- Python 3 with `pycryptodome` and `factordb-python`
```bash
pip install pycryptodome factordb-python --break-system-packages
```

### Steps

1. Parse `n`, `e`, and ciphertext from output.txt
2. Query FactorDB for the factorization of `n`. It returns `p` and `q` immediately
3. Compute `phi(n) = (p-1)(q-1)` and private exponent `d = e^(-1) mod phi(n)`
4. Construct the RSA private key and decrypt the OAEP-padded ciphertext

### Solve Script

```python
#!/usr/bin/env python3
# solve.py — Leaker solver
from Crypto.Util.number import inverse
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from factordb.factordb import FactorDB

n = 13995956115848263016093995223392495521243979865638305847601770972340640125297667678944314439171417639231782675463971847717627574848505124209559607972261237926528300604391494532968883603778640097073818900716974733608411380808201234907216954732943248515866679332757937854142500896757118378645377699623623380558410565392545307338283447480897500153488025166968685475289186601821552365746059488451320955829358367697180065644022847845732351374069943618582175542319624338785025687297561229557210615574597443819217707744954666671816281273581746054365416031968971880792191097581869485525299421842425875982831447806956965305089
e = 65537
ct_hex = "4a2671eadf5cf7920b6829b04b9758ac82989d009dc5a43de8fa77d060875b019e60b6b61f6241853fe25d08466cc270d651cd98a874d337ab17cee41e51ebb4e42113e4d60eb68eb1fcd7846608f7bc218cf641eddb4bf680d93c6c106f4c73503839b3d638c56d8d6edfcd48a3acd60875255a05e59b1e1bc435f39d4a7bfa82bcb4f7ff6b6d69aa551d08bee580455dc194b228d4fdb20f86fd98bddd6731abb11bbd599492cf30b1dcc44b1ceeb126db947e3d379cac58b5285d94c2f288a4c7e4dc9d0c943f7fe62a24f44705dcfb1d55a34fee25fdb0003481816d07ca5710c33a5d02ccc28191d2a31c5f64a6060c51841a39cc191986097dd12aac50"

f = FactorDB(n)
f.connect()
p, q = f.get_factor_list()

phi = (p - 1) * (q - 1)
d = inverse(e, phi)

key = RSA.construct((n, e, d, p, q))
cipher = PKCS1_OAEP.new(key)
plaintext = cipher.decrypt(bytes.fromhex(ct_hex))
print(plaintext.decode())
```

## Flag

```
HackOn{Ar3_y0u_4_L3aKer?}
```
