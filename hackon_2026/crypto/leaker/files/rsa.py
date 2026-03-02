from Crypto.Util.number import getPrime, inverse
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from secret import p, q, e

with open("flag.txt", "rb") as f:
    data = f.read()

n = p * q
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

key = RSA.construct((n, e, d, p, q))
public_key = key.public_key()

cipher_rsa = PKCS1_OAEP.new(public_key)
ciphertext = cipher_rsa.encrypt(data)

print(f"n = {n}")
print(f"e = {e}")
print(f"ct = {ciphertext.hex()}")
