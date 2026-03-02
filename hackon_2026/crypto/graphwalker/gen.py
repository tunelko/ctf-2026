import os
import random
import sys
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

try:
    from common import Matrix2x2, stateful_matrix_gen
except ImportError:
    sys.path.append('.')
    from common import Matrix2x2, stateful_matrix_gen

FLAG = "HackOn{F4k3_Fl4g_F0R_t3st1ng}"
P = 100003

def generate_challenge():
    state_a = os.urandom(16)
    state_b = os.urandom(16)
    
    seed_a = state_a
    seed_b = state_b
    
    path_bits = [random.randint(0, 1) for _ in range(48)]
    
    current_pos = Matrix2x2(1, 0, 0, 1, P)
    
    for bit in path_bits:
        state_a, mat_a = stateful_matrix_gen(state_a, P)
        state_b, mat_b = stateful_matrix_gen(state_b, P)
        
        if bit == 0:
            current_pos = current_pos * mat_a
        else:
            current_pos = current_pos * mat_b

    path_str = "".join(str(b) for b in path_bits)
    key = sha256(path_str.encode()).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted_flag = cipher.encrypt(pad(FLAG.encode(), 16))
    
    return {
        "P": P,
        "SeedA_hex": seed_a.hex(),
        "SeedB_hex": seed_b.hex(),
        "Target": current_pos,
        "EncFlag": encrypted_flag.hex()
    }

if __name__ == "__main__":
    chall_data = generate_challenge()
    
    with open("output.txt", "w") as f:
        f.write("=== Graph Walker ===\n")
        f.write(f"Prime: {chall_data['P']}\n")
        f.write(f"Seed A: {chall_data['SeedA_hex']}\n")
        f.write(f"Seed B: {chall_data['SeedB_hex']}\n")
        f.write(f"Target: {chall_data['Target']}\n")
        f.write(f"EncFlag: {chall_data['EncFlag']}\n")
        f.write("\nPath len: 48\n")
