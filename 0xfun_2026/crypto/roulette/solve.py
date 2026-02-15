#!/usr/bin/env python3
"""Mersenne Twister Roulette - final exploit"""
from pwn import *
from randcrack import RandCrack

context.log_level = 'info'

XOR_KEY = 0xCAFEBABE

def main():
    io = remote('chall.0xfun.org', 57779)

    # Create RandCrack
    rc = RandCrack()

    log.info("Collecting 624 outputs...")

    # Collect 624 outputs
    for i in range(624):
        io.recvuntil(b'> ')
        io.sendline(b'spin')

        output_line = io.recvline().decode().strip()
        obfuscated = int(output_line)

        # Deobfuscate
        raw = obfuscated ^ XOR_KEY
        rc.submit(raw)

        if (i + 1) % 100 == 0:
            log.info(f"Progress: {i+1}/624")

    log.success("RNG state cloned!")

    # Now we can predict
    log.info("Testing predictions...")

    # Verify with a few more spins
    for i in range(5):
        # Predict
        pred_raw = rc.predict_getrandbits(32)
        pred_obf = pred_raw ^ XOR_KEY

        # Get actual value
        io.recvuntil(b'> ')
        io.sendline(b'spin')
        real_obf = int(io.recvline().decode().strip())

        match = "OK" if pred_obf == real_obf else "FAIL"
        log.info(f"Prediction {i+1}: {pred_obf} vs {real_obf} {match}")

    # Now use "predict" to win
    log.info("Using predict command to win...")

    io.recvuntil(b'> ')
    io.sendline(b'predict')

    # Server asks "Predict next 10 raw values (space-separated)"
    response = io.recvrepeat(timeout=2).decode()
    log.info(f"Server response: {response}")

    # Generate 10 RAW predictions (without XOR)
    predictions = []
    for _ in range(10):
        pred_raw = rc.predict_getrandbits(32)
        # Server asks for "raw values" - probably without XOR
        predictions.append(str(pred_raw))

    # Send space-separated
    pred_line = ' '.join(predictions)
    log.info(f"Sending predictions: {pred_line}")
    io.sendline(pred_line.encode())

    # Get final response
    final = io.recvrepeat(timeout=2).decode()
    log.success(f"Final response:\n{final}")

    io.interactive()

if __name__ == '__main__':
    main()
