#!/usr/bin/env python3
from pwn import *
import randcrack, threading

LOCAL = False
HOST = "34.126.223.46"
PORT = 17034

def main():
    if LOCAL:
        p = process("./checker")
    else:
        p = remote(HOST, PORT)

    t_line = p.recvline().strip()
    log.info(f"First line: {t_line}")
    t = int(t_line)
    log.info(f"Test cases: {t}")

    rc = randcrack.RandCrack()
    state_recovered = False

    for tc in range(t):
        n_line = p.recvline().strip()
        log.info(f"TC {tc+1}/{t}: raw line = {n_line}")
        n = int(n_line)

        if not state_recovered:
            num = 624
            queries = []
            for i in range(1, num + 1):
                for bit in range(32):
                    queries.append(f"? {i} {1 << bit}")

            log.info(f"  Sending {len(queries)} queries...")

            def sender():
                for idx in range(0, len(queries), 200):
                    chunk = "\n".join(queries[idx:idx+200]) + "\n"
                    p.send(chunk.encode())

            th = threading.Thread(target=sender); th.start()

            responses = []
            for j in range(len(queries)):
                line = p.recvline().strip()
                responses.append(int(line))
                if (j + 1) % 5000 == 0:
                    log.info(f"  Read {j+1}/{len(queries)}")
            th.join()

            for i in range(num):
                val = 0
                for bit in range(32):
                    if responses[i * 32 + bit] == 1:
                        val |= (1 << bit)
                rc.submit(val)
            state_recovered = True
            log.info("  MT state recovered!")

            for i in range(num + 1, n):
                rc.predict_getrandbits(32)
            pred = rc.predict_getrandbits(32)
        else:
            for i in range(n - 1):
                rc.predict_getrandbits(32)
            pred = rc.predict_getrandbits(32)

        log.info(f"  Answer: ! {pred}")
        p.sendline(f"! {pred}".encode())

    log.info("All answers sent, reading remaining output...")
    try:
        remaining = p.recvall(timeout=5)
        log.info(f"Output: {remaining}")
    except:
        pass
    p.close()

if __name__ == "__main__":
    main()
