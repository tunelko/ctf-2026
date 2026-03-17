import os
import subprocess
import tempfile

print("Input your code (1 line)")
code = input("> ")

banned_char = "#[]<>#%$:_ '\"*=,?\\/|0123456789-+"

if any(c in banned_char for c in code):
    print("You can't use those characters!")
    exit(1)

mainCode = f"""
int main()
{{
{code}
}}
"""

with tempfile.TemporaryDirectory() as td:
    src_path = os.path.join(td, "source.c")
    compiled_path = os.path.join(td, "compiled")
    with open(src_path, "w") as file:
        file.write(mainCode)

    returncode = subprocess.call(
        ["gcc", "-B/usr/bin", "-w", "-O3", "-o", compiled_path, src_path],
        stderr=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL
    )

    if returncode != 0:
        print("Oops, there were some compilation errors!")
        exit(1)

    print("Good luck!")
    subprocess.call([compiled_path])
