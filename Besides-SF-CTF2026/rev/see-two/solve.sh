#!/bin/bash
# see-two: Build Go binary with correct UUID to connect to C2 server
# The client needs a specific built-in UUID to authenticate

UUID="21f96e72-4e88-49a4-a1ff-2000db761089"

echo "[*] Building client with UUID: $UUID"
go build -ldflags "-X main.builtClientUUID=$UUID" -o client_patched .

echo "[+] Run ./client_patched to connect and retrieve flag"
echo "[+] FLAG: CTF{c2itthatth3fil3sar3f0und}"
