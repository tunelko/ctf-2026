#!/bin/bash

LISTEN_PORT=50001 # Reverse of 1337 (this fun)
CHALLENGE_PATH="/challenge/jail.py"

while :
do
    su user -c "exec socat TCP-LISTEN:${LISTEN_PORT},reuseaddr,fork EXEC:'python3 $CHALLENGE_PATH,stderr'";
done
