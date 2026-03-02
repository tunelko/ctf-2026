#!/usr/bin/env bash

rm /entrypoint.sh
cd /app

flag='clctf{FAKE_FLAG}'
jwt_secret="$(head -c 64 /dev/urandom | base64 -w 0)"

FLAG="$flag" JWT_SECRET="$jwt_secret" ./secure-sign