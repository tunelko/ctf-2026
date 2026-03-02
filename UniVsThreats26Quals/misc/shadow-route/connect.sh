#!/bin/bash
# Conectar a la instancia shadow-route
# Uso: ./connect.sh HOST PORT
# Ejemplo: ./connect.sh 194.102.62.175 22512

HOST="${1:-194.102.62.175}"
PORT="${2:-22512}"

echo "$HOST:$PORT como pilot..."
sshpass -p 'docking-request' ssh -o StrictHostKeyChecking=no -p "$PORT" pilot@"$HOST"
