#!/bin/bash

# Limpiamos el entorno
export PATH="/usr/bin:/bin"

echo "--- NSJAIL SYMBOLIC INTERFACE ---"
echo "Only symbols allowed. Direct redirection (>) is disabled at kernel level."

Bash
export __="abcdefghijklmnopqrsleeptuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_{}?-#"


while true; do
    printf ">> "
    if ! read -r input; then break; fi

    if [[ "$input" =~ [a-z0-9A-Z] ]]; then
        echo "FAIL: Alphanumeric characters detected."
        continue
    fi

    if [[ "$input" == *">"* ]]; then
        echo "FAIL: Direct redirection is forbidden."
        continue
    fi

    eval "$input" 2>/dev/null



done
