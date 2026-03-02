#!/bin/bash
# Restricted shell for pilot user
# Allows: limited recon tools on internal subnet + SSH tunneling
# Denies: everything else

NETWORK_ENV="/etc/shadowroute-network.env"

# Prefer runtime-selected network values from entrypoint.
if [ -r "$NETWORK_ENV" ]; then
    # shellcheck disable=SC1090
    . "$NETWORK_ENV"
fi

if echo "${STATION_IP:-}" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$'; then
    INTERNAL_IP="$STATION_IP"
else
    INTERNAL_IP=$(ip -4 addr show dev lo | awk '/inet /{print $2}' | cut -d/ -f1 | grep -E '^(10\.13\.37|127\.13\.37)\.' | head -1)
fi

if [ -z "$INTERNAL_IP" ]; then
    INTERNAL_IP="127.13.37.1"
fi

if ! echo "${INTERNAL_SUBNET:-}" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'; then
    INTERNAL_SUBNET=$(echo "$INTERNAL_IP" | sed 's/\.[0-9]*$/.0\/24/')
fi
SUBNET_PREFIX="${INTERNAL_SUBNET%0/24}"

# Validate that any explicit IPv4/CIDR target stays inside the active internal subnet.
is_allowed_target() {
    local token="$1"
    if [ "${INTERNAL_SUBNET#*/}" = "24" ] && echo "$INTERNAL_SUBNET" | grep -qE '^([0-9]{1,3}\.){3}0/24$'; then
        local escaped_prefix
        escaped_prefix=$(printf '%s' "$SUBNET_PREFIX" | sed 's/\./\\./g')
        echo "$token" | grep -qE "^${escaped_prefix}([0-9]{1,3}|\\*)(-[0-9]{1,3})?(\\/[0-9]{1,2})?$"
    else
        [ "$token" = "$INTERNAL_IP" ] || [ "$token" = "$INTERNAL_SUBNET" ]
    fi
}

echo ""
echo "  ★ HELIOS DOCKING PORT - CONNECTED ★"
echo ""
echo "  Welcome, pilot. Restricted terminal active."
echo "  Internal network detected: $INTERNAL_SUBNET"
echo ""
echo "  Type 'help' for available commands."
echo ""

while true; do
    read -r -p "pilot@helios:~$ " input 2>/dev/null || exit 0
    
    # Parse command and args
    cmd=$(echo "$input" | awk '{print $1}')
    args=$(echo "$input" | cut -d' ' -f2-)

    case "$cmd" in
        nmap)
            if [ -z "$args" ]; then
                echo "  Usage: nmap <target in $INTERNAL_SUBNET> [options]"
                continue
            fi

            # In loopback-simulated fallback mode, subnet ping sweeps on 127/8 are misleading.
            # Keep writeup behavior deterministic by resolving sweep mode to the active station host.
            if [ "${INTERNAL_MODE:-}" = "loopback-simulated" ] &&
               echo "$args" | grep -qE '(^|[[:space:]])-sn([[:space:]]|$)' &&
               echo "$args" | grep -q -- "$INTERNAL_SUBNET"; then
                /usr/bin/nmap -sn "$INTERNAL_IP"
                continue
            fi

            # Extract IPv4/CIDR-like tokens from the command for subnet validation.
            ip_tokens=$(echo "$args" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}([/-][0-9]{1,3})?')

            if [ -z "$ip_tokens" ]; then
                echo "  Please specify a target in $INTERNAL_SUBNET."
                continue
            fi

            invalid_target=""
            for token in $ip_tokens; do
                if ! is_allowed_target "$token"; then
                    invalid_target="$token"
                    break
                fi
            done

            if [ -n "$invalid_target" ]; then
                echo "  Access restricted to internal network only ($INTERNAL_SUBNET)."
                echo "  Invalid target: $invalid_target"
                continue
            fi

            # Pass user-supplied nmap arguments through unchanged after validation.
            /usr/bin/nmap $args
            ;;
        help)
            echo ""
            echo "  AVAILABLE COMMANDS:"
            echo "    nmap <target>    Scan hosts on the internal network"
            echo "    help             Show this message"
            echo "    exit             Disconnect"
            echo ""
            ;;
        exit|quit|logout)
            echo "  Disconnecting from Helios Station..."
            exit 0
            ;;
        "")
            ;;
        *)
            echo "  -bash: $cmd: command not found"
            ;;
    esac
done
