#!/bin/bash

# === Configuration ===
INTERFACE="any"            # Use "any" for all interfaces
LOGFILE="/tmp/traffic_log.txt"
INTERVAL=1                # Update interval in seconds

# === Colors ===
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# === Ensure root permissions ===
if [[ $EUID -ne 0 ]]; then
   echo -e "${BLUE}⚠️ This script requires sudo to capture packets.${NC}"
   echo "Usage: sudo $0"
   exit 1
fi

# === Check for required tools ===
for cmd in tcpdump dig awk; do
    if ! command -v "$cmd" &>/dev/null; then
        echo -e "${BLUE}❌ '$cmd' not found. Install with:${NC}"
        case "$cmd" in
            tcpdump) echo "      sudo apt install tcpdump   # Debian/Ubuntu"; echo "      sudo yum install tcpdump   # CentOS/RHEL"; ;;
            dig) echo "      sudo apt install dnsutils     # Debian/Ubuntu"; echo "      sudo yum install bind-utils   # CentOS/RHEL"; ;;
        esac
        exit 1
    fi
done

# === Clear screen function ===
clear_screen() {
    printf "\033c"
}

# === Resolve domain to IP using dig ===
resolve_domain() {
    local domain="$1"
    dig +short "$domain" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1
}

# === Count packets from tcpdump output ===
analyze_packets() {
    awk '
    BEGIN {
        tcp=udp=icmp=other=0
    }
    /IP/ {
        proto = ""
        if ($0 ~ /proto/) {
            split($0, a, "proto ");
            split(a[2], b, " ");
            proto = b[1];
        } else if ($0 ~ /ICMP/) {
            proto = "ICMP";
        }

        if (proto == "TCP") tcp++;
        else if (proto == "UDP") udp++;
        else if (proto == "ICMP") icmp++;
        else other++;
    }
    END {
        print "TCP:" tcp;
        print "UDP:" udp;
        print "ICMP:" icmp;
        print "Other:" other;
    }
    ' "$LOGFILE"
}

# === Prompt user for target domain or IP ===
get_target_input() {
    while true; do
        read -p "Enter domain/IP to analyze (e.g., google.com): " user_input
        user_input=$(echo "$user_input" | xargs)

        if [[ -z "$user_input" ]]; then
            echo -e "${BLUE}⚠️ Please enter a domain or IP address.${NC}"
            continue
        fi

        if [[ "$user_input" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo -e "${GREEN}✅ Filtering traffic to/from IP: $user_input${NC}"
            FILTER="host $user_input"
            TARGET_INFO="$user_input (IP)"
            break
        else
            resolved_ip=$(resolve_domain "$user_input")
            if [[ -n "$resolved_ip" ]]; then
                echo -e "${GREEN}✅ Resolved $user_input → $resolved_ip${NC}"
                FILTER="host $resolved_ip"
                TARGET_INFO="$user_input ($resolved_ip)"
                break
            else
                echo -e "${BLUE}⚠️ Could not resolve domain. Try again.${NC}"
            fi
        fi
    done
}

# === Start packet capture with optional filter ===
start_capture() {
    > "$LOGFILE"
    timeout "$INTERVAL" tcpdump -i "$INTERFACE" -nn $FILTER >> "$LOGFILE" 2>/dev/null &
    CAPTURE_PID=$!
}

# === Stop current packet capture ===
stop_capture() {
    if [ -n "$CAPTURE_PID" ]; then
        kill "$CAPTURE_PID" &>/dev/null
    fi
}

# === Main loop to monitor traffic ===
main_loop() {
    clear_screen
    echo -e "${GREEN}🟢 Capturing packets... Press Ctrl+C to stop.${NC}\n"

    while true; do
        start_capture

        clear_screen
        echo "📡 CLI Network Traffic Analyzer"
        echo "=============================="
        analyze_packets | while IFS=: read -r key val; do
            val=${val:-0}
            printf "%-6s %s\n" "$key" "$val"
        done
        echo "------------------------------"
        echo "Target : $TARGET_INFO"
        echo "=============================="
        echo -e "${BLUE}Press Ctrl+C to stop.${NC}"

        stop_capture
        sleep "$INTERVAL"
    done
}

# === Trap Ctrl+C to clean up ===
trap 'echo -e "\n🛑 Stopping packet capture..."; exit 0' INT

# === Main Program ===

echo "📡 CLI Network Traffic Analyzer"
echo "=============================="

get_target_input

main_loop