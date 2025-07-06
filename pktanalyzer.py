import socket
import threading
import time
from scapy.all import sniff, IP, TCP, UDP, ICMP, AsyncSniffer


# === Global variables ===
packet_counts = {
    "TCP": 0,
    "UDP": 0,
    "ICMP": 0,
    "Other": 0
}

count_lock = threading.Lock()
FILTER_DOMAIN = None
filter_ip = None
sniffer = None
running = True


def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        print(f"❌ Unable to resolve domain: {domain}")
        return None


def packet_callback(packet):
    global filter_ip
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Apply filter
        if filter_ip and src_ip != filter_ip and dst_ip != filter_ip:
            return

        proto = ip_layer.proto
        with count_lock:
            if proto == 6:  # TCP
                packet_counts["TCP"] += 1
            elif proto == 17:  # UDP
                packet_counts["UDP"] += 1
            elif proto == 1:  # ICMP
                packet_counts["ICMP"] += 1
            else:
                packet_counts["Other"] += 1


def start_sniffer():
    global sniffer, filter_ip
    bpf_filter = f"host {filter_ip}" if filter_ip else None
    sniffer = AsyncSniffer(filter=bpf_filter, prn=packet_callback, store=False)
    sniffer.start()


def stop_sniffer(signum=None, frame=None):
    global running, sniffer
    print("\n🛑 Stopping packet capture...")
    if sniffer and sniffer.running:
        sniffer.stop()
    running = False


def clear_screen():
    print("\033c", end="")


def display_stats():
    while running:
        clear_screen()
        print("📡 CLI Network Traffic Analyzer")
        print("=" * 30)
        for proto, count in packet_counts.items():
            print(f"{proto+':':<6} {count}")
        print("-" * 30)
        print(f"Target : {FILTER_DOMAIN or 'None'} ({filter_ip or 'All'})")
        print("=" * 30)
        print("Press Ctrl+C to stop.")
        time.sleep(1)


def get_user_input():
    global FILTER_DOMAIN, filter_ip
    while True:
        user_input = input("Enter domain/IP to analyze (e.g., google.com): ").strip()

        if not user_input:
            print("⚠️ Please enter a domain or IP address.\n")
            continue

        if '/' in user_input:
            print("⚠️ Invalid input. Do not include CIDR notation.\n")
            continue

        if '.' in user_input and all(part.isdigit() for part in user_input.split('.')):
            # It's an IP
            print(f"✅ Filtering traffic to/from IP: {user_input}")
            filter_ip = user_input
            FILTER_DOMAIN = None
            break
        else:
            resolved_ip = resolve_domain(user_input)
            if resolved_ip:
                print(f"✅ Resolved {user_input} → {resolved_ip}")
                FILTER_DOMAIN = user_input
                filter_ip = resolved_ip
                break
            else:
                print("⚠️ Could not resolve domain. Try again.\n")

    start_sniffer()


if __name__ == "__main__":
    import signal

    signal.signal(signal.SIGINT, stop_sniffer)
    signal.signal(signal.SIGTERM, stop_sniffer)

    print("📡 CLI Network Traffic Analyzer\n")

    # Ask for target first
    get_user_input()

    # Start stats display
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()

    print("\n🟢 Capturing packets...\nPress Ctrl+C to stop.\n")

    try:
        while running:
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop_sniffer()