A simple CLI-based network traffic analyzer that captures and analyzes packets in real time. It allows filtering by domain or IP address and displays live statistics for TCP, UDP, ICMP, and other protocols.

🧠 Overview
##This project includes two versions:

✅ Python version : Uses scapy to sniff and analyze packets.
✅ Bash version : Uses tcpdump, dig, and shell scripting for packet analysis.


##Both versions:

Accept a domain or IP input from the user
Start capturing only traffic related to that target
Display real-time packet counts
Support clean exit with Ctrl+C

🐍 Python Version (pktanalyzer.py)
✅ Features
Real-time packet capture using scapy.AsyncSniffer
Resolves domains to IPs automatically
Tracks: TCP, UDP, ICMP, Other
Displays stats every second
Clean shutdown on Ctrl+C
##🛠️ Requirements

pip install scapy
Run as administrator/root for packet capture: 

sudo python pktanalyzer.py
📋 Usage
Run the script
Enter a domain (e.g., google.com) or an IP (e.g., 8.8.8.8)
Watch real-time traffic stats update every second
Press Ctrl+C to stop
🐚 Bash Version (traffic_analyzer.sh)
✅ Features
Lightweight bash-only implementation
Uses tcpdump, dig, and awk for packet capture & analysis
Resolves domain names to IPs
Shows live packet count updates
No background threads or race conditions
##🛠️ Requirements
Install these tools once:

Debian/Ubuntu:

sudo apt install tcpdump dnsutils
CentOS/RHEL:

sudo yum install tcpdump bind-utils
macOS (with Homebrew):

brew install tcpdump
Run with root privileges: 


sudo ./traffic_analyzer.sh
📋 Usage
Save and make executable

chmod +x traffic_analyzer.sh
Run with sudo

sudo ./traffic_analyzer.sh
Enter a domain or IP when prompted
View real-time stats
Press Ctrl+C to stop
📌 Future Work / Enhancements
Here are some great ideas to expand this project:

🔍 For Both Versions
Add option to export captured packets as .pcap file
Log traffic stats to file (traffic.log)
Show top source/destination IPs
Add color-coded output using ANSI codes
Allow filtering by port number
🖥️ For Python Version
Use argparse for command-line arguments
Add support for multiple interfaces
Include protocol-specific filters (e.g., only TCP)
Add a GUI interface using tkinter or curses
🐚 For Bash Version
Add auto-restart filter without restarting script
Add keyboard shortcuts (like 'r' to reset filter)
Support filtering by port
Add CSV logging of stats
