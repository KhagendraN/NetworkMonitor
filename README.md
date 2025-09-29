# 🌐 NetworkMonitor

**A comprehensive C++ network monitoring system that tracks devices and their activities on local networks.**

## ✨ Features

🔍 **Device Discovery** - ARP scanning with MAC vendor identification  
📊 **Traffic Monitoring** - Real-time packet capture and analysis  
🌐 **Website Tracking** - DNS monitoring and visited sites detection  
📈 **Activity Reports** - Per-device activity summaries with timestamps  

## 📸 Screenshot

![ARP Scanner Output](assets/output.gif)

## 🚀 Quick Start

### Build
```bash
# Using Makefile (recommended)
make

# Or manually
g++ -std=c++17 -Wall -Wextra network_monitor.cpp network_tracker.cpp arp_scanner.cpp log_writer.cpp dns_parser.cpp -lpcap -pthread -o network_monitor
```

### Run
```bash
sudo ./network_monitor --debug
```

## 📊 Sample Output

```
IP Address     MAC Address       Vendor              Hostname       Status    Packets   DNS Queries Visited Sites       
----------------------------------------------------------------------------------------------------------------------------------
192.168.1.11   94:bb:43:de:d6:36 AzureWave Technolog archlinux      Active    506       29          amazon.com,face...  
192.168.1.5    fc:19:99:c8:b7:9e Xiaomi Communicatio xiaomi-phone   Active    124       15          youtube.com,goo...  
```

## �️ Requirements

- **Linux** (tested on Arch Linux)
- **libpcap** development libraries
- **C++17** compiler (g++/clang++)
- **Root privileges** (for packet capture)

## 📋 Command Line Options

```bash
sudo ./network_monitor [options]
  -d, --debug          Enable debug logging
  -i, --interface      Specify network interface
  -t, --time          Set monitoring duration (seconds)
  -q, --quick         Quick 60-second scan
  -h, --help          Show help message
```

## 🎯 How It Works

1. **ARP Scanning** discovers devices on the local network
2. **Packet Capture** monitors all network traffic in real-time  
3. **Service Detection** identifies popular websites by IP ranges
4. **Activity Tracking** associates traffic with specific devices
5. **Real-time Reports** show live device activity and visited sites

---
**Built with ❤️ using modern C++17, libpcap, and multithreading**
- Continuous ARP-based device discovery
- Device state tracking (active/inactive with timeouts)
- MAC vendor lookup integration
- Device activity counters

**Traffic Analysis:**
- Real-time packet capture and analysis
- Device-traffic association by IP/MAC matching
- Protocol-specific handling (TCP, UDP, DNS, ICMP)
- Activity event logging with timestamps

**DNS Integration:**  
- DNS packet parsing and domain extraction
- Per-device domain tracking
- Query-response correlation
- Website visit history per device

### 🔧 **Supporting Components**

**ARP Scanner** (`arp_scan.cpp`) - Standalone device discovery tool
**DNS Parser** (`dns_parser.cpp`) - DNS packet analysis engine  
**Logger System** (`log_writer.cpp`) - Structured logging with color coding
**Network Monitor** (`network_monitor.cpp`) - Main application interface

## Files
- `network_tracker.cpp/h`: **Core comprehensive monitoring system** ✅
- `network_monitor.cpp`: **Main application interface** ✅
- `arp_scan.cpp`: Standalone ARP network scanner ✅
- `dns_parser.cpp/h`: DNS packet parsing engine ✅
- `dns_monitor.cpp`: Standalone DNS traffic monitor ✅
- `log_writer.cpp/h`: Structured logging with color coding ✅
- `oui.csv`: MAC address vendor database (37,524+ entries)
- `test_dns_parser.cpp`: DNS parser unit tests ✅

## Prerequisites

- Linux operating system
- libpcap development library
- Root privileges (for raw socket access)
- C++17 compatible compiler

## Installation

1. Install dependencies:
```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev g++

# Fedora/CentOS
sudo dnf install libpcap-devel gcc-c++
```

2. Compile the applications:
```bash
# Main Comprehensive Network Monitor
g++ -o network_monitor network_monitor.cpp network_tracker.cpp dns_parser.cpp log_writer.cpp -lpcap -std=c++17

# Standalone Tools (optional)
g++ -o arp_scan arp_scan.cpp log_writer.cpp -lpcap -std=c++17
g++ -o dns_monitor dns_monitor.cpp dns_parser.cpp log_writer.cpp -lpcap -std=c++17
```

## Usage

### 🚀 **Comprehensive Network Monitoring** (Recommended)

**Continuous monitoring** - tracks devices and their activities over time:

```bash
# Start continuous monitoring (Press Ctrl+C to generate reports)
sudo ./network_monitor

# Quick 60-second scan
sudo ./network_monitor --quick

# Monitor for specific duration (5 minutes)
sudo ./network_monitor --time 300

# Use specific network interface
sudo ./network_monitor --interface eth0
```

**Sample Output:**
```
🚀 NetworkMonitor v2.0 - Comprehensive Network Monitoring
🔍 Starting Comprehensive Network Monitoring
📡 Interface: wlan0
🎯 Objective: Track devices and monitor their network activity

This system will:
  ✓ Discover devices via ARP scanning
  ✓ Track device activity and traffic patterns
  ✓ Monitor DNS queries to see websites visited
  ✓ Associate all network activity with specific devices
  ✓ Generate per-device activity reports

📊 Monitoring active - Press Ctrl+C to stop and generate reports

=== Live Status Update ===
Active devices: 5
Total devices seen: 8
Most active devices:
  192.168.1.100 (Apple) - 1,247 packets, 89 DNS queries
  192.168.1.101 (Samsung) - 892 packets, 45 DNS queries
  192.168.1.1 (Cisco Systems) - 234 packets, 12 DNS queries

=== Final Device Summary ===
IP Address      MAC Address       Vendor              Status    Packets   Last Seen
192.168.1.100   12:34:56:78:9A    Apple               Active    1,247     14:23:45
192.168.1.101   AB:CD:EF:12:34    Samsung             Active    892       14:23:42
192.168.1.1     AA:BB:CC:DD:EE    Cisco Systems       Active    234       14:23:40

=== Per-Device Domain Access ===
Device: 192.168.1.100 (Apple iPhone)
Domains accessed: 23
  • google.com
  • apple.com  
  • icloud.com
  • facebook.com
  • youtube.com
```

### 📡 **Standalone Tools** (For specific tasks)

**ARP Scanner** - Device discovery only:
```bash
sudo ./arp_scan
```

**DNS Monitor** - DNS traffic only:
```bash  
sudo ./dns_monitor [interface]
```

**Sample ARP Scanner Output:**
```
[STATUS] NetworkMonitor ARP Scanner Starting...
[INFO] Loaded 37524 MAC vendor entries from oui.csv
[INFO] Using interface: wlan0
[STATUS] Device discovered: 192.168.1.1 (AA:BB:CC:DD:EE:FF) - Cisco Systems
[STATUS] Device discovered: 192.168.1.100 (12:34:56:78:9A:BC) - Apple
[STATUS] Scan complete. Found 5 devices.
```

## Technical Details

### Comprehensive System Implementation
- **Device Discovery**: Continuous ARP scanning every 5 minutes
- **Traffic Monitoring**: Real-time packet capture with device association
- **DNS Analysis**: Query parsing and domain tracking per device  
- **Data Persistence**: Activity logging with configurable retention
- **Live Reporting**: Real-time status updates and final comprehensive reports


## Troubleshooting

### Common Issues

1. **No devices found:**
   - Ensure you're running with `sudo`
   - Check if other devices exist on the network
   - Some devices may not respond to ARP requests
   - Network firewall might be blocking traffic

2. **Permission denied:**
   - Run with `sudo` for raw socket access
   - Ensure user has CAP_NET_RAW capability

3. **Interface not found:**
   - Check available interfaces: `ip addr show`
   - Modify interface name in code if needed

## Contributing

This project is under active development. Feel free to contribute by:
- Testing the ARP scanner on different networks
- Reporting issues and edge cases
- Suggesting new monitoring features
- Improving documentation

---

*Last Updated: September 29, 2025*
