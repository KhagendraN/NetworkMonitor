# NetworkMonitor

A network monitoring and discovery tool for local network analysis.

## Features

### ARP Scanner ✅ (Implemented)
- **Network Device Discovery**: Scans local network (192.168.x.x/24) to find active devices
- **MAC Address Vendor Lookup**: Identifies device manufacturers using OUI database (37,524+ entries)
- **Hostname Resolution**: Attempts to resolve device hostnames
- **Real-time Results**: Shows discovered devices with IP, MAC, vendor, and hostname information

### Planned Features (Coming Soon)
- DNS Traffic Monitoring
- Network Usage Logging
- Web Domain Tracking
- Traffic Analysis Dashboard

## Current Implementation

### ARP Scanner (`arp_scan.cpp`)
The ARP scanner discovers devices on your local network by sending ARP requests and analyzing responses.

**Key Features:**
- Uses raw sockets for ARP packet crafting
- Integrates with comprehensive OUI.csv database for vendor identification
- Non-blocking timeout mechanism (3-second scan duration)
- Detailed error reporting and debugging information
- Gateway connectivity testing

## Files
- `arp_scan.cpp`: Network device discovery using ARP protocol
- `oui.csv`: MAC address vendor database (37,524+ entries)
- `dns_parser.cpp`: DNS packet parsing (planned)
- `log_writer.cpp`: Network activity logging (planned)
- `sniffer.cpp`: General packet capture (planned)

## 📸 Screenshot

![ARP Scanner Output](assets/Screenshot_16-Jun_19-23-49_32412.png)

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

2. Compile the ARP scanner:
```bash
g++ -o arp_scan arp_scan.cpp -lpcap -std=c++17
```

## Usage

### ARP Network Scanner

Run the ARP scanner to discover devices on your local network:

```bash
sudo ./arp_scan
```

**Sample Output:**
```
Loading MAC vendor database...
Loaded 37524 MAC vendor entries from oui.csv
Using interface: wlan0
Source MAC: 94:BB:43:DE:D6:36
Source IP: 192.168.254.11
Testing connectivity to gateway: 192.168.254.1
ARP request sent to gateway successfully
Gateway responded! Network is working.
Sending ARP requests to 254 addresses...
Sent 254 ARP requests successfully, 0 failed.
Listening for replies for 3 seconds...

Device found:
  IP       : 192.168.254.1
  MAC      : AA:BB:CC:DD:EE:FF
  Hostname : router.local
  Vendor   : Cisco Systems
--------------------------------------
Scan complete. Found 1 devices.
```

## Technical Details

### ARP Scanner Implementation
- **Protocol**: Uses ARP (Address Resolution Protocol) for device discovery
- **Scope**: Scans entire /24 subnet (254 addresses)
- **Database**: Loads MAC vendor information from IEEE OUI registry
- **Performance**: 2ms delay between requests to avoid network flooding
- **Timeout**: 3-second listening window for responses

### Network Interface Detection
- Automatically uses `wlan0` interface (configurable)
- Validates interface availability and permissions
- Extracts source MAC and IP for ARP requests

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

## Development Status

- ✅ **ARP Scanner**: Fully implemented and functional
- 🔄 **DNS Monitor**: Planned for next iteration
- 🔄 **Web Usage Tracker**: Future enhancement
- 🔄 **Traffic Logger**: Future enhancement

## Contributing

This project is under active development. Feel free to contribute by:
- Testing the ARP scanner on different networks
- Reporting issues and edge cases
- Suggesting new monitoring features
- Improving documentation

---

*Last Updated: September 27, 2025*
