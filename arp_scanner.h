#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <cstdint>

// Structure to hold discovered device information
struct DiscoveredDevice {
    std::string ip;
    std::string mac;
    std::string vendor;
    std::string hostname;
    
    DiscoveredDevice() = default;
    DiscoveredDevice(const std::string& ip_addr, const std::string& mac_addr, 
                    const std::string& vendor_name, const std::string& host_name)
        : ip(ip_addr), mac(mac_addr), vendor(vendor_name), hostname(host_name) {}
};

// Callback function type for device discovery
using DeviceDiscoveryCallback = std::function<void(const DiscoveredDevice&)>;

class ARPScanner {
public:
    explicit ARPScanner(const std::string& interface_name);
    ~ARPScanner();
    
    // Initialize the scanner
    bool initialize();
    
    // Load OUI database for vendor lookup
    bool loadOUIDatabase(const std::string& oui_file = "oui.csv");
    
    // Perform network scan
    std::vector<DiscoveredDevice> performScan(int timeout_seconds = 3);
    
    // Perform scan with callback for real-time results
    void performScanWithCallback(DeviceDiscoveryCallback callback, int timeout_seconds = 3);
    
    // Get last scan results
    const std::vector<DiscoveredDevice>& getLastScanResults() const;
    
    // Check if scanner is ready
    bool isReady() const;
    
    // Get scanner interface
    const std::string& getInterface() const { return interface; }
    
private:
    std::string interface;
    std::map<std::string, std::string> oui_map;
    std::vector<DiscoveredDevice> last_scan_results;
    bool initialized;
    
    // Internal helper functions
    bool getInterfaceInfo(uint8_t* mac, uint32_t* ip);
    bool sendARPRequests(int socket, const uint8_t* src_mac, uint32_t src_ip);
    std::string lookupVendor(const uint8_t* mac_bytes);
    std::string getHostname(uint32_t ip_addr);
    
    // Static packet handler for pcap
    static void packetHandler(u_char* user_data, const struct pcap_pkthdr* header, const u_char* packet);
};
