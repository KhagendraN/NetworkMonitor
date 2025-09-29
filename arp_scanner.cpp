#include "arp_scanner.h"
#include "log_writer.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <cstring>
#include <ctime>
#include <algorithm>

// Structure for passing data to packet handler
struct ScanContext {
    ARPScanner* scanner;
    std::vector<DiscoveredDevice>* results;
    DeviceDiscoveryCallback callback;
    bool use_callback;
    
    ScanContext(ARPScanner* s, std::vector<DiscoveredDevice>* r) 
        : scanner(s), results(r), use_callback(false) {}
    ScanContext(ARPScanner* s, DeviceDiscoveryCallback cb) 
        : scanner(s), results(nullptr), callback(cb), use_callback(true) {}
};

ARPScanner::ARPScanner(const std::string& interface_name) 
    : interface(interface_name), initialized(false) {
}

ARPScanner::~ARPScanner() {
    // Cleanup handled automatically by destructors
}

bool ARPScanner::initialize() {
    Logger::Debug("Initializing ARP scanner for interface: " + interface);
    
    // Test if we can create a raw socket (requires root privileges)
    int test_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (test_sock < 0) {
        Logger::Error("Cannot create raw socket. Make sure you're running as root or with CAP_NET_RAW capability.");
        return false;
    }
    close(test_sock);
    
    // Test if we can open pcap handle
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* test_handle = pcap_open_live(interface.c_str(), 65536, 1, 1000, errbuf);
    if (!test_handle) {
        Logger::Error("Cannot open pcap handle for interface " + interface + ": " + std::string(errbuf));
        return false;
    }
    pcap_close(test_handle);
    
    initialized = true;
    Logger::Debug("ARP scanner initialized successfully");
    return true;
}

bool ARPScanner::loadOUIDatabase(const std::string& oui_file) {
    Logger::Info("Loading MAC vendor database from " + oui_file + "...");
    
    std::ifstream file(oui_file);
    if (!file.is_open()) {
        Logger::Warning("Could not open OUI database file: " + oui_file);
        return false;
    }
    
    oui_map.clear();
    std::string line;
    int loaded = 0;
    
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        
        // Parse CSV format: Registry,Assignment,Organization Name,Organization Address
        size_t first_comma = line.find(',');
        if (first_comma == std::string::npos) continue;
        
        size_t second_comma = line.find(',', first_comma + 1);
        if (second_comma == std::string::npos) continue;
        
        size_t third_comma = line.find(',', second_comma + 1);
        if (third_comma == std::string::npos) continue;
        
        // Extract OUI (second column) and vendor (third column)
        std::string oui = line.substr(first_comma + 1, second_comma - first_comma - 1);
        std::string vendor = line.substr(second_comma + 1, third_comma - second_comma - 1);
        
        // Remove quotes if present
        if (!vendor.empty() && vendor[0] == '\"' && vendor.back() == '\"') {
            vendor = vendor.substr(1, vendor.length() - 2);
        }
        
        // Convert OUI to uppercase for consistency
        std::transform(oui.begin(), oui.end(), oui.begin(), ::toupper);
        
        oui_map[oui] = vendor;
        loaded++;
    }
    
    Logger::Info("Loaded " + std::to_string(loaded) + " MAC vendor entries");
    return loaded > 0;
}

bool ARPScanner::getInterfaceInfo(uint8_t* mac, uint32_t* ip) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    
    // Get MAC address
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    
    // Get IP address
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return false;
    }
    *ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
    
    close(fd);
    return true;
}

bool ARPScanner::sendARPRequests(int socket, const uint8_t* src_mac, uint32_t src_ip) {
    struct sockaddr_ll sa;
    memset(&sa, 0, sizeof(sa));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(interface.c_str());
    sa.sll_hatype = ARPHRD_ETHER;
    sa.sll_pkttype = PACKET_BROADCAST;
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xff, 6); // Broadcast
    
    // Create ARP request packet
    struct {
        struct ether_header eth;
        struct ether_arp arp;
    } packet;
    
    // Ethernet header
    memset(packet.eth.ether_dhost, 0xff, 6); // Broadcast
    memcpy(packet.eth.ether_shost, src_mac, 6);
    packet.eth.ether_type = htons(ETHERTYPE_ARP);
    
    // ARP header
    packet.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    packet.arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    packet.arp.ea_hdr.ar_hln = 6;
    packet.arp.ea_hdr.ar_pln = 4;
    packet.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);
    
    memcpy(packet.arp.arp_sha, src_mac, 6);
    memcpy(packet.arp.arp_spa, &src_ip, 4);
    memset(packet.arp.arp_tha, 0, 6);
    
    int sent = 0, failed = 0;
    
    // Send ARP requests to all hosts in subnet
    for (int i = 1; i <= 254; i++) {
        uint32_t target_ip = src_ip;
        ((uint8_t*)&target_ip)[3] = i;
        
        memcpy(packet.arp.arp_tpa, &target_ip, 4);
        
        if (sendto(socket, &packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa)) > 0) {
            sent++;
        } else {
            failed++;
        }
        
        usleep(1000); // 1ms delay between requests
    }
    
    Logger::Info("Sent " + std::to_string(sent) + " ARP requests, " + std::to_string(failed) + " failed");
    return sent > 0;
}

std::string ARPScanner::lookupVendor(const uint8_t* mac_bytes) {
    char oui_str[9];
    snprintf(oui_str, sizeof(oui_str), "%02X%02X%02X", mac_bytes[0], mac_bytes[1], mac_bytes[2]);
    
    std::string oui_string(oui_str);
    Logger::Debug("Looking up OUI: " + oui_string + " in database with " + std::to_string(oui_map.size()) + " entries");
    
    auto it = oui_map.find(oui_string);
    if (it != oui_map.end()) {
        Logger::Debug("Found vendor for " + oui_string + ": " + it->second);
        return it->second;
    } else {
        Logger::Debug("No vendor found for OUI: " + oui_string);
        // Check if there are any similar entries (for debugging)
        int similar_count = 0;
        for (const auto& entry : oui_map) {
            if (entry.first.substr(0, 2) == oui_string.substr(0, 2)) {
                similar_count++;
                if (similar_count <= 3) {  // Show first 3 similar entries
                    Logger::Debug("Similar OUI found: " + entry.first + " -> " + entry.second);
                }
            }
        }
        return "Unknown";
    }
}

std::string ARPScanner::getHostname(uint32_t ip_addr) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_addr;
    
    char hostname[NI_MAXHOST];
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), 
                   nullptr, 0, NI_NAMEREQD) == 0) {
        return std::string(hostname);
    }
    
    // Try without NI_NAMEREQD flag
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), 
                   nullptr, 0, 0) == 0) {
        return std::string(hostname);
    }
    
    return "Unknown";
}

void ARPScanner::packetHandler(u_char* user_data, [[maybe_unused]] const struct pcap_pkthdr* header, const u_char* packet) {
    ScanContext* context = reinterpret_cast<ScanContext*>(user_data);
    
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;
    
    struct ether_arp* arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) return;
    
    // Extract device information
    char ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->arp_spa, ip_str, sizeof(ip_str));
    
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
             arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
             arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
    
    std::string vendor = context->scanner->lookupVendor(arp->arp_sha);
    uint32_t ip_addr;
    memcpy(&ip_addr, arp->arp_spa, 4);
    std::string hostname = context->scanner->getHostname(ip_addr);
    
    Logger::Debug("Raw ARP reply - IP: " + std::string(ip_str) + ", MAC: " + std::string(mac_str) + ", Vendor: " + vendor);
    
    DiscoveredDevice device(ip_str, mac_str, vendor, hostname);
    
    Logger::Status("Device discovered - IP: " + device.ip + ", MAC: " + device.mac);
    
    if (context->use_callback && context->callback) {
        context->callback(device);
    } else if (context->results) {
        context->results->push_back(device);
    }
}

std::vector<DiscoveredDevice> ARPScanner::performScan(int timeout_seconds) {
    if (!initialized) {
        Logger::Error("ARP scanner not initialized");
        return {};
    }
    
    Logger::Status("Starting ARP network scan...");
    
    std::vector<DiscoveredDevice> results;
    
    // Get interface information
    uint8_t src_mac[6];
    uint32_t src_ip;
    if (!getInterfaceInfo(src_mac, &src_ip)) {
        Logger::Error("Failed to get interface information");
        return results;
    }
    
    char src_ip_str[INET_ADDRSTRLEN];
    struct in_addr addr;
    addr.s_addr = src_ip;
    inet_ntop(AF_INET, &addr, src_ip_str, sizeof(src_ip_str));
    
    Logger::Info("Source MAC: " + 
                std::string([&]() {
                    static char mac_str[18];
                    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                            src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
                    return mac_str;
                }()));
    Logger::Info("Source IP: " + std::string(src_ip_str));
    
    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        Logger::Error("Socket creation failed - " + std::string(strerror(errno)));
        return results;
    }
    
    // Set up pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        Logger::Error("Failed to create pcap handle: " + std::string(errbuf));
        close(sock);
        return results;
    }
    
    // Apply ARP filter
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "arp", 0, PCAP_NETMASK_UNKNOWN) != 0) {
        Logger::Error("Failed to compile ARP filter");
        pcap_close(handle);
        close(sock);
        return results;
    }
    
    if (pcap_setfilter(handle, &filter) != 0) {
        Logger::Error("Failed to apply ARP filter");
        pcap_freecode(&filter);
        pcap_close(handle);
        close(sock);
        return results;
    }
    
    Logger::Debug("ARP packet filter applied successfully");
    
    // Send ARP requests
    Logger::Status("Scanning your network...");
    if (!sendARPRequests(sock, src_mac, src_ip)) {
        Logger::Error("Failed to send ARP requests");
        pcap_freecode(&filter);
        pcap_close(handle);
        close(sock);
        return results;
    }
    
    // Listen for replies
    Logger::Status("Listening for replies for " + std::to_string(timeout_seconds) + " seconds...");
    ScanContext context(this, &results);
    
    time_t start_time = time(nullptr);
    while (time(nullptr) - start_time < timeout_seconds) {
        int result = pcap_dispatch(handle, 10, packetHandler, reinterpret_cast<u_char*>(&context));
        if (result > 0) {
            Logger::Debug("Processed " + std::to_string(result) + " packets");
        }
        usleep(100000); // 100ms
    }
    
    // Cleanup
    pcap_freecode(&filter);
    pcap_close(handle);
    close(sock);
    
    last_scan_results = results;
    Logger::Status("Scan complete. Found " + std::to_string(results.size()) + " devices.");
    
    return results;
}

void ARPScanner::performScanWithCallback(DeviceDiscoveryCallback callback, int timeout_seconds) {
    if (!initialized) {
        Logger::Error("ARP scanner not initialized");
        return;
    }
    
    Logger::Status("Starting ARP network scan with callback...");
    
    // Get interface information
    uint8_t src_mac[6];
    uint32_t src_ip;
    if (!getInterfaceInfo(src_mac, &src_ip)) {
        Logger::Error("Failed to get interface information");
        return;
    }
    
    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        Logger::Error("Socket creation failed - " + std::string(strerror(errno)));
        return;
    }
    
    // Set up pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), 65536, 1, 1000, errbuf);
    if (!handle) {
        Logger::Error("Failed to create pcap handle: " + std::string(errbuf));
        close(sock);
        return;
    }
    
    // Apply ARP filter
    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "arp", 0, PCAP_NETMASK_UNKNOWN) != 0 ||
        pcap_setfilter(handle, &filter) != 0) {
        Logger::Error("Failed to apply ARP filter");
        pcap_freecode(&filter);
        pcap_close(handle);
        close(sock);
        return;
    }
    
    // Send ARP requests
    sendARPRequests(sock, src_mac, src_ip);
    
    // Listen for replies with callback
    ScanContext context(this, callback);
    
    Logger::Debug("Starting packet capture for " + std::to_string(timeout_seconds) + " seconds...");
    time_t start_time = time(nullptr);
    int total_packets_processed = 0;
    
    while (time(nullptr) - start_time < timeout_seconds) {
        int result = pcap_dispatch(handle, 10, packetHandler, reinterpret_cast<u_char*>(&context));
        if (result > 0) {
            total_packets_processed += result;
            Logger::Debug("Processed " + std::to_string(result) + " packets (total: " + std::to_string(total_packets_processed) + ")");
        }
        usleep(100000); // 100ms
    }
    
    Logger::Debug("Packet capture completed. Total packets processed: " + std::to_string(total_packets_processed));
    
    // Cleanup
    pcap_freecode(&filter);
    pcap_close(handle);
    close(sock);
}

const std::vector<DiscoveredDevice>& ARPScanner::getLastScanResults() const {
    return last_scan_results;
}

bool ARPScanner::isReady() const {
    return initialized;
}
