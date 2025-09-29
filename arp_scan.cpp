#include <iostream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>         
#include <arpa/inet.h>
#include <cstring>
#include <pcap.h>
#include <map>
#include <string>
#include <netdb.h>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>
#include <signal.h>
#include <chrono>
#include <thread>
#include "log_writer.h"


// ARP packet structure
struct arp_packet {
    struct ether_header eth_hdr;
    struct ether_arp arp_hdr;
};

// MAC prefix vendor map (loaded from OUI.csv)
std::map<std::string, std::string> mac_vendor_map;

// Global flag for stopping the scan
volatile bool scan_complete = false;

// Load OUI data from CSV file
void load_oui_data() {
    std::ifstream file("oui.csv");
    if (!file.is_open()) {
        Logger::Warning("Could not open oui.csv file. Using built-in vendor data.");
        // Fallback to hardcoded data
        mac_vendor_map["F81A67"] = "Xiaomi";
        mac_vendor_map["842E27"] = "Itel";
        mac_vendor_map["405BD8"] = "Apple";
        mac_vendor_map["B827EB"] = "Raspberry Pi";
        mac_vendor_map["001E45"] = "Dell";
        mac_vendor_map["3C5AB4"] = "HP";
        mac_vendor_map["FCC2DE"] = "Samsung";
        mac_vendor_map["000C29"] = "VMware";
        mac_vendor_map["186590"] = "Lenovo";
        mac_vendor_map["F099BF"] = "Huawei";
        return;
    }
    
    std::string line;
    std::getline(file, line); // Skip header
    
    int loaded = 0;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string registry, assignment, organization, address;
        
        if (std::getline(ss, registry, ',') && 
            std::getline(ss, assignment, ',') && 
            std::getline(ss, organization, ',')) {
            
            // Remove quotes from assignment and organization
            assignment.erase(std::remove(assignment.begin(), assignment.end(), '"'), assignment.end());
            organization.erase(std::remove(organization.begin(), organization.end(), '"'), organization.end());
            
            // Convert to uppercase for consistent lookup
            std::transform(assignment.begin(), assignment.end(), assignment.begin(), ::toupper);
            
            if (assignment.length() == 6) {
                mac_vendor_map[assignment] = organization;
                loaded++;
            }
        }
    }
    Logger::Info("Loaded " + std::to_string(loaded) + " MAC vendor entries from oui.csv");
}

// Get MAC address of interface
bool get_mac_address(const char* iface, uint8_t* mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, iface);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) return false;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return true;
}

// Get IP address of interface
bool get_ip_address(const char* iface, in_addr* ip) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, iface);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) return false;
    *ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
    close(fd);
    return true;
}

// Build and send an ARP request
bool send_arp_request(int sock, const char* iface, uint8_t* src_mac, in_addr src_ip, in_addr target_ip) {
    struct arp_packet packet;
    memset(&packet, 0, sizeof(packet));

    // Ethernet header
    memset(packet.eth_hdr.ether_dhost, 0xff, 6);  // Broadcast
    memcpy(packet.eth_hdr.ether_shost, src_mac, 6);
    packet.eth_hdr.ether_type = htons(ETHERTYPE_ARP);

    // ARP header
    packet.arp_hdr.arp_hrd = htons(ARPHRD_ETHER);
    packet.arp_hdr.arp_pro = htons(ETHERTYPE_IP);
    packet.arp_hdr.arp_hln = 6;
    packet.arp_hdr.arp_pln = 4;
    packet.arp_hdr.arp_op  = htons(ARPOP_REQUEST);
    memcpy(packet.arp_hdr.arp_sha, src_mac, 6);
    memcpy(packet.arp_hdr.arp_spa, &src_ip.s_addr, 4);
    memset(packet.arp_hdr.arp_tha, 0x00, 6);
    memcpy(packet.arp_hdr.arp_tpa, &target_ip.s_addr, 4);

    struct sockaddr_ll sa = {};
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(iface);
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xff, 6);

    ssize_t sent = sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa));
    return sent > 0;
}

// Convert MAC to vendor
std::string lookup_vendor(const uint8_t* mac) {
    char prefix[7];
    snprintf(prefix, sizeof(prefix), "%02X%02X%02X", mac[0], mac[1], mac[2]);

    auto it = mac_vendor_map.find(prefix);
    if (it != mac_vendor_map.end()) return it->second;
    return "Unknown";
}

// Print ARP reply
void packet_handler([[maybe_unused]] u_char* args, [[maybe_unused]] const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;

    struct ether_arp* arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) return;

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->arp_spa, ip, sizeof(ip));

    char hostname[NI_MAXHOST] = "Unknown";
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    memcpy(&sa.sin_addr, arp->arp_spa, 4);

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), hostname, sizeof(hostname), nullptr, 0, 0) != 0) {
        strcpy(hostname, "Unknown");
    }

    std::string vendor = lookup_vendor(arp->arp_sha);

    // Create device info string
    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
             arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
             
    std::string device_info = "Device discovered - IP: " + std::string(ip) + 
                              ", MAC: " + std::string(mac_str);

    Logger::Status(device_info);
    
    // Detailed device information with formatting
    printf("Device found:\n");
    printf("  IP       : %s\n", ip);
    printf("  MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
           arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
    printf("  Hostname : %s\n", hostname);
    printf("  Vendor   : %s\n", vendor.c_str());
    printf("--------------------------------------\n");
    
    // Log device details
    std::string device_details = "Hostname: " + std::string(hostname) + ", Vendor: " + vendor;
    Logger::Info(device_details);
    
    // Increment counter for found devices
    (*(int*)args)++;
}

int main() {
    // Initialize logger
    Logger::Init(LogLevel::DEBUG);
    Logger::Status("NetworkMonitor ARP Scanner Starting...");
    
    const char* iface = "wlan0"; // You can change this to your interface name

    Logger::Info("Loading MAC vendor database...");
    load_oui_data();

    // Get source MAC & IP
    uint8_t src_mac[6];
    in_addr src_ip;
    if (!get_mac_address(iface, src_mac) || !get_ip_address(iface, &src_ip)) {
        Logger::Error("Failed to get MAC or IP of interface " + std::string(iface));
        Logger::Error("Make sure the interface exists and you have proper permissions.");
        return 1;
    }

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X", 
             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    
    Logger::Info("Using interface: " + std::string(iface));
    Logger::Info("Source MAC: " + std::string(mac_str));
    Logger::Info("Source IP: " + std::string(inet_ntoa(src_ip)));

    // Open raw socket for sending ARP
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        Logger::Error("Socket creation failed - " + std::string(strerror(errno)));
        Logger::Error("Make sure you're running as root or with CAP_NET_RAW capability.");
        return 1;
    }
    Logger::Debug("Raw socket created successfully");

    // Start pcap for listening
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, BUFSIZ, 0, 100, errbuf);  // Reduced timeout to 100ms
    if (!handle) {
        Logger::Error("pcap_open_live failed: " + std::string(errbuf));
        close(sock);
        return 1;
    }
    Logger::Debug("pcap handle created successfully");

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) < 0) {
        Logger::Error("pcap_compile failed: " + std::string(pcap_geterr(handle)));
        pcap_close(handle);
        close(sock);
        return 1;
    }
    
    if (pcap_setfilter(handle, &fp) < 0) {
        Logger::Error("pcap_setfilter failed: " + std::string(pcap_geterr(handle)));
        pcap_freecode(&fp);
        pcap_close(handle);
        close(sock);
        return 1;
    }
    pcap_freecode(&fp);
    Logger::Debug("ARP packet filter applied successfully");

    Logger::Status("Scanning your network...");
    
    // First, try to ping the gateway to populate ARP table
    in_addr gateway_ip = src_ip;
    ((uint8_t*)&gateway_ip.s_addr)[3] = 1;
    Logger::Info("Testing connectivity to gateway: " + std::string(inet_ntoa(gateway_ip)));
    
    if (!send_arp_request(sock, iface, src_mac, src_ip, gateway_ip)) {
        Logger::Error("Failed to send ARP request to gateway");
    } else {
        Logger::Debug("ARP request sent to gateway successfully");
        
        // Wait a bit and listen for response
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        int test_devices = 0;
        pcap_dispatch(handle, 5, packet_handler, (u_char*)&test_devices);
        
        if (test_devices > 0) {
            Logger::Info("Gateway responded! Network is working.");
        } else {
            Logger::Warning("No response from gateway. This might indicate network issues.");
        }
    }

    Logger::Status("Sending ARP requests to 254 addresses...");

    // Send ARP to all addresses in /24 subnet
    int sent_requests = 0;
    int failed_requests = 0;
    for (int i = 1; i <= 254; ++i) {
        in_addr target_ip = src_ip;
        ((uint8_t*)&target_ip.s_addr)[3] = i;
        if (send_arp_request(sock, iface, src_mac, src_ip, target_ip)) {
            sent_requests++;
        } else {
            failed_requests++;
        }
        usleep(2000);  // Smaller delay
    }
    
    Logger::Info("Sent " + std::to_string(sent_requests) + " ARP requests successfully, " + 
                 std::to_string(failed_requests) + " failed.");
    Logger::Status("Listening for replies for 3 seconds...");

    // Listen for replies with timeout
    int found_devices = 0;
    auto start_time = std::chrono::steady_clock::now();
    const auto timeout_duration = std::chrono::seconds(3);  // 3 second timeout
    
    while (std::chrono::steady_clock::now() - start_time < timeout_duration) {
        int result = pcap_dispatch(handle, 10, packet_handler, (u_char*)&found_devices);
        if (result < 0) {
            Logger::Error("pcap_dispatch failed: " + std::string(pcap_geterr(handle)));
            break;
        }
        if (result > 0) {
            Logger::Debug("Processed " + std::to_string(result) + " packets");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    if (found_devices == 0) {
        Logger::Warning("No devices found. This could mean:");
        Logger::Info("1. No other devices are on the network");
        Logger::Info("2. Firewall is blocking ARP responses");
        Logger::Info("3. Network interface issues");
        Logger::Info("4. Permission issues");
        Logger::Status("Trying to scan the gateway to verify connectivity...");
        
        // Try scanning the gateway (usually .1)
        in_addr gateway_ip = src_ip;
        ((uint8_t*)&gateway_ip.s_addr)[3] = 1;
        send_arp_request(sock, iface, src_mac, src_ip, gateway_ip);
        
        Logger::Info("Sent ARP request to gateway: " + std::string(inet_ntoa(gateway_ip)));
        std::this_thread::sleep_for(std::chrono::seconds(1));
        pcap_dispatch(handle, 1, packet_handler, (u_char*)&found_devices);
        
        if (found_devices == 0) {
            Logger::Error("No response from gateway either. Check your network configuration.");
        }
    } else {
        Logger::Status("Scan complete. Found " + std::to_string(found_devices) + " devices.");
    }

    pcap_close(handle);
    close(sock);
    Logger::Status("NetworkMonitor ARP Scanner finished.");
    return 0;
}
