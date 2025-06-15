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


// ARP packet structure
struct arp_packet {
    struct ether_header eth_hdr;
    struct ether_arp arp_hdr;
};

// MAC prefix vendor map
std::map<std::string, std::pair<std::string, std::string>> mac_vendor_map = {
    {"F8:1A:67", {"Xiaomi", "Phone"}},
    {"84:2E:27", {"Itel", "Phone"}},
    {"40:5B:D8", {"Apple", "Phone"}},
    {"B8:27:EB", {"Raspberry Pi", "IoT"}},
    {"00:1E:45", {"Dell", "Laptop"}},
    {"3C:5A:B4", {"HP", "Printer"}},
    {"FC:C2:DE", {"Samsung", "Phone"}},
    {"00:0C:29", {"VMware", "VM"}},
    {"18:65:90", {"Lenovo", "Laptop"}},
    {"F0:99:BF", {"Huawei", "Phone"}}
};

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
void send_arp_request(int sock, const char* iface, uint8_t* src_mac, in_addr src_ip, in_addr target_ip) {
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

    sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa));
}

// Convert MAC to vendor/type
std::pair<std::string, std::string> lookup_vendor(const uint8_t* mac) {
    char prefix[9];
    snprintf(prefix, sizeof(prefix), "%02X:%02X:%02X", mac[0], mac[1], mac[2]);

    auto it = mac_vendor_map.find(prefix);
    if (it != mac_vendor_map.end()) return it->second;
    return {"Unknown", "Unknown"};
}

// Print ARP reply
void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
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

    auto [vendor, type] = lookup_vendor(arp->arp_sha);

    printf("Device found:\n");
    printf("  IP       : %s\n", ip);
    printf("  MAC      : %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
           arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
    printf("  Hostname : %s\n", hostname);
    printf("  Vendor   : %s\n", vendor.c_str());
    printf("  Type     : %s\n", type.c_str());
    printf("--------------------------------------\n");
}

int main() {
    const char* iface = "wlan0"; // You can change this to your interface name

    // Get source MAC & IP
    uint8_t src_mac[6];
    in_addr src_ip;
    if (!get_mac_address(iface, src_mac) || !get_ip_address(iface, &src_ip)) {
        std::cerr << "Failed to get MAC or IP of interface.\n";
        return 1;
    }

    // Open raw socket for sending ARP
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Start pcap for listening
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, BUFSIZ, 0, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    struct bpf_program fp;
    pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fp);

    std::cout << "Scanning your network... Please wait.\n";

    // Send ARP to all addresses in /24 subnet
    for (int i = 1; i <= 254; ++i) {
        in_addr target_ip = src_ip;
        ((uint8_t*)&target_ip.s_addr)[3] = i;
        send_arp_request(sock, iface, src_mac, src_ip, target_ip);
        usleep(5000);  // Small delay to avoid flooding
    }

    // Listen for replies (up to 50 responses or timeout)
    pcap_loop(handle, 50, packet_handler, nullptr);

    pcap_close(handle);
    close(sock);
    return 0;
}
