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

// Simple ARP packet structure
struct arp_packet {
    struct ether_header eth_hdr;
    struct ether_arp arp_hdr;
};

// Get MAC address of interface
bool get_mac_address(const char* iface, uint8_t* mac) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, iface);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFHWADDR");
        close(fd);
        return false;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return true;
}

// Get IP address of interface
bool get_ip_address(const char* iface, in_addr* ip) {
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, iface);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        perror("ioctl SIOCGIFADDR");
        close(fd);
        return false;
    }
    *ip = ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr;
    close(fd);
    return true;
}

void packet_handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ether_header* eth = (struct ether_header*)packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_ARP) return;

    struct ether_arp* arp = (struct ether_arp*)(packet + sizeof(struct ether_header));
    if (ntohs(arp->ea_hdr.ar_op) != ARPOP_REPLY) return;

    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, arp->arp_spa, ip, sizeof(ip));

    printf("*** ARP REPLY RECEIVED ***\n");
    printf("IP: %s\n", ip);
    printf("MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
           arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
           arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
    printf("**************************\n");
    
    // Increment counter
    (*(int*)args)++;
}

int main() {
    const char* iface = "wlan0";
    const char* target_ip_str = "192.168.254.1";  // Gateway

    uint8_t src_mac[6];
    in_addr src_ip;
    
    if (!get_mac_address(iface, src_mac)) {
        std::cerr << "Failed to get MAC address\n";
        return 1;
    }
    
    if (!get_ip_address(iface, &src_ip)) {
        std::cerr << "Failed to get IP address\n";
        return 1;
    }

    printf("Source MAC: %02X:%02X:%02X:%02X:%02X:%02X\n", 
           src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("Source IP: %s\n", inet_ntoa(src_ip));
    printf("Target IP: %s\n", target_ip_str);

    // Parse target IP
    in_addr target_ip;
    if (inet_pton(AF_INET, target_ip_str, &target_ip) <= 0) {
        std::cerr << "Invalid target IP\n";
        return 1;
    }

    // Open pcap first
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "arp", 0, PCAP_NETMASK_UNKNOWN) < 0) {
        std::cerr << "pcap_compile failed\n";
        return 1;
    }
    pcap_setfilter(handle, &fp);

    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    // Create ARP packet
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

    // Socket address
    struct sockaddr_ll sa = {};
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(iface);
    sa.sll_halen = 6;
    memset(sa.sll_addr, 0xff, 6);

    printf("Sending ARP request to %s...\n", target_ip_str);
    
    // Send packet
    if (sendto(sock, &packet, sizeof(packet), 0, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        return 1;
    }
    
    printf("ARP request sent successfully!\n");
    printf("Waiting for reply for 3 seconds...\n");

    int replies = 0;
    int result = pcap_dispatch(handle, -1, packet_handler, (u_char*)&replies);
    
    if (result < 0) {
        std::cerr << "pcap_dispatch failed: " << pcap_geterr(handle) << std::endl;
    }
    
    printf("Received %d ARP replies\n", replies);
    
    pcap_close(handle);
    close(sock);
    return 0;
}
