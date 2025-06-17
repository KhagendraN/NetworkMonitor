#include <cstdint>
#include <iostream>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <cstring>
#include <pcap.h>
#include <string>
#include <map>
#include <netdb.h>

// ARP packet structure 
class arp_packet{
public:
    class ether_header{
        // here is the content 
    };

    class ether_arp{
        // here is the content of this class 
    };
};

// call function from maclookup

class network{
    char* iface;
    uint8_t* mac;
    in_addr* ip;

public:
    // constructor to initialize value of its attributes
    network(char* iface, uint8_t* mac, in_addr* ip){
        this->iface = iface ;
        this->mac = mac;
        this->ip = ip;
    }

    // member functions 
    // function ->1 to get MAC address of interface 
    bool get_mac_address(const char* iface , uint8_t* mac){
        // logic to het mac address 
    }

};