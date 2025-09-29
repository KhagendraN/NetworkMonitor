#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

// DNS Header structure (based on RFC 1035)
struct DNSHeader {
    uint16_t id;        // Identification number
    uint16_t flags;     // DNS flags
    uint16_t qd_count;  // Number of questions
    uint16_t an_count;  // Number of answers
    uint16_t ns_count;  // Number of authority records
    uint16_t ar_count;  // Number of additional records
};

// DNS Question structure
struct DNSQuestion {
    std::string name;   // Domain name
    uint16_t qtype;     // Query type
    uint16_t qclass;    // Query class
};

// DNS Resource Record structure
struct DNSRecord {
    std::string name;   // Domain name
    uint16_t type;      // Record type
    uint16_t rclass;    // Record class
    uint32_t ttl;       // Time to live
    uint16_t rdlength;  // Resource data length
    std::string rdata;  // Resource data
};

// DNS Packet structure
struct DNSPacket {
    DNSHeader header;
    std::vector<DNSQuestion> questions;
    std::vector<DNSRecord> answers;
    std::vector<DNSRecord> authority;
    std::vector<DNSRecord> additional;
    
    // Metadata
    std::string source_ip;
    std::string dest_ip;
    uint16_t source_port;
    uint16_t dest_port;
    bool is_query;
    bool is_response;
};

// DNS Record Types (common ones)
enum DNSType {
    DNS_TYPE_A      = 1,    // IPv4 Address
    DNS_TYPE_NS     = 2,    // Name Server
    DNS_TYPE_CNAME  = 5,    // Canonical Name
    DNS_TYPE_SOA    = 6,    // Start of Authority
    DNS_TYPE_PTR    = 12,   // Pointer
    DNS_TYPE_MX     = 15,   // Mail Exchange
    DNS_TYPE_TXT    = 16,   // Text
    DNS_TYPE_AAAA   = 28,   // IPv6 Address
    DNS_TYPE_SRV    = 33,   // Service
    DNS_TYPE_ANY    = 255   // Any record type
};

// DNS Response Codes
enum DNSResponseCode {
    DNS_RCODE_NOERROR   = 0,    // No error
    DNS_RCODE_FORMERR   = 1,    // Format error
    DNS_RCODE_SERVFAIL  = 2,    // Server failure
    DNS_RCODE_NXDOMAIN  = 3,    // Non-existent domain
    DNS_RCODE_NOTIMP    = 4,    // Not implemented
    DNS_RCODE_REFUSED   = 5     // Query refused
};

class DNSParser {
public:
    // Parse DNS packet from raw data
    static bool parseDNSPacket(const uint8_t* packet_data, size_t packet_len, DNSPacket& dns_packet);
    
    // Parse specific DNS components
    static bool parseHeader(const uint8_t* data, DNSHeader& header);
    static int parseQuestion(const uint8_t* data, size_t data_len, int offset, DNSQuestion& question);
    static int parseRecord(const uint8_t* data, size_t data_len, int offset, DNSRecord& record);
    
    // Utility functions
    static int parseDomainName(const uint8_t* data, size_t data_len, int offset, std::string& name);
    static std::string getRecordTypeString(uint16_t type);
    static std::string getResponseCodeString(uint8_t rcode);
    static std::string formatIPv4(const std::string& data);
    static std::string formatIPv6(const std::string& data);
    
    // Extract DNS from IP packet
    static bool extractDNSFromIP(const uint8_t* ip_packet, size_t packet_len, DNSPacket& dns_packet);
    
    // Display functions
    static void printDNSPacket(const DNSPacket& packet);
    static void printDNSHeader(const DNSHeader& header);
    static void printDNSQuestion(const DNSQuestion& question);
    static void printDNSRecord(const DNSRecord& record);
    
private:
    // Helper functions
    static uint16_t readUint16(const uint8_t* data);
    static uint32_t readUint32(const uint8_t* data);
    static bool isValidDNSPacket(const uint8_t* data, size_t len);
};
