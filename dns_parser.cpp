#include "dns_parser.h"
#include "log_writer.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>

// Parse DNS packet from raw data
bool DNSParser::parseDNSPacket(const uint8_t* packet_data, size_t packet_len, DNSPacket& dns_packet) {
    if (!packet_data || packet_len < sizeof(DNSHeader)) {
        Logger::Error("Invalid DNS packet: too small");
        return false;
    }

    // Clear the packet structure
    dns_packet.questions.clear();
    dns_packet.answers.clear();
    dns_packet.authority.clear();
    dns_packet.additional.clear();

    int offset = 0;

    // Parse DNS header
    if (!parseHeader(packet_data + offset, dns_packet.header)) {
        Logger::Error("Failed to parse DNS header");
        return false;
    }
    offset += sizeof(DNSHeader);

    // Determine if this is a query or response
    dns_packet.is_query = !(dns_packet.header.flags & 0x8000);
    dns_packet.is_response = (dns_packet.header.flags & 0x8000);

    Logger::Debug("Parsing DNS packet: " + std::to_string(ntohs(dns_packet.header.qd_count)) + 
                  " questions, " + std::to_string(ntohs(dns_packet.header.an_count)) + " answers");

    // Parse questions
    for (int i = 0; i < ntohs(dns_packet.header.qd_count); i++) {
        DNSQuestion question;
        int new_offset = parseQuestion(packet_data, packet_len, offset, question);
        if (new_offset == -1) {
            Logger::Error("Failed to parse DNS question " + std::to_string(i));
            return false;
        }
        dns_packet.questions.push_back(question);
        offset = new_offset;
    }

    // Parse answers
    for (int i = 0; i < ntohs(dns_packet.header.an_count); i++) {
        DNSRecord record;
        int new_offset = parseRecord(packet_data, packet_len, offset, record);
        if (new_offset == -1) {
            Logger::Error("Failed to parse DNS answer " + std::to_string(i));
            return false;
        }
        dns_packet.answers.push_back(record);
        offset = new_offset;
    }

    // Parse authority records
    for (int i = 0; i < ntohs(dns_packet.header.ns_count); i++) {
        DNSRecord record;
        int new_offset = parseRecord(packet_data, packet_len, offset, record);
        if (new_offset == -1) {
            Logger::Error("Failed to parse DNS authority record " + std::to_string(i));
            return false;
        }
        dns_packet.authority.push_back(record);
        offset = new_offset;
    }

    // Parse additional records
    for (int i = 0; i < ntohs(dns_packet.header.ar_count); i++) {
        DNSRecord record;
        int new_offset = parseRecord(packet_data, packet_len, offset, record);
        if (new_offset == -1) {
            Logger::Error("Failed to parse DNS additional record " + std::to_string(i));
            return false;
        }
        dns_packet.additional.push_back(record);
        offset = new_offset;
    }

    return true;
}

// Parse DNS header
bool DNSParser::parseHeader(const uint8_t* data, DNSHeader& header) {
    if (!data) return false;

    header.id = readUint16(data);
    header.flags = readUint16(data + 2);
    header.qd_count = readUint16(data + 4);
    header.an_count = readUint16(data + 6);
    header.ns_count = readUint16(data + 8);
    header.ar_count = readUint16(data + 10);

    return true;
}

// Parse DNS question
int DNSParser::parseQuestion(const uint8_t* data, size_t data_len, int offset, DNSQuestion& question) {
    if (!data || offset >= (int)data_len) return -1;

    // Parse domain name
    int name_end = parseDomainName(data, data_len, offset, question.name);
    if (name_end == -1) return -1;

    // Check if we have enough data for qtype and qclass
    if (name_end + 4 > (int)data_len) return -1;

    question.qtype = readUint16(data + name_end);
    question.qclass = readUint16(data + name_end + 2);

    return name_end + 4;
}

// Parse DNS resource record
int DNSParser::parseRecord(const uint8_t* data, size_t data_len, int offset, DNSRecord& record) {
    if (!data || offset >= (int)data_len) return -1;

    // Parse domain name
    int name_end = parseDomainName(data, data_len, offset, record.name);
    if (name_end == -1) return -1;

    // Check if we have enough data for the fixed fields
    if (name_end + 10 > (int)data_len) return -1;

    record.type = readUint16(data + name_end);
    record.rclass = readUint16(data + name_end + 2);
    record.ttl = readUint32(data + name_end + 4);
    record.rdlength = readUint16(data + name_end + 8);

    int rdata_start = name_end + 10;

    // Check if we have enough data for the resource data
    if (rdata_start + ntohs(record.rdlength) > (int)data_len) return -1;

    // Extract resource data based on type
    uint16_t type = ntohs(record.type);
    uint16_t rdlength = ntohs(record.rdlength);

    if (type == DNS_TYPE_A && rdlength == 4) {
        // IPv4 address
        record.rdata = formatIPv4(std::string((char*)(data + rdata_start), rdlength));
    } else if (type == DNS_TYPE_AAAA && rdlength == 16) {
        // IPv6 address
        record.rdata = formatIPv6(std::string((char*)(data + rdata_start), rdlength));
    } else if (type == DNS_TYPE_CNAME || type == DNS_TYPE_NS || type == DNS_TYPE_PTR) {
        // Domain name
        std::string domain_name;
        if (parseDomainName(data, data_len, rdata_start, domain_name) != -1) {
            record.rdata = domain_name;
        } else {
            record.rdata = "Invalid domain name";
        }
    } else if (type == DNS_TYPE_TXT) {
        // Text record - first byte is length
        if (rdlength > 0) {
            uint8_t txt_len = data[rdata_start];
            if (txt_len < rdlength) {
                record.rdata = std::string((char*)(data + rdata_start + 1), txt_len);
            } else {
                record.rdata = std::string((char*)(data + rdata_start + 1), rdlength - 1);
            }
        }
    } else {
        // Generic binary data
        std::stringstream ss;
        for (int i = 0; i < rdlength; i++) {
            ss << std::hex << std::setfill('0') << std::setw(2) << (int)data[rdata_start + i];
        }
        record.rdata = ss.str();
    }

    return rdata_start + rdlength;
}

// Parse domain name with compression support
int DNSParser::parseDomainName(const uint8_t* data, size_t data_len, int offset, std::string& name) {
    if (!data || offset >= (int)data_len) return -1;

    name.clear();
    int current_offset = offset;
    bool jumped = false;
    int jumps = 0;
    const int MAX_JUMPS = 10; // Prevent infinite loops

    while (current_offset < (int)data_len && jumps < MAX_JUMPS) {
        uint8_t length = data[current_offset];

        if (length == 0) {
            // End of domain name
            current_offset++;
            break;
        } else if ((length & 0xC0) == 0xC0) {
            // Compression pointer
            if (current_offset + 1 >= (int)data_len) return -1;
            
            if (!jumped) {
                offset = current_offset + 2; // Save the position after the pointer
            }
            
            // Calculate the jump target
            int jump_target = ((length & 0x3F) << 8) | data[current_offset + 1];
            if (jump_target >= (int)data_len) return -1;
            
            current_offset = jump_target;
            jumped = true;
            jumps++;
        } else {
            // Regular label
            if (length > 63) return -1; // Invalid label length
            if (current_offset + 1 + length > (int)data_len) return -1;

            if (!name.empty()) {
                name += ".";
            }
            
            name += std::string((char*)(data + current_offset + 1), length);
            current_offset += 1 + length;
        }
    }

    if (jumps >= MAX_JUMPS) {
        Logger::Warning("Too many compression jumps in DNS name");
        return -1;
    }

    return jumped ? offset : current_offset;
}

// Extract DNS from IP packet
bool DNSParser::extractDNSFromIP(const uint8_t* ip_packet, size_t packet_len, DNSPacket& dns_packet) {
    if (!ip_packet || packet_len < sizeof(struct iphdr) + sizeof(struct udphdr)) {
        return false;
    }

    struct iphdr* ip_hdr = (struct iphdr*)ip_packet;
    
    // Check if it's UDP
    if (ip_hdr->protocol != IPPROTO_UDP) {
        return false;
    }

    size_t ip_header_len = ip_hdr->ihl * 4;
    if (packet_len < ip_header_len + sizeof(struct udphdr)) {
        return false;
    }

    struct udphdr* udp_hdr = (struct udphdr*)(ip_packet + ip_header_len);
    
    // Check if it's DNS (port 53)
    if (ntohs(udp_hdr->source) != 53 && ntohs(udp_hdr->dest) != 53) {
        return false;
    }

    // Extract IP addresses
    struct in_addr src_addr, dest_addr;
    src_addr.s_addr = ip_hdr->saddr;
    dest_addr.s_addr = ip_hdr->daddr;
    
    dns_packet.source_ip = inet_ntoa(src_addr);
    dns_packet.dest_ip = inet_ntoa(dest_addr);
    dns_packet.source_port = ntohs(udp_hdr->source);
    dns_packet.dest_port = ntohs(udp_hdr->dest);

    // Extract DNS data
    size_t udp_header_len = sizeof(struct udphdr);
    size_t dns_data_offset = ip_header_len + udp_header_len;
    
    if (packet_len <= dns_data_offset) {
        return false;
    }

    size_t dns_data_len = packet_len - dns_data_offset;
    const uint8_t* dns_data = ip_packet + dns_data_offset;

    return parseDNSPacket(dns_data, dns_data_len, dns_packet);
}

// Utility functions
std::string DNSParser::getRecordTypeString(uint16_t type) {
    switch (type) {
        case DNS_TYPE_A: return "A";
        case DNS_TYPE_NS: return "NS";
        case DNS_TYPE_CNAME: return "CNAME";
        case DNS_TYPE_SOA: return "SOA";
        case DNS_TYPE_PTR: return "PTR";
        case DNS_TYPE_MX: return "MX";
        case DNS_TYPE_TXT: return "TXT";
        case DNS_TYPE_AAAA: return "AAAA";
        case DNS_TYPE_SRV: return "SRV";
        case DNS_TYPE_ANY: return "ANY";
        default: return "Unknown(" + std::to_string(type) + ")";
    }
}

std::string DNSParser::getResponseCodeString(uint8_t rcode) {
    switch (rcode) {
        case DNS_RCODE_NOERROR: return "No Error";
        case DNS_RCODE_FORMERR: return "Format Error";
        case DNS_RCODE_SERVFAIL: return "Server Failure";
        case DNS_RCODE_NXDOMAIN: return "Non-existent Domain";
        case DNS_RCODE_NOTIMP: return "Not Implemented";
        case DNS_RCODE_REFUSED: return "Query Refused";
        default: return "Unknown(" + std::to_string(rcode) + ")";
    }
}

std::string DNSParser::formatIPv4(const std::string& data) {
    if (data.length() != 4) return "Invalid IPv4";
    
    const uint8_t* bytes = (const uint8_t*)data.data();
    return std::to_string(bytes[0]) + "." + 
           std::to_string(bytes[1]) + "." + 
           std::to_string(bytes[2]) + "." + 
           std::to_string(bytes[3]);
}

std::string DNSParser::formatIPv6(const std::string& data) {
    if (data.length() != 16) return "Invalid IPv6";
    
    const uint16_t* words = (const uint16_t*)data.data();
    std::stringstream ss;
    
    for (int i = 0; i < 8; i++) {
        if (i > 0) ss << ":";
        ss << std::hex << ntohs(words[i]);
    }
    
    return ss.str();
}

// Display functions
void DNSParser::printDNSPacket(const DNSPacket& packet) {
    Logger::Status("=== DNS Packet Analysis ===");
    
    if (!packet.source_ip.empty()) {
        Logger::Info("Source: " + packet.source_ip + ":" + std::to_string(packet.source_port));
        Logger::Info("Destination: " + packet.dest_ip + ":" + std::to_string(packet.dest_port));
    }
    
    Logger::Info("Type: " + std::string(packet.is_query ? "Query" : "Response"));
    
    printDNSHeader(packet.header);
    
    // Print questions
    if (!packet.questions.empty()) {
        Logger::Info("=== Questions ===");
        for (size_t i = 0; i < packet.questions.size(); i++) {
            Logger::Info("Question " + std::to_string(i + 1) + ":");
            printDNSQuestion(packet.questions[i]);
        }
    }
    
    // Print answers
    if (!packet.answers.empty()) {
        Logger::Info("=== Answers ===");
        for (size_t i = 0; i < packet.answers.size(); i++) {
            Logger::Info("Answer " + std::to_string(i + 1) + ":");
            printDNSRecord(packet.answers[i]);
        }
    }
    
    // Print authority records
    if (!packet.authority.empty()) {
        Logger::Info("=== Authority Records ===");
        for (size_t i = 0; i < packet.authority.size(); i++) {
            Logger::Info("Authority " + std::to_string(i + 1) + ":");
            printDNSRecord(packet.authority[i]);
        }
    }
    
    // Print additional records
    if (!packet.additional.empty()) {
        Logger::Info("=== Additional Records ===");
        for (size_t i = 0; i < packet.additional.size(); i++) {
            Logger::Info("Additional " + std::to_string(i + 1) + ":");
            printDNSRecord(packet.additional[i]);
        }
    }
    
    Logger::Status("=== End DNS Packet ===");
}

void DNSParser::printDNSHeader(const DNSHeader& header) {
    uint16_t flags = ntohs(header.flags);
    uint8_t rcode = flags & 0x0F;
    
    Logger::Info("Header:");
    Logger::Info("  Transaction ID: 0x" + 
                std::to_string(ntohs(header.id)));
    Logger::Info("  Flags: 0x" + 
                std::to_string(flags));
    Logger::Info("  Response Code: " + getResponseCodeString(rcode));
    Logger::Info("  Questions: " + std::to_string(ntohs(header.qd_count)));
    Logger::Info("  Answers: " + std::to_string(ntohs(header.an_count)));
    Logger::Info("  Authority: " + std::to_string(ntohs(header.ns_count)));
    Logger::Info("  Additional: " + std::to_string(ntohs(header.ar_count)));
}

void DNSParser::printDNSQuestion(const DNSQuestion& question) {
    Logger::Info("  Domain: " + question.name);
    Logger::Info("  Type: " + getRecordTypeString(ntohs(question.qtype)));
    Logger::Info("  Class: " + std::to_string(ntohs(question.qclass)));
}

void DNSParser::printDNSRecord(const DNSRecord& record) {
    Logger::Info("  Domain: " + record.name);
    Logger::Info("  Type: " + getRecordTypeString(ntohs(record.type)));
    Logger::Info("  Class: " + std::to_string(ntohs(record.rclass)));
    Logger::Info("  TTL: " + std::to_string(ntohl(record.ttl)));
    Logger::Info("  Data: " + record.rdata);
}

// Helper functions
uint16_t DNSParser::readUint16(const uint8_t* data) {
    return (data[0] << 8) | data[1];
}

uint32_t DNSParser::readUint32(const uint8_t* data) {
    return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

bool DNSParser::isValidDNSPacket(const uint8_t* data, size_t len) {
    if (!data || len < sizeof(DNSHeader)) {
        return false;
    }
    
    // Basic validation - check if the packet structure makes sense
    DNSHeader header;
    parseHeader(data, header);
    
    // Reasonable limits
    if (ntohs(header.qd_count) > 100 || 
        ntohs(header.an_count) > 100 ||
        ntohs(header.ns_count) > 100 ||
        ntohs(header.ar_count) > 100) {
        return false;
    }
    
    return true;
}
