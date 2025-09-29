#include "network_tracker.h"
#include "dns_parser.h"
#include "log_writer.h"
#include "arp_scanner.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <thread>
#include <algorithm>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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
#include <map>
#include <cstring>
#include <ctime>

// Global pointer for packet handler callback
NetworkTracker* g_network_tracker = nullptr;

NetworkTracker::NetworkTracker(const std::string& iface) 
    : interface(iface), monitoring_active(false), device_timeout(std::chrono::minutes(10)) {
    Logger::Init(LogLevel::INFO);
    Logger::Status("NetworkTracker initialized on interface: " + interface);
    g_network_tracker = this;
    
    // Initialize ARP scanner
    arp_scanner = std::make_unique<ARPScanner>(interface);
    if (!arp_scanner->initialize()) {
        Logger::Error("Failed to initialize ARP scanner");
        arp_scanner.reset();
    } else {
        // Load OUI database
        if (!arp_scanner->loadOUIDatabase("oui.csv")) {
            Logger::Warning("Could not load OUI database - vendor lookup will be limited");
        }
    }
}

NetworkTracker::~NetworkTracker() {
    stopMonitoring();
}

void NetworkTracker::addOrUpdateDevice(const std::string& ip, const std::string& mac, 
                                      const std::string& vendor, const std::string& hostname) {
    auto now = std::chrono::system_clock::now();
    
    // Check if device exists by IP
    auto ip_it = devices_by_ip.find(ip);
    if (ip_it != devices_by_ip.end()) {
        // Update existing device
        ip_it->second.last_seen = now;
        ip_it->second.is_active = true;
        if (!mac.empty() && ip_it->second.mac != mac) {
            ip_it->second.mac = mac;
        }
        if (!vendor.empty()) {
            ip_it->second.vendor = vendor;
        }
        if (!hostname.empty()) {
            ip_it->second.hostname = hostname;
        }
    } else {
        // Add new device
        Device new_device;
        new_device.ip = ip;
        new_device.mac = mac;
        new_device.vendor = vendor;
        new_device.hostname = hostname;
        new_device.first_seen = now;
        new_device.last_seen = now;
        
        devices_by_ip[ip] = new_device;
        if (!mac.empty()) {
            devices_by_mac[mac] = new_device;
        }
        
        Logger::Status("New device discovered: " + ip + " (" + mac + ") - " + vendor);
    }
}

void NetworkTracker::updateDeviceActivity(const std::string& ip) {
    auto it = devices_by_ip.find(ip);
    if (it != devices_by_ip.end()) {
        it->second.last_seen = std::chrono::system_clock::now();
        it->second.is_active = true;
        it->second.total_packets++;
    }
}

Device* NetworkTracker::getDeviceByIP(const std::string& ip) {
    auto it = devices_by_ip.find(ip);
    return (it != devices_by_ip.end()) ? &it->second : nullptr;
}

Device* NetworkTracker::getDeviceByMAC(const std::string& mac) {
    auto it = devices_by_mac.find(mac);
    return (it != devices_by_mac.end()) ? &it->second : nullptr;
}

void NetworkTracker::logActivity(const ActivityEvent& event) {
    activity_log.push_back(event);
    
    // Update device activity
    updateDeviceActivity(event.device_ip);
    
    // Log the activity
    std::string activity_msg = event.device_ip + " -> " + event.dst_ip + 
                              " (" + event.protocol + ")";
    if (!event.domain.empty()) {
        activity_msg += " Domain: " + event.domain;
    }
    
    Logger::Debug("Activity: " + activity_msg);
}

void NetworkTracker::logDNSQuery(const DNSQuery& query) {
    dns_queries.push_back(query);
    
    // Update device DNS query counter
    auto device = getDeviceByIP(query.device_ip);
    if (device) {
        device->dns_queries++;
        Logger::Debug("Updated device " + query.device_ip + " DNS count to " + std::to_string(device->dns_queries));
    }
    
    // Track domains per device
    device_domains[query.device_ip].insert(query.domain);
    Logger::Debug("Added domain " + query.domain + " to device " + query.device_ip);
    
    Logger::Info("DNS Query: " + query.device_ip + " queried " + query.domain);
}

bool NetworkTracker::startMonitoring() {
    Logger::Status("🚀 Starting comprehensive network monitoring...");
    
    monitoring_active = true;
    
    // Start with an initial ARP scan - run this BEFORE starting packet capture
    Logger::Status("Performing initial device discovery...");
    performARPScan();
    
    // Wait a bit before starting other monitoring to ensure ARP scan completes
    std::this_thread::sleep_for(std::chrono::seconds(2));
    
    // Start packet capture thread
    std::thread capture_thread([this]() {
        startPacketCapture();
    });
    
    // Start periodic ARP scanning thread
    std::thread arp_thread([this]() {
        schedulePeriodicARPScan(5); // Every 5 minutes
    });
    
    capture_thread.detach();
    arp_thread.detach();
    
    Logger::Status("✅ Network monitoring started successfully");
    return true;
}

void NetworkTracker::stopMonitoring() {
    monitoring_active = false;
    Logger::Status("🛑 Network monitoring stopped");
}

void NetworkTracker::performARPScan() {
    if (!arp_scanner || !arp_scanner->isReady()) {
        Logger::Error("ARP scanner not available");
        return;
    }
    
    Logger::Debug("Performing ARP scan using integrated scanner...");
    
    // Use callback approach for real-time device discovery
    auto callback = [this](const DiscoveredDevice& device) {
        this->onDeviceDiscovered(device);
    };
    
    // Increase timeout to match standalone scanner behavior
    arp_scanner->performScanWithCallback(callback, 5);  // Increased from 3 to 5 seconds
    
    Logger::Debug("ARP scan completed");
}

void NetworkTracker::onDeviceDiscovered(const DiscoveredDevice& device) {
    // Check if device already exists to avoid duplicates
    auto existing = getDeviceByIP(device.ip);
    if (existing) {
        Logger::Debug("Device " + device.ip + " already known, updating info");
        // Update existing device info
        existing->vendor = device.vendor;
        existing->hostname = device.hostname;
        existing->last_seen = std::chrono::system_clock::now();
        return;
    }
    
    Logger::Status("New device discovered: " + device.ip + " (" + device.mac + ") - " + device.vendor);
    addOrUpdateDevice(device.ip, device.mac, device.vendor, device.hostname);
}

void NetworkTracker::schedulePeriodicARPScan(int interval_minutes) {
    while (monitoring_active) {
        std::this_thread::sleep_for(std::chrono::minutes(interval_minutes));
        if (monitoring_active) {
            performARPScan();
            markInactiveDevices();
        }
    }
}

void NetworkTracker::startPacketCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    
    if (!handle) {
        Logger::Error("Failed to open interface for packet capture: " + std::string(errbuf));
        return;
    }
    
    Logger::Info("Packet capture started on interface: " + interface);
    
    // Capture all traffic for comprehensive monitoring (including HTTP/HTTPS for site detection)
    pcap_loop(handle, -1, NetworkTracker::packetHandler, nullptr);
    
    pcap_close(handle);
}

void NetworkTracker::packetHandler([[maybe_unused]] u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    if (g_network_tracker && g_network_tracker->isMonitoring()) {
        g_network_tracker->processPacket(pkthdr, packet);
    }
}

void NetworkTracker::processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    // Skip Ethernet header (14 bytes)
    if (pkthdr->caplen < 14) return;
    
    const struct ethhdr* eth_header = (struct ethhdr*)packet;
    const u_char* ip_packet = packet + 14;
    size_t ip_packet_len = pkthdr->caplen - 14;
    
    // Process IP packets
    if (ntohs(eth_header->h_proto) == ETH_P_IP && ip_packet_len >= sizeof(struct iphdr)) {
        const struct iphdr* ip_header = (struct iphdr*)ip_packet;
        
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        
        struct in_addr src_addr, dst_addr;
        src_addr.s_addr = ip_header->saddr;
        dst_addr.s_addr = ip_header->daddr;
        
        inet_ntop(AF_INET, &src_addr, src_ip_str, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_ip_str, INET_ADDRSTRLEN);
        
        std::string src_ip(src_ip_str);
        std::string dst_ip(dst_ip_str);
        
        // Only track local network traffic
        if (!isLocalIP(src_ip) && !isLocalIP(dst_ip)) {
            return;
        }
        
        // Determine protocol
        std::string protocol;
        uint16_t src_port = 0, dst_port = 0;
        
        Logger::Debug("Processing IP packet: " + src_ip + " -> " + dst_ip + " (protocol: " + std::to_string(ip_header->protocol) + ")");
        
        if (ip_header->protocol == IPPROTO_TCP) {
            protocol = "TCP";
            if (ip_packet_len >= sizeof(struct iphdr) + sizeof(struct tcphdr)) {
                const struct tcphdr* tcp_header = (struct tcphdr*)(ip_packet + sizeof(struct iphdr));
                src_port = ntohs(tcp_header->source);
                dst_port = ntohs(tcp_header->dest);
                
                Logger::Debug("TCP packet: " + src_ip + ":" + std::to_string(src_port) + " -> " + dst_ip + ":" + std::to_string(dst_port));
                
                // Check for HTTPS/HTTP connections
                if (dst_port == 443 || dst_port == 80) {
                    Logger::Debug("Found HTTPS/HTTP connection: " + src_ip + " -> " + dst_ip + ":" + std::to_string(dst_port));
                    
                    std::string detected_service = detectServiceFromConnection(dst_ip, dst_port);
                    if (!detected_service.empty()) {
                        Logger::Info("Service connection detected: " + src_ip + " -> " + detected_service + " (" + dst_ip + ")");
                        
                        // Log as service connection (simulate DNS query for visited sites tracking)
                        DNSQuery service_query;
                        service_query.device_ip = src_ip;
                        service_query.domain = detected_service;
                        service_query.query_type = (dst_port == 443) ? "HTTPS" : "HTTP";
                        logDNSQuery(service_query);
                    } else {
                        Logger::Debug("No known service detected for TCP connection to IP: " + dst_ip);
                    }
                }
            }
        } else if (ip_header->protocol == IPPROTO_UDP) {
            protocol = "UDP";
            if (ip_packet_len >= sizeof(struct iphdr) + sizeof(struct udphdr)) {
                const struct udphdr* udp_header = (struct udphdr*)(ip_packet + sizeof(struct iphdr));
                src_port = ntohs(udp_header->source);
                dst_port = ntohs(udp_header->dest);
                
                Logger::Debug("UDP packet: " + src_ip + ":" + std::to_string(src_port) + " -> " + dst_ip + ":" + std::to_string(dst_port));
                
                // Check for DNS traffic
                if (src_port == 53 || dst_port == 53) {
                    Logger::Debug("Found DNS packet from " + src_ip + ":" + std::to_string(src_port) + 
                                " to " + dst_ip + ":" + std::to_string(dst_port));
                    DNSPacket dns_packet;
                    if (DNSParser::extractDNSFromIP(ip_packet, ip_packet_len, dns_packet)) {
                        Logger::Debug("Successfully parsed DNS packet");
                        processDNSPacket(dns_packet);
                    } else {
                        Logger::Debug("Failed to parse DNS packet");
                    }
                }
                
                // Check for common HTTPS/HTTP connections to popular services
                if (dst_port == 443 || dst_port == 80) {
                    Logger::Debug("Checking connection: " + src_ip + " -> " + dst_ip + ":" + std::to_string(dst_port));
                    
                    std::string detected_service = detectServiceFromConnection(dst_ip, dst_port);
                    if (!detected_service.empty()) {
                        Logger::Info("Service connection detected: " + src_ip + " -> " + detected_service + " (" + dst_ip + ")");
                        
                        // Log as service connection (simulate DNS query for visited sites tracking)
                        DNSQuery service_query;
                        service_query.device_ip = src_ip;
                        service_query.domain = detected_service;
                        service_query.query_type = (dst_port == 443) ? "HTTPS" : "HTTP";
                        logDNSQuery(service_query);
                    } else {
                        Logger::Debug("No known service detected for IP: " + dst_ip);
                    }
                }
                
                // Check for DNS over HTTPS (DoH) traffic
                if (dst_port == 443) {
                    // Common DNS over HTTPS providers
                    if (dst_ip == "1.1.1.1" || dst_ip == "1.0.0.1" ||      // Cloudflare
                        dst_ip == "8.8.8.8" || dst_ip == "8.8.4.4" ||      // Google
                        dst_ip == "9.9.9.9" || dst_ip == "149.112.112.112" || // Quad9
                        dst_ip.find("dns.google") != std::string::npos ||
                        dst_ip.find("cloudflare-dns") != std::string::npos) {
                        Logger::Info("DoH DNS query detected: " + src_ip + " -> " + dst_ip + " (HTTPS)");
                        
                        // Log as encrypted DNS activity
                        DNSQuery query;
                        query.device_ip = src_ip;
                        query.domain = "encrypted-dns-query";
                        query.query_type = "DoH";
                        logDNSQuery(query);
                    }
                }
            }
        } else if (ip_header->protocol == IPPROTO_ICMP) {
            protocol = "ICMP";
        } else {
            protocol = "Other";
        }
        
        // Log packet activity
        logPacket(src_ip, dst_ip, protocol, src_port, dst_port);
    }
}

void NetworkTracker::processDNSPacket(const DNSPacket& dns_packet) {
    Logger::Debug("Processing DNS packet: query=" + std::to_string(dns_packet.is_query) + 
                  ", response=" + std::to_string(dns_packet.is_response) + 
                  ", questions=" + std::to_string(dns_packet.questions.size()));
    
    if (dns_packet.is_query && !dns_packet.questions.empty()) {
        // DNS Query
        for (const auto& question : dns_packet.questions) {
            Logger::Info("DNS Query: " + dns_packet.source_ip + " -> " + question.name);
            
            DNSQuery query;
            query.device_ip = dns_packet.source_ip;
            query.domain = question.name;
            query.query_type = DNSParser::getRecordTypeString(ntohs(question.qtype));
            
            logDNSQuery(query);
        }
    } else if (dns_packet.is_response && !dns_packet.answers.empty()) {
        // DNS Response - update resolved IPs
        for (const auto& answer : dns_packet.answers) {
            auto recent_query = std::find_if(dns_queries.rbegin(), dns_queries.rend(),
                [&](const DNSQuery& q) {
                    return q.domain == answer.name && 
                           (std::chrono::system_clock::now() - q.timestamp) < std::chrono::seconds(30);
                });
            
            if (recent_query != dns_queries.rend()) {
                const_cast<DNSQuery&>(*recent_query).resolved_ip = answer.rdata;
            }
        }
    }
}

void NetworkTracker::logPacket(const std::string& src_ip, const std::string& dst_ip, 
                               const std::string& protocol, uint16_t src_port, uint16_t dst_port) {
    ActivityEvent event;
    
    // Determine which is the local device
    if (isLocalIP(src_ip)) {
        event.device_ip = src_ip;
        if (auto device = getDeviceByIP(src_ip)) {
            event.device_mac = device->mac;
        }
    } else if (isLocalIP(dst_ip)) {
        event.device_ip = dst_ip;
        if (auto device = getDeviceByIP(dst_ip)) {
            event.device_mac = device->mac;
        }
    }
    
    event.src_ip = src_ip;
    event.dst_ip = dst_ip;
    event.protocol = protocol;
    event.src_port = src_port;
    event.dst_port = dst_port;
    
    // Create description
    std::stringstream desc;
    desc << protocol;
    if (src_port > 0) {
        desc << " " << src_port << "->" << dst_port;
    }
    event.description = desc.str();
    
    logActivity(event);
}

void NetworkTracker::markInactiveDevices() {
    auto now = std::chrono::system_clock::now();
    int marked_inactive = 0;
    
    for (auto& [ip, device] : devices_by_ip) {
        if (device.is_active && (now - device.last_seen) > device_timeout) {
            device.is_active = false;
            marked_inactive++;
        }
    }
    
    if (marked_inactive > 0) {
        Logger::Debug("Marked " + std::to_string(marked_inactive) + " devices as inactive");
    }
}

std::vector<Device> NetworkTracker::getAllDevices() const {
    std::vector<Device> devices;
    for (const auto& [ip, device] : devices_by_ip) {
        devices.push_back(device);
    }
    return devices;
}

std::vector<Device> NetworkTracker::getActiveDevices() const {
    std::vector<Device> active_devices;
    for (const auto& [ip, device] : devices_by_ip) {
        if (device.is_active) {
            active_devices.push_back(device);
        }
    }
    return active_devices;
}

void NetworkTracker::printDeviceSummary() const {
    auto devices = getAllDevices();
    auto active_devices = getActiveDevices();
    
    Logger::Status("=== Device Summary ===");
    Logger::Info("Total devices discovered: " + std::to_string(devices.size()));
    Logger::Info("Currently active devices: " + std::to_string(active_devices.size()));
    
    std::cout << std::left << std::setw(15) << "IP Address" 
              << std::setw(18) << "MAC Address" 
              << std::setw(20) << "Vendor"
              << std::setw(15) << "Hostname"
              << std::setw(10) << "Status"
              << std::setw(10) << "Packets"
              << std::setw(12) << "DNS Queries"
              << std::setw(20) << "Visited Sites"
              << "Last Seen" << std::endl;
    std::cout << std::string(130, '-') << std::endl;
    
    for (const auto& device : devices) {
        auto last_seen = std::chrono::system_clock::to_time_t(device.last_seen);
        
        // Get visited sites for this device
        auto domains = getDeviceDomains(device.ip);
        std::string visited_sites;
        if (domains.empty()) {
            visited_sites = "None";
        } else {
            // Show first few domains, truncated for display
            for (const auto& domain : domains) {
                if (visited_sites.empty()) {
                    visited_sites = domain;
                } else {
                    visited_sites += "," + domain;
                }
                if (visited_sites.length() > 15) {
                    visited_sites = visited_sites.substr(0, 15) + "...";
                    break;
                }
            }
        }
        
        std::cout << std::left << std::setw(15) << device.ip
                  << std::setw(18) << device.mac
                  << std::setw(20) << device.vendor.substr(0, 19)
                  << std::setw(15) << device.hostname.substr(0, 14)
                  << std::setw(10) << (device.is_active ? "Active" : "Inactive")
                  << std::setw(10) << device.total_packets
                  << std::setw(12) << device.dns_queries
                  << std::setw(20) << visited_sites
                  << std::put_time(std::localtime(&last_seen), "%H:%M:%S") << std::endl;
    }
}

void NetworkTracker::printDNSSummary(const std::string& device_ip) const {
    Logger::Status("=== DNS Activity Summary ===");
    
    if (!device_ip.empty()) {
        // Show DNS activity for specific device
        auto domains = getDeviceDomains(device_ip);
        Logger::Info("DNS queries from device " + device_ip + ": " + std::to_string(domains.size()) + " unique domains");
        
        for (const auto& domain : domains) {
            std::cout << "  " << domain << std::endl;
        }
    } else {
        // Show DNS activity for all devices
        for (const auto& [ip, domains] : device_domains) {
            if (!domains.empty()) {
                Logger::Info("Device " + ip + ": " + std::to_string(domains.size()) + " domains");
                for (const auto& domain : domains) {
                    std::cout << "  " << domain << std::endl;
                }
                std::cout << std::endl;
            }
        }
    }
}

std::set<std::string> NetworkTracker::getDeviceDomains(const std::string& device_ip) const {
    auto it = device_domains.find(device_ip);
    return (it != device_domains.end()) ? it->second : std::set<std::string>();
}

bool NetworkTracker::isLocalIP(const std::string& ip) const {
    // Check for common local network ranges
    return (ip.find("192.168.") == 0 || 
            ip.find("10.") == 0 || 
            ip.find("172.") == 0);
}

int NetworkTracker::getDeviceCount() const {
    return devices_by_ip.size();
}

int NetworkTracker::getActiveDeviceCount() const {
    return getActiveDevices().size();
}

std::string NetworkTracker::getCurrentTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

std::string NetworkTracker::detectServiceFromConnection(const std::string& ip, uint16_t /* port */) const {
    // YouTube/Google services - multiple IP ranges
    if (ip.find("216.58.") == 0 || ip.find("172.217.") == 0 || ip.find("142.250.") == 0 ||
        ip.find("208.65.") == 0 || ip.find("74.125.") == 0 || ip.find("173.194.") == 0) {
        return "youtube.com";
    }
    
    // Facebook/Meta services
    if (ip.find("157.240.") == 0 || ip.find("31.13.") == 0 || ip.find("69.63.") == 0 ||
        ip.find("69.171.") == 0 || ip.find("173.252.") == 0) {
        return "facebook.com";
    }
    
    // Amazon/AWS services
    if (ip.find("54.") == 0 || ip.find("52.") == 0 || ip.find("13.") == 0 ||
        ip.find("18.") == 0 || ip.find("176.32.") == 0) {
        return "amazon.com";
    }
    
    // Netflix
    if (ip.find("23.246.") == 0 || ip.find("37.77.") == 0 || ip.find("45.57.") == 0 ||
        ip.find("108.175.") == 0 || ip.find("185.2.") == 0) {
        return "netflix.com";
    }
    
    // Twitter
    if (ip.find("104.244.") == 0 || ip.find("199.59.") == 0 || ip.find("199.96.") == 0) {
        return "twitter.com";
    }
    
    // Instagram (part of Meta but different IP ranges)
    if (ip.find("31.13.") == 0 || ip.find("157.240.") == 0) {
        return "instagram.com";
    }
    
    // Spotify
    if (ip.find("35.186.") == 0 || ip.find("104.154.") == 0) {
        return "spotify.com";
    }
    
    // Microsoft services
    if (ip.find("13.") == 0 || ip.find("20.") == 0 || ip.find("40.") == 0 ||
        ip.find("52.") == 0 || ip.find("104.") == 0) {
        return "microsoft.com";
    }
    
    // Apple services
    if (ip.find("17.") == 0 || ip.find("23.") == 0) {
        return "apple.com";
    }
    
    // Akamai CDN (used by many services)
    if (ip.find("23.") == 0 || ip.find("96.") == 0 || ip.find("184.") == 0) {
        return "cdn-service";
    }
    
    // Cloudflare
    if (ip.find("104.16.") == 0 || ip.find("104.17.") == 0 || ip.find("172.64.") == 0) {
        return "cloudflare-service";
    }
    
    return "";  // Unknown service
}
