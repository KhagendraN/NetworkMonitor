#pragma once

#include "arp_scanner.h"
#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <set>
#include <memory>

// Forward declarations
struct DNSPacket;

// Device information structure
struct Device {
    std::string ip;
    std::string mac;
    std::string vendor;
    std::string hostname;
    std::chrono::system_clock::time_point first_seen;
    std::chrono::system_clock::time_point last_seen;
    bool is_active;
    
    // Activity counters
    uint64_t total_packets;
    uint64_t dns_queries;
    uint64_t http_requests;
    
    Device() : is_active(true), total_packets(0), dns_queries(0), http_requests(0) {
        auto now = std::chrono::system_clock::now();
        first_seen = now;
        last_seen = now;
    }
};

// Network activity event
struct ActivityEvent {
    std::chrono::system_clock::time_point timestamp;
    std::string device_ip;
    std::string device_mac;
    std::string protocol;
    std::string src_ip;
    std::string dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    std::string domain;      // For DNS queries
    std::string description; // Human readable description
    
    ActivityEvent() : src_port(0), dst_port(0) {
        timestamp = std::chrono::system_clock::now();
    }
};

// DNS query record
struct DNSQuery {
    std::chrono::system_clock::time_point timestamp;
    std::string device_ip;
    std::string domain;
    std::string query_type;
    std::string resolved_ip;
    
    DNSQuery() {
        timestamp = std::chrono::system_clock::now();
    }
};

class NetworkTracker {
private:
    // Device tracking
    std::map<std::string, Device> devices_by_ip;    // IP -> Device
    std::map<std::string, Device> devices_by_mac;   // MAC -> Device
    
    // Activity tracking
    std::vector<ActivityEvent> activity_log;
    std::vector<DNSQuery> dns_queries;
    
    // Domain tracking per device
    std::map<std::string, std::set<std::string>> device_domains; // Device IP -> domains
    
    // Configuration
    std::string interface;
    bool monitoring_active;
    std::chrono::seconds device_timeout;
    
    // ARP scanner instance
    std::unique_ptr<ARPScanner> arp_scanner;
    
public:
    NetworkTracker(const std::string& iface = "wlan0");
    ~NetworkTracker();
    
    // Device management
    void addOrUpdateDevice(const std::string& ip, const std::string& mac, const std::string& vendor = "", const std::string& hostname = "");
    void updateDeviceActivity(const std::string& ip);
    void markInactiveDevices();
    Device* getDeviceByIP(const std::string& ip);
    Device* getDeviceByMAC(const std::string& mac);
    
    // Activity logging
    void logActivity(const ActivityEvent& event);
    void logDNSQuery(const DNSQuery& query);
    void logPacket(const std::string& src_ip, const std::string& dst_ip, 
                   const std::string& protocol, uint16_t src_port = 0, uint16_t dst_port = 0);
    
    // Monitoring control
    bool startMonitoring();
    void stopMonitoring();
    bool isMonitoring() const { return monitoring_active; }
    
    // ARP scanning
    void performARPScan();
    void schedulePeriodicARPScan(int interval_minutes = 5);
    
    // Packet sniffing
    void startPacketCapture();
    static void packetHandler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void processPacket(const struct pcap_pkthdr* pkthdr, const u_char* packet);
    
    // DNS monitoring
    void processDNSPacket(const DNSPacket& dns_packet);
    
    // Data access
    std::vector<Device> getAllDevices() const;
    std::vector<Device> getActiveDevices() const;
    std::vector<ActivityEvent> getRecentActivity(int hours = 24) const;
    std::vector<DNSQuery> getRecentDNSQueries(int hours = 24) const;
    std::set<std::string> getDeviceDomains(const std::string& device_ip) const;
    
    // Reporting
    void printDeviceSummary() const;
    void printActivitySummary(int hours = 1) const;
    void printDNSSummary(const std::string& device_ip = "") const;
    void saveDeviceReport(const std::string& filename) const;
    void saveActivityReport(const std::string& filename) const;
    
    // Statistics
    int getDeviceCount() const;
    int getActiveDeviceCount() const;
    uint64_t getTotalPacketsSeen() const;
    
private:
    // Helper functions
    std::string getCurrentTimestamp() const;
    bool isLocalIP(const std::string& ip) const;
    std::string getDeviceKey(const std::string& ip, const std::string& mac) const;
    void cleanupOldData(int days = 7);
    std::string detectServiceFromConnection(const std::string& ip, uint16_t port) const;
    
    // Device discovery callback for ARP scanner
    void onDeviceDiscovered(const DiscoveredDevice& device);
};
