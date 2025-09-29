#include "network_tracker.h"
#include "dns_parser.h"
#include "log_writer.h"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <algorithm>
#include <signal.h>
#include <csignal>
#include <fstream>
#include <sstream>

volatile bool monitoring_active = true;
NetworkTracker* global_tracker = nullptr;

void signalHandler(int signum) {
    Logger::Status("Interrupt signal (" + std::to_string(signum) + ") received.");
    Logger::Status("Generating final reports...");
    
    if (global_tracker) {
        global_tracker->stopMonitoring();
        
        // Print final summaries
        std::cout << "\n";
        global_tracker->printDeviceSummary();
        std::cout << "\n";
        global_tracker->printDNSSummary();
        
        Logger::Status("Network monitoring session complete.");
        Logger::Info("Total devices tracked: " + std::to_string(global_tracker->getDeviceCount()));
        Logger::Info("Active devices: " + std::to_string(global_tracker->getActiveDeviceCount()));
    }
    
    monitoring_active = false;
    exit(0);
}

// Function to find the default network interface
std::string findDefaultInterface() {
    Logger::Info("Searching for default network interface...");
    
    std::ifstream route_file("/proc/net/route");
    if (!route_file.is_open()) {
        Logger::Warning("Cannot open /proc/net/route, checking common interfaces");
        
        // Try common interface names in order of likelihood
        std::vector<std::string> common_interfaces = {"eth0", "ens33", "enp0s3", "eno1", "wlan0", "wlp2s0", "wlp3s0", "wifi0"};
        for (const auto& iface : common_interfaces) {
            std::ifstream test_file("/sys/class/net/" + iface + "/operstate");
            if (test_file.is_open()) {
                std::string state;
                test_file >> state;
                Logger::Info("Interface " + iface + " state: " + state);
                if (state == "up") {
                    Logger::Status("Selected active interface: " + iface);
                    return iface;
                }
            }
        }
        Logger::Warning("No active interfaces found, using eth0 as fallback");
        return "eth0";
    }
    
    std::string line;
    std::getline(route_file, line); // Skip header
    
    while (std::getline(route_file, line)) {
        std::istringstream iss(line);
        std::string iface, dest, gateway;
        iss >> iface >> dest >> gateway;
        
        // Look for default route (destination 00000000)
        if (dest == "00000000") {
            Logger::Status("Found default interface from routing table: " + iface);
            return iface;
        }
    }
    
    Logger::Warning("No default route found, trying to find any active interface");
    
    // Fallback: check common interfaces
    std::vector<std::string> fallback_interfaces = {"eth0", "ens33", "wlan0", "wlp2s0"};
    for (const auto& iface : fallback_interfaces) {
        std::ifstream test_file("/sys/class/net/" + iface + "/operstate");
        if (test_file.is_open()) {
            std::string state;
            test_file >> state;
            if (state == "up") {
                Logger::Status("Using fallback active interface: " + iface);
                return iface;
            }
        }
    }
    
    Logger::Warning("Using eth0 as final fallback");
    return "eth0";
}

class ComprehensiveNetworkMonitor {
private:
    NetworkTracker tracker;
    std::string interface;
    int monitoring_duration;
    
public:
    ComprehensiveNetworkMonitor(const std::string& iface, int duration = 0) 
        : tracker(iface), interface(iface), monitoring_duration(duration) {
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);
        global_tracker = &tracker;
    }
    
    void startContinuousMonitoring() {
        Logger::Status("🔍 Starting Comprehensive Network Monitoring");
        Logger::Status("📡 Interface: " + interface);
        Logger::Status("🎯 Objective: Track devices and monitor their network activity");
        Logger::Info("");
        Logger::Info("This system will:");
        Logger::Info("  ✓ Discover devices via ARP scanning");
        Logger::Info("  ✓ Track device activity and traffic patterns");  
        Logger::Info("  ✓ Monitor DNS queries to see websites visited");
        Logger::Info("  ✓ Associate all network activity with specific devices");
        Logger::Info("  ✓ Generate per-device activity reports");
        Logger::Info("");
        
        // Start comprehensive monitoring
        if (!tracker.startMonitoring()) {
            Logger::Error("Failed to start network monitoring");
            return;
        }
        
        // Main monitoring loop
        Logger::Status("📊 Monitoring active - Press Ctrl+C to stop and generate reports");
        
        int report_interval = 60; // Print status every minute
        int elapsed = 0;
        
        while (monitoring_active) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            elapsed++;
            
            // Print periodic status updates
            if (elapsed % report_interval == 0) {
                printLiveStatus();
                
                if (monitoring_duration > 0 && elapsed >= monitoring_duration) {
                    Logger::Status("Monitoring duration completed");
                    break;
                }
            }
        }
        
        // Final cleanup and reporting
        finalizeMonitoring();
    }
    
    void printLiveStatus() {
        auto active_devices = tracker.getActiveDevices();
        
        Logger::Status("=== Live Status Update ===");
        Logger::Info("Active devices: " + std::to_string(active_devices.size()));
        Logger::Info("Total devices seen: " + std::to_string(tracker.getDeviceCount()));
        
        // Show most active devices
        if (!active_devices.empty()) {
            // Sort by packet count
            std::sort(active_devices.begin(), active_devices.end(), 
                     [](const Device& a, const Device& b) {
                         return a.total_packets > b.total_packets;
                     });
            
            Logger::Info("Most active devices:");
            int count = std::min(3, (int)active_devices.size());
            for (int i = 0; i < count; i++) {
                const auto& device = active_devices[i];
                Logger::Info("  " + device.ip + " (" + device.vendor + ") - " + 
                           std::to_string(device.total_packets) + " packets, " +
                           std::to_string(device.dns_queries) + " DNS queries");
            }
        }
        Logger::Status("========================");
    }
    
    void finalizeMonitoring() {
        Logger::Status("🏁 Finalizing monitoring session...");
        
        tracker.stopMonitoring();
        
        // Generate comprehensive reports
        std::cout << "\n" << std::string(80, '=') << std::endl;
        std::cout << "COMPREHENSIVE NETWORK MONITORING REPORT" << std::endl;
        std::cout << std::string(80, '=') << std::endl;
        
        // Device summary
        tracker.printDeviceSummary();
        
        std::cout << "\n";
        
        // DNS activity summary
        tracker.printDNSSummary();
        
        // Show per-device domain access
        std::cout << "\n" << std::string(60, '-') << std::endl;
        std::cout << "PER-DEVICE DOMAIN ACCESS" << std::endl;
        std::cout << std::string(60, '-') << std::endl;
        
        auto devices = tracker.getActiveDevices();
        for (const auto& device : devices) {
            auto domains = tracker.getDeviceDomains(device.ip);
            if (!domains.empty()) {
                std::cout << "\nDevice: " << device.ip << " (" << device.vendor << ")" << std::endl;
                std::cout << "Domains accessed: " << domains.size() << std::endl;
                
                for (const auto& domain : domains) {
                    std::cout << "  • " << domain << std::endl;
                }
            }
        }
        
        Logger::Status("✅ Network monitoring complete!");
    }
    
    void runQuickScan(int duration_seconds = 60) {
        Logger::Status("🚀 Running Quick Network Scan");
        Logger::Info("Duration: " + std::to_string(duration_seconds) + " seconds");
        
        if (!tracker.startMonitoring()) {
            Logger::Error("Failed to start monitoring");
            return;
        }
        
        // Wait for the specified duration
        std::this_thread::sleep_for(std::chrono::seconds(duration_seconds));
        
        finalizeMonitoring();
    }
};

void printUsage(const std::string& program_name) {
    std::cout << "NetworkMonitor v2.0 - Comprehensive Device & Activity Tracking\n\n";
    std::cout << "Usage: " << program_name << " [OPTIONS]\n\n";
    std::cout << "OPTIONS:\n";
    std::cout << "  -i, --interface <iface>    Network interface (default: wlan0)\n";
    std::cout << "  -t, --time <seconds>       Quick scan duration (default: continuous)\n";
    std::cout << "  -q, --quick               Run quick 60-second scan\n";
    std::cout << "  -h, --help                Show this help\n\n";
    std::cout << "EXAMPLES:\n";
    std::cout << "  " << program_name << "                    # Continuous monitoring\n";
    std::cout << "  " << program_name << " -i eth0           # Monitor on eth0\n";
    std::cout << "  " << program_name << " -q                # Quick 60-second scan\n";
    std::cout << "  " << program_name << " -t 300            # Monitor for 5 minutes\n\n";
    std::cout << "FEATURES:\n";
    std::cout << "  • Continuous device discovery (ARP scanning)\n";
    std::cout << "  • Live traffic monitoring and device association\n";
    std::cout << "  • DNS query tracking (websites visited per device)\n";
    std::cout << "  • Per-device activity reports\n";
    std::cout << "  • Real-time status updates\n\n";
    std::cout << "Press Ctrl+C during monitoring to generate final reports.\n";
}

int main(int argc, char* argv[]) {
    // Initialize logger with DEBUG level to troubleshoot vendor lookup
    Logger::Init(LogLevel::DEBUG);
    
    std::string interface = findDefaultInterface();
    int duration = 0; // 0 = continuous
    bool quick_scan = false;
    
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        
        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        } else if (arg == "-i" || arg == "--interface") {
            if (i + 1 < argc) {
                interface = argv[++i];
            } else {
                Logger::Error("Interface option requires a value");
                return 1;
            }
        } else if (arg == "-t" || arg == "--time") {
            if (i + 1 < argc) {
                duration = std::stoi(argv[++i]);
            } else {
                Logger::Error("Time option requires a value");
                return 1;
            }
        } else if (arg == "-q" || arg == "--quick") {
            quick_scan = true;
            duration = 60;
        } else if (arg == "-d" || arg == "--debug") {
            Logger::Init(LogLevel::DEBUG);
            Logger::Debug("Debug logging enabled");
        } else if (arg == "--arp-scan") {
            // Legacy option for compatibility, but we always do ARP scanning now
            Logger::Debug("ARP scan mode (default behavior)");
        } else {
            Logger::Warning("Unknown option: " + arg);
        }
    }
    
    Logger::Status("🚀 NetworkMonitor v2.0 - Comprehensive Network Monitoring");
    Logger::Info("Designed to track devices and monitor their network activity");
    
    try {
        ComprehensiveNetworkMonitor monitor(interface, duration);
        
        if (quick_scan) {
            monitor.runQuickScan(duration);
        } else {
            monitor.startContinuousMonitoring();
        }
        
    } catch (const std::exception& e) {
        Logger::Error("Network monitoring error: " + std::string(e.what()));
        return 1;
    }
    
    return 0;
}
