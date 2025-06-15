#include <iostream>
#include <fstream>
#include <string>
#include <unordered_map>
#include <sstream>
#include <algorithm>
#include <cctype>

// Convert string to uppercase
std::string toUpper(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c){ return std::toupper(c); });
    return s;
}

// Trim spaces and quotes
std::string trim(const std::string& str) {
    size_t start = 0;
    while (start < str.size() && (std::isspace(static_cast<unsigned char>(str[start])) || str[start] == '\"')) ++start;
    size_t end = str.size();
    while (end > start && (std::isspace(static_cast<unsigned char>(str[end - 1])) || str[end - 1] == '\"')) --end;
    return str.substr(start, end - start);
}

// Load your CSV format: second column = OUI, third column = vendor
bool loadOUIMap(const std::string& filename, std::unordered_map<std::string, std::string>& map) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Cannot open CSV file: " << filename << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string col1, oui, vendor;

        // Read first 3 columns only
        if (!std::getline(ss, col1, ',')) continue;
        if (!std::getline(ss, oui, ',')) continue;
        if (!std::getline(ss, vendor, ',')) continue;

        oui = trim(toUpper(oui));
        vendor = trim(vendor);

        if (oui.empty() || vendor.empty()) continue;

        map[oui] = vendor;
    }

    std::cout << "Loaded " << map.size() << " OUI entries\n";
    return true;
}

// Extract OUI from MAC address in XX:XX:XX:XX:XX:XX format as 6 hex digits (uppercase, no separator)
std::string extractOUI(const std::string& mac) {
    // Remove colons and get first 6 hex digits
    std::string oui;
    for (char c : mac) {
        if (c != ':') oui.push_back(c);
        if (oui.size() == 6) break;
    }
    return toUpper(oui);
}

// Lookup vendor by OUI from map
std::string getVendorFromMac(const std::string& mac, const std::unordered_map<std::string, std::string>& ouiMap) {
    std::string oui = extractOUI(mac);
    if (oui.size() != 6) return "Invalid MAC";

    auto it = ouiMap.find(oui);
    if (it != ouiMap.end()) {
        return it->second;
    }
    return "Unknown Vendor";
}

int main() {
    std::unordered_map<std::string, std::string> ouiMap;

    if (!loadOUIMap("oui.csv", ouiMap)) {
        return 1;
    }

    // Test MAC addresses - replace with actual ones to test
    std::string mac1 = "36:06:67:FC:85:30"; // Should map to Espressif Inc.
    std::string mac2 = "1C:4C:48:28:09:E2"; // Should map to zte corporation
    std::string mac3 = "AC:31:84:AA:BB:CC"; // Should map to Huawei Device Co., Ltd.

    std::cout << mac1 << " -> " << getVendorFromMac(mac1, ouiMap) << std::endl;
    std::cout << mac2 << " -> " << getVendorFromMac(mac2, ouiMap) << std::endl;
    std::cout << mac3 << " -> " << getVendorFromMac(mac3, ouiMap) << std::endl;

    return 0;
}
