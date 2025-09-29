# NetworkMonitor Makefile
# Compiler settings
CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -g
LIBS = -lpcap -pthread
DEBUG_FLAGS = -DDEBUG

# Source files
MONITOR_SOURCES = network_monitor.cpp network_tracker.cpp arp_scanner.cpp dns_parser.cpp log_writer.cpp

# Target executable
TARGET = network_monitor

# Default target
all: $(TARGET)

# Main comprehensive network monitor
$(TARGET): $(MONITOR_SOURCES)
	@echo "Building NetworkMonitor..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "✅ $(TARGET) built successfully"

# Debug build
debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(TARGET)

# Clean build artifacts
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(TARGET)
	@echo "✅ Clean complete"

# Install dependencies (Ubuntu/Debian)
install-deps:
	@echo "Installing dependencies..."
	sudo apt-get update
	sudo apt-get install libpcap-dev g++

# Help
help:
	@echo "NetworkMonitor Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all (default) - Build network_monitor"
	@echo "  debug         - Build with debug symbols"
	@echo "  clean         - Remove build artifacts"
	@echo "  install-deps  - Install dependencies (Ubuntu/Debian)"
	@echo "  help          - Show this help"
	@echo ""
	@echo "Usage:"
	@echo "  make          # Build the application"
	@echo "  make clean    # Clean build files"
	@echo "  make debug    # Build with debugging enabled"

.PHONY: all debug clean install-deps help
	@echo "✅ arp_scan built successfully"

# Standalone DNS monitor
dns_monitor: $(DNS_SOURCES)
	@echo "Building DNS monitor..."
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LIBS)
	@echo "✅ dns_monitor built successfully"

# Build all targets
build-all: $(TARGETS)
	@echo "🚀 All NetworkMonitor tools built successfully!"
	@echo ""
	@echo "Available executables:"
	@echo "  • network_monitor  - Comprehensive network monitoring (recommended)"
	@echo "  • arp_scan         - Standalone ARP device scanner"
	@echo "  • dns_monitor      - Standalone DNS traffic monitor"
	@echo ""
	@echo "Usage: sudo ./network_monitor --help"

# Debug builds
debug: CXXFLAGS += $(DEBUG_FLAGS)
debug: $(MAIN_TARGET)
	@echo "🐛 Debug build completed"

debug-all: CXXFLAGS += $(DEBUG_FLAGS)
debug-all: $(TARGETS)
	@echo "🐛 All debug builds completed"

# Installation (copy to /usr/local/bin)
install: $(MAIN_TARGET)
	@echo "Installing NetworkMonitor..."
	sudo cp network_monitor /usr/local/bin/
	sudo chmod +x /usr/local/bin/network_monitor
	@echo "✅ NetworkMonitor installed to /usr/local/bin/"
	@echo "You can now run: sudo network_monitor"

install-all: $(TARGETS)
	@echo "Installing all NetworkMonitor tools..."
	sudo cp network_monitor /usr/local/bin/
	sudo cp arp_scan /usr/local/bin/
	sudo cp dns_monitor /usr/local/bin/
	sudo chmod +x /usr/local/bin/network_monitor
	sudo chmod +x /usr/local/bin/arp_scan
	sudo chmod +x /usr/local/bin/dns_monitor
	@echo "✅ All tools installed to /usr/local/bin/"

# Uninstall
uninstall:
	@echo "Uninstalling NetworkMonitor..."
	sudo rm -f /usr/local/bin/network_monitor
	sudo rm -f /usr/local/bin/arp_scan
	sudo rm -f /usr/local/bin/dns_monitor
	@echo "✅ NetworkMonitor uninstalled"

# Clean compiled files
clean:
	@echo "Cleaning compiled files..."
	rm -f $(TARGETS)
	rm -f *.o
	@echo "✅ Clean completed"

# Clean everything including backup files
distclean: clean
	@echo "Deep cleaning..."
	rm -f *~ *.bak *.tmp
	rm -f core core.*
	@echo "✅ Deep clean completed"

# Check dependencies
check-deps:
	@echo "Checking dependencies..."
	@which g++ >/dev/null 2>&1 || (echo "❌ g++ not found. Install: sudo apt-get install g++" && exit 1)
	@pkg-config --exists libpcap 2>/dev/null || (echo "❌ libpcap not found. Install: sudo apt-get install libpcap-dev" && exit 1)
	@echo "✅ All dependencies satisfied"

# Run tests (basic functionality check)
test: $(MAIN_TARGET)
	@echo "Running basic functionality tests..."
	@./network_monitor --help >/dev/null 2>&1 && echo "✅ network_monitor help working" || echo "❌ network_monitor help failed"
	@test -f oui.csv && echo "✅ OUI database found" || echo "⚠️  OUI database missing (optional)"
	@echo "✅ Basic tests completed"

# Quick build and test
quick: $(MAIN_TARGET) test
	@echo "🚀 Quick build and test completed"

# Show help
help:
	@echo "NetworkMonitor Build System"
	@echo "=========================="
	@echo ""
	@echo "Main Targets:"
	@echo "  all             - Build main network_monitor (default)"
	@echo "  build-all       - Build all tools (network_monitor, arp_scan, dns_monitor)"
	@echo "  clean           - Remove compiled files"
	@echo "  install         - Install network_monitor to /usr/local/bin"
	@echo "  install-all     - Install all tools to /usr/local/bin"
	@echo "  uninstall       - Remove installed tools"
	@echo ""
	@echo "Development:"
	@echo "  debug           - Build network_monitor with debug symbols"
	@echo "  debug-all       - Build all tools with debug symbols"
	@echo "  test            - Run basic functionality tests"
	@echo "  check-deps      - Check if dependencies are installed"
	@echo ""
	@echo "Maintenance:"
	@echo "  distclean       - Deep clean (removes backups, core files)"
	@echo "  quick           - Quick build and test"
	@echo "  help            - Show this help"
	@echo ""
	@echo "Examples:"
	@echo "  make                    # Build network_monitor"
	@echo "  make build-all          # Build all tools"
	@echo "  make install            # Install network_monitor"
	@echo "  sudo make install-all   # Install all tools"

# Phony targets
.PHONY: all build-all clean distclean install install-all uninstall check-deps test debug debug-all quick help

# Default target when just running 'make'
.DEFAULT_GOAL := all
