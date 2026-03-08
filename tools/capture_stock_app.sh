#!/bin/bash
# Capture traffic while using the stock HASAKEE Q10 app
# Run this BEFORE opening the stock app, then connect with the app.
# Press Ctrl+C to stop when done.
#
# Usage:
#   chmod +x tools/capture_stock_app.sh
#   sudo tools/capture_stock_app.sh

CAPTURE_FILE="captures/stock_app_$(date +%Y%m%d_%H%M%S).pcap"
mkdir -p captures

echo "============================================="
echo "  Q10 Stock App Packet Capture"
echo "============================================="
echo ""
echo "1. Make sure you're connected to the drone's WiFi"
echo "2. DON'T open the stock app yet"
echo "3. This will start capturing..."
echo "4. Then open the stock app and connect"
echo "5. Try takeoff, move sticks, land"
echo "6. Press Ctrl+C here when done"
echo ""
echo "Saving to: $CAPTURE_FILE"
echo ""

# First, show network info
echo "--- Network interfaces ---"
ifconfig | grep -A2 "en0\|en1\|awdl" | head -20
echo ""
echo "--- Route to drone ---"
route -n get 192.168.0.1 2>/dev/null | grep -E "gateway|interface" || echo "(no route found)"
echo ""
echo "--- ARP table ---"
arp -a 2>/dev/null | grep "192.168" || echo "(no 192.168.x entries)"
echo ""

# Quick connectivity check
echo "--- Ping test ---"
ping -c 2 -t 2 192.168.0.1 2>&1 | tail -3
echo ""
ping -c 2 -t 2 192.168.169.1 2>&1 | tail -3
echo ""

echo "Starting capture on all interfaces for UDP traffic..."
echo "Press Ctrl+C to stop."
echo ""

# Capture all UDP traffic on drone-related IPs/ports
tcpdump -i any -w "$CAPTURE_FILE" -v \
  'udp and (host 192.168.0.1 or host 192.168.169.1 or port 8800 or port 1234)'
