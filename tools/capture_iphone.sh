#!/bin/bash
# Capture iPhone traffic via USB to see exactly what the stock app sends.
#
# Steps:
#   1. Connect iPhone to Mac via USB cable
#   2. Trust the computer on the iPhone if prompted
#   3. Connect iPhone to the drone's WiFi
#   4. Run this script: sudo tools/capture_iphone.sh
#   5. Open the HASAKEE Q10 app, connect, try takeoff/move/land
#   6. Press Ctrl+C here when done
#
# The capture will be saved in captures/ for analysis.

set -e

CAPTURE_DIR="captures"
mkdir -p "$CAPTURE_DIR"
CAPTURE_FILE="$CAPTURE_DIR/iphone_stock_$(date +%Y%m%d_%H%M%S).pcap"

echo "============================================="
echo "  iPhone Stock App Capture"
echo "============================================="
echo ""

# Get iPhone UDID
echo "Looking for connected iPhone..."
UDID=$(system_profiler SPUSBDataType 2>/dev/null | grep -A2 "iPhone" | grep "Serial Number" | awk '{print $NF}')

if [ -z "$UDID" ]; then
    # Try xcrun
    UDID=$(xcrun xctrace list devices 2>/dev/null | grep "iPhone" | head -1 | grep -oE '[A-F0-9-]{25,}')
fi

if [ -z "$UDID" ]; then
    echo "ERROR: No iPhone found. Make sure it's connected via USB."
    echo ""
    echo "You can find the UDID manually:"
    echo "  system_profiler SPUSBDataType | grep -A5 iPhone"
    echo ""
    echo "Then run:"
    echo "  rvictl -s YOUR_UDID"
    echo "  sudo tcpdump -i rvi0 -w $CAPTURE_FILE udp"
    exit 1
fi

echo "Found iPhone UDID: $UDID"
echo ""

# Create virtual interface
echo "Creating remote virtual interface..."
rvictl -s "$UDID" 2>/dev/null || true
sleep 1

# Check if rvi0 exists
if ! ifconfig rvi0 > /dev/null 2>&1; then
    echo "ERROR: Could not create rvi0 interface."
    echo "Make sure the iPhone is connected and trusted."
    exit 1
fi

echo "rvi0 interface is up!"
echo ""
echo "Now:"
echo "  1. Make sure iPhone is on the drone's WiFi"
echo "  2. Open the HASAKEE Q10 app"
echo "  3. Connect to the drone and fly it around"
echo "  4. Try: connect, takeoff, move sticks, land"
echo "  5. Press Ctrl+C here when done"
echo ""
echo "Saving to: $CAPTURE_FILE"
echo ""
echo "Capturing..."

# Capture UDP traffic on drone subnet
tcpdump -i rvi0 -w "$CAPTURE_FILE" -v 'udp'

# Cleanup
echo ""
echo "Stopping capture..."
rvictl -x "$UDID" 2>/dev/null || true
echo "Saved to: $CAPTURE_FILE"
echo ""
echo "Now run the analyzer:"
echo "  python3 tools/analyze_capture.py $CAPTURE_FILE"
