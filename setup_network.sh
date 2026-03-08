#!/bin/bash
# ============================================================================
# Q10 Drone Network Setup
# ============================================================================
# The drone WiFi assigns IPs on 192.168.0.x (e.g. Mac gets 192.168.0.50).
# But the stock app controls the drone via a tunnel subnet: 192.168.169.x
#   - Drone control IP: 192.168.169.1
#   - Stock app sends from: 192.168.169.3
#
# The drone firmware only accepts control commands from 192.168.169.3.
# This script adds that IP as an alias on your WiFi interface.
#
# Usage:
#   sudo bash setup_network.sh          # Add the alias
#   sudo bash setup_network.sh remove   # Remove the alias
# ============================================================================

set -e

# Auto-detect the WiFi interface connected to the drone
# The drone WiFi uses 192.168.0.x for the base network
WIFI_IF=""
for iface in en0 en1 en2; do
    if ifconfig "$iface" 2>/dev/null | grep -q "192.168.0\."; then
        WIFI_IF="$iface"
        break
    fi
done

# Fallback: also check if 192.168.169.x is already there
if [ -z "$WIFI_IF" ]; then
    for iface in en0 en1 en2; do
        if ifconfig "$iface" 2>/dev/null | grep -q "192.168.169"; then
            WIFI_IF="$iface"
            break
        fi
    done
fi

if [ -z "$WIFI_IF" ]; then
    echo "ERROR: Cannot find WiFi interface connected to drone."
    echo "Make sure you're connected to the drone's WiFi hotspot first!"
    echo ""
    echo "Looking for 192.168.0.x or 192.168.169.x on en0/en1/en2"
    echo ""
    echo "Available interfaces with IPs:"
    ifconfig | grep -B1 "inet " | grep -v "127.0.0.1"
    exit 1
fi

echo "WiFi interface: $WIFI_IF"
CURRENT_IP=$(ifconfig "$WIFI_IF" | grep "inet " | head -1 | awk '{print $2}')
echo "Current IP: $CURRENT_IP"

if [ "$1" = "remove" ]; then
    echo "Removing 192.168.169.3 alias..."
    sudo ifconfig "$WIFI_IF" -alias 192.168.169.3 2>/dev/null || true
    echo "Done. Alias removed."
    exit 0
fi

# Check if .3 is already assigned
if ifconfig "$WIFI_IF" | grep -q "192.168.169.3"; then
    echo "192.168.169.3 already exists on $WIFI_IF — ready to go!"
    exit 0
fi

echo ""
echo "Adding 192.168.169.3 as alias on $WIFI_IF..."
sudo ifconfig "$WIFI_IF" alias 192.168.169.3 netmask 255.255.255.0
echo "Done!"
echo ""

# Also add a route so 192.168.169.1 is reachable via this interface
# (the drone has 192.168.169.1 as its control IP on the tunnel subnet)
echo "Adding route to 192.168.169.0/24 via $WIFI_IF..."
sudo route add -net 192.168.169.0/24 -interface "$WIFI_IF" 2>/dev/null || true
echo ""

# Verify
echo "Verification:"
ifconfig "$WIFI_IF" | grep "inet "
echo ""
echo "You can now run the controller:"
echo "  python q10_controller.py"
echo ""
echo "To remove the alias later:"
echo "  sudo bash setup_network.sh remove"
