#!/bin/bash
# ============================================================================
# Q10 Drone Network Setup (macOS + Linux/Pi)
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

OS="$(uname)"
WIFI_IF=""

if [ "$OS" = "Darwin" ]; then
    # macOS: check en0/en1/en2
    for iface in en0 en1 en2; do
        if ifconfig "$iface" 2>/dev/null | grep -q "192.168.0\."; then
            WIFI_IF="$iface"
            break
        fi
    done
    if [ -z "$WIFI_IF" ]; then
        for iface in en0 en1 en2; do
            if ifconfig "$iface" 2>/dev/null | grep -q "192.168.169"; then
                WIFI_IF="$iface"
                break
            fi
        done
    fi
else
    # Linux (Pi): check wlan0, then wlan1
    for iface in wlan0 wlan1; do
        if ip addr show "$iface" 2>/dev/null | grep -q "192.168.0\."; then
            WIFI_IF="$iface"
            break
        fi
    done
    if [ -z "$WIFI_IF" ]; then
        for iface in wlan0 wlan1; do
            if ip addr show "$iface" 2>/dev/null | grep -q "192.168.169"; then
                WIFI_IF="$iface"
                break
            fi
        done
    fi
fi

if [ -z "$WIFI_IF" ]; then
    echo "ERROR: Cannot find WiFi interface connected to drone."
    echo "Make sure you're connected to the drone's WiFi hotspot first!"
    echo ""
    if [ "$OS" = "Darwin" ]; then
        echo "Looking for 192.168.0.x or 192.168.169.x on en0/en1/en2"
        echo ""
        echo "Available interfaces with IPs:"
        ifconfig | grep -B1 "inet " | grep -v "127.0.0.1"
    else
        echo "Looking for 192.168.0.x or 192.168.169.x on wlan0/wlan1"
        echo ""
        echo "Available interfaces with IPs:"
        ip -4 addr show | grep -E "inet |^[0-9]"
    fi
    exit 1
fi

echo "WiFi interface: $WIFI_IF"
if [ "$OS" = "Darwin" ]; then
    CURRENT_IP=$(ifconfig "$WIFI_IF" | grep "inet " | head -1 | awk '{print $2}')
else
    CURRENT_IP=$(ip -4 addr show "$WIFI_IF" | grep "inet " | head -1 | awk '{print $2}' | cut -d/ -f1)
fi
echo "Current IP: $CURRENT_IP"

# --- Remove ---
if [ "$1" = "remove" ]; then
    echo "Removing 192.168.169.3 alias..."
    if [ "$OS" = "Darwin" ]; then
        sudo ifconfig "$WIFI_IF" -alias 192.168.169.3 2>/dev/null || true
    else
        sudo ip addr del 192.168.169.3/24 dev "$WIFI_IF" 2>/dev/null || true
        sudo ip route del 192.168.169.0/24 dev "$WIFI_IF" 2>/dev/null || true
    fi
    echo "Done. Alias removed."
    exit 0
fi

# --- Check if already set up ---
if [ "$OS" = "Darwin" ]; then
    ALREADY=$(ifconfig "$WIFI_IF" 2>/dev/null | grep -c "192.168.169.3" || true)
else
    ALREADY=$(ip addr show "$WIFI_IF" 2>/dev/null | grep -c "192.168.169.3" || true)
fi

if [ "$ALREADY" -gt 0 ]; then
    echo "192.168.169.3 already exists on $WIFI_IF — ready to go!"
    exit 0
fi

# --- Add alias ---
echo ""
echo "Adding 192.168.169.3 as alias on $WIFI_IF..."
if [ "$OS" = "Darwin" ]; then
    sudo ifconfig "$WIFI_IF" alias 192.168.169.3 netmask 255.255.255.0
else
    sudo ip addr add 192.168.169.3/24 dev "$WIFI_IF"
fi
echo "Done!"
echo ""

# --- Add route ---
echo "Adding route to 192.168.169.0/24 via $WIFI_IF..."
if [ "$OS" = "Darwin" ]; then
    sudo route add -net 192.168.169.0/24 -interface "$WIFI_IF" 2>/dev/null || true
else
    sudo ip route add 192.168.169.0/24 dev "$WIFI_IF" 2>/dev/null || true
fi
echo ""

# --- Verify ---
echo "Verification:"
if [ "$OS" = "Darwin" ]; then
    ifconfig "$WIFI_IF" | grep "inet "
else
    ip -4 addr show "$WIFI_IF" | grep "inet "
fi
echo ""
echo "You can now run the controller:"
echo "  python q10_controller.py"
echo ""
echo "To remove the alias later:"
echo "  sudo bash setup_network.sh remove"
