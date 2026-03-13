#!/bin/bash
# ============================================================================
# Q10 Controller Test Script (for Raspberry Pi)
# ============================================================================
# Switches to drone WiFi, sets up network alias + route, starts the
# controller, and tests /api/connect with full diagnostics.
#
# Usage: nohup bash controller_test.sh > ~/test_result.log 2>&1 &
# ============================================================================

set -x  # trace every command for diagnostics

DRONE_SSID="HASAKEE-Q10_2B653C"
DRONE_BSSID="B4:C2:E0:2B:65:3C"
HOME_WIFI="netplan-wlan0-VM8821639"
PROJECT_DIR="$HOME/q10-drone-controller"
CONTROLLER_LOG="$HOME/controller_output.log"

echo "=== Q10 Controller Test ==="
echo "Started: $(date)"
echo ""

# --- Connect to drone WiFi ---
echo "--- Switching to drone WiFi ---"
sudo nmcli device wifi connect "$DRONE_BSSID" 2>&1
sleep 3

echo "--- WiFi status ---"
nmcli device status
echo ""

# --- Verify we got a drone IP ---
echo "--- Current IPs on wlan0 ---"
ip -4 addr show wlan0
echo ""

# --- Add 192.168.169.3 alias ---
echo "--- Adding 192.168.169.3 alias ---"
sudo ip addr add 192.168.169.3/24 dev wlan0 2>/dev/null || echo "(alias may already exist)"

# --- Add route to 192.168.169.0/24 ---
echo "--- Adding route to 192.168.169.0/24 ---"
sudo ip route add 192.168.169.0/24 dev wlan0 2>/dev/null || echo "(route may already exist)"

# --- Verify alias and route ---
echo "--- Verify alias ---"
ip -4 addr show wlan0
echo ""
echo "--- Verify route ---"
ip route show | grep 192.168.169
echo ""

# --- Test drone reachability ---
echo "--- Ping drone at 192.168.169.1 ---"
ping -c 2 -W 1 192.168.169.1 2>&1 || echo "WARNING: drone not reachable at 192.168.169.1"
echo ""

# --- Start the controller ---
echo "--- Starting controller ---"
cd "$PROJECT_DIR"
python3 q10_controller.py > "$CONTROLLER_LOG" 2>&1 &
CONTROLLER_PID=$!
echo "Controller PID: $CONTROLLER_PID"
sleep 5

# --- Check controller is running ---
if ! kill -0 "$CONTROLLER_PID" 2>/dev/null; then
    echo "ERROR: Controller exited early!"
    echo "--- Controller output ---"
    cat "$CONTROLLER_LOG"
    echo "--- Switching back to home WiFi ---"
    sudo nmcli connection up "$HOME_WIFI" 2>/dev/null || true
    exit 1
fi

echo "--- Controller startup output ---"
cat "$CONTROLLER_LOG"
echo ""

# --- Connect to drone ---
echo "--- Calling /api/connect ---"
CONNECT_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" http://localhost:5050/api/connect 2>&1)
echo "Connect response: $CONNECT_RESPONSE"
echo ""

sleep 2

# --- Check state ---
echo "--- Checking /api/state ---"
STATE_RESPONSE=$(curl -s http://localhost:5050/api/state 2>&1)
echo "State: $STATE_RESPONSE"
echo ""

# --- Check if connected ---
if echo "$STATE_RESPONSE" | python3 -c "import sys,json; d=json.load(sys.stdin); print('CONNECTED:', d.get('connected', False))" 2>/dev/null; then
    echo ""
else
    echo "Could not parse state response"
fi

# --- Cleanup ---
echo "--- Stopping controller ---"
kill "$CONTROLLER_PID" 2>/dev/null || true
wait "$CONTROLLER_PID" 2>/dev/null || true

echo ""
echo "--- Final controller log ---"
cat "$CONTROLLER_LOG"
echo ""

echo "--- Switching back to home WiFi ---"
sudo nmcli connection up "$HOME_WIFI" 2>/dev/null || true

echo ""
echo "=== Test complete: $(date) ==="
