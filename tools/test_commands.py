#!/usr/bin/env python3
"""
Test different control packet formats against the drone.
Run while connected to drone WiFi.

This sends takeoff commands in several formats to find which one
the drone actually responds to.

WARNING: The drone may take off! Be ready to catch it.

Usage: python3 tools/test_commands.py
"""
import socket
import struct
import time
import sys

DRONE_IP = "192.168.169.1"
PORT = 8800
STREAM_INIT = bytes([0xEF, 0x00, 0x04, 0x00])

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.5)

def send(data, label=""):
    print(f"  TX [{len(data):3d}B] {data.hex(' ')[:80]}  {label}")
    sock.sendto(data, (DRONE_IP, PORT))

def drain_video():
    """Read any pending video packets."""
    count = 0
    while True:
        try:
            data, _ = sock.recvfrom(2048)
            count += 1
        except socket.timeout:
            break
    return count

def pause(sec=1.0, label=""):
    if label:
        print(f"\n  >>> {label} — watch the drone! <<<")
    time.sleep(sec)
    v = drain_video()
    if v:
        print(f"  (drained {v} video packets)")

# =====================================================================
print("=" * 60)
print("  DRONE COMMAND FORMAT TESTER")
print("  IP: %s  Port: %d" % (DRONE_IP, PORT))
print("=" * 60)

# Init stream
print("\n[0] Stream init...")
for _ in range(5):
    send(STREAM_INIT)
    time.sleep(0.1)
pause(1.0)
print(f"  Video packets received: {drain_video()}")
print("  Stream is active.\n")

input("Press ENTER to start testing formats (drone may take off!)...")

# =====================================================================
# FORMAT 1: WIFI UAV 20-byte (as we've been sending)
# =====================================================================
print("\n" + "-" * 60)
print("[1] WIFI UAV 20-byte: takeoff cmd=0x01 at byte 6")
print("-" * 60)

def wifi_uav_packet(roll=0x80, pitch=0x80, throttle=0x80, yaw=0x80, cmd=0, headless=0x02):
    buf = bytearray(20)
    buf[0] = 0x66
    buf[1] = 0x80
    buf[2] = roll
    buf[3] = pitch
    buf[4] = throttle
    buf[5] = yaw
    buf[6] = cmd
    buf[7] = headless
    buf[18] = roll ^ pitch ^ throttle ^ yaw ^ cmd ^ headless
    buf[19] = 0x99
    return bytes(buf)

# Send takeoff
for _ in range(10):
    send(wifi_uav_packet(cmd=0x01), "takeoff")
    time.sleep(0.05)
# Then centered sticks
for _ in range(40):
    send(wifi_uav_packet())
    time.sleep(0.05)
pause(2.0, "FORMAT 1: Did it move?")

# =====================================================================
# FORMAT 2: Just the inner 66..99 block from original captures (8 bytes)
# =====================================================================
print("\n" + "-" * 60)
print("[2] Short 66..99 block (8 bytes) with takeoff")
print("-" * 60)

def short_66_packet(roll=0x80, pitch=0x80, throttle=0x80, yaw=0x80, cmd=0):
    buf = bytearray(8)
    buf[0] = 0x66
    buf[1] = roll
    buf[2] = pitch
    buf[3] = throttle
    buf[4] = yaw
    buf[5] = 0x40  # trim from original
    buf[6] = 0x40  # trim from original
    buf[7] = 0x99
    return bytes(buf)

for _ in range(10):
    send(short_66_packet(cmd=0x01), "takeoff")
    time.sleep(0.05)
for _ in range(40):
    send(short_66_packet())
    time.sleep(0.05)
pause(2.0, "FORMAT 2: Did it move?")

# =====================================================================
# FORMAT 3: Original EF 02 control packet (88 bytes) at correct IP
# =====================================================================
print("\n" + "-" * 60)
print("[3] Original EF 02 format (88 bytes) — from CLAUDE.md captures")
print("-" * 60)

seq = 0
def ef02_packet(roll=0x80, pitch=0x80, throttle=0x80, yaw=0x80, sub_type=0):
    global seq
    pkt_len = 88 if sub_type == 0 else (128 if sub_type == 2 else 160)
    buf = bytearray(pkt_len)
    buf[0] = 0xEF
    buf[1] = 0x02
    struct.pack_into("<H", buf, 2, pkt_len)
    buf[4:8] = bytes([0x02, 0x02, 0x00, 0x01])
    buf[8] = sub_type
    struct.pack_into("<I", buf, 12, seq)
    seq += 1
    buf[16] = 0x08
    buf[17] = 0x00
    buf[18] = 0x66
    buf[19] = roll
    buf[20] = pitch
    buf[21] = throttle
    buf[22] = yaw
    buf[23] = 0x40
    buf[24] = 0x40
    buf[25] = 0x99
    if pkt_len >= 86:
        buf[82:86] = bytes([0x32, 0x4B, 0x14, 0x2D])
    return bytes(buf)

# Do the original handshake at correct IP
for _ in range(2):
    send(ef02_packet(sub_type=0), "init-88")
    time.sleep(0.05)
send(bytes([0xEF, 0x20, 0x06, 0x00, 0x01, 0x65]), "enable")
time.sleep(0.05)
for _ in range(2):
    send(ef02_packet(sub_type=2), "init-128")
    time.sleep(0.05)

# Send text commands
def text_cmd(cmd_id):
    text = f"cmd={cmd_id}".encode("ascii")
    total_len = 4 + 3 + len(text)
    buf = bytearray()
    buf.append(0xEF)
    buf.append(0x20)
    buf += struct.pack("<H", total_len)
    buf += bytes([0x00, 0x01, 0x67])
    buf += text
    return bytes(buf)

send(text_cmd(2), "cmd=2 connect")
time.sleep(0.05)
send(text_cmd(3), "cmd=3 start video")
time.sleep(0.05)
send(text_cmd(106), "cmd=106 calibrate")
time.sleep(0.1)

# Now send takeoff
send(text_cmd(1), "cmd=1 TAKEOFF")
time.sleep(0.05)

# Send control packets
for _ in range(60):
    send(ef02_packet(sub_type=1, throttle=0x90), "control-throttle-up")
    time.sleep(0.05)
pause(2.0, "FORMAT 3: Did it move?")

# =====================================================================
# FORMAT 4: WIFI UAV but with throttle UP (not just takeoff cmd)
# =====================================================================
print("\n" + "-" * 60)
print("[4] WIFI UAV 20-byte with THROTTLE=0xFF (full up)")
print("-" * 60)

for _ in range(60):
    send(wifi_uav_packet(throttle=0xFF), "full-throttle")
    time.sleep(0.05)
pause(2.0, "FORMAT 4: Did it move?")

# =====================================================================
# FORMAT 5: Try different byte 1 values (maybe it's not 0x80)
# =====================================================================
print("\n" + "-" * 60)
print("[5] WIFI UAV with byte1=0x00 (instead of 0x80)")
print("-" * 60)

def wifi_uav_v2(roll=0x80, pitch=0x80, throttle=0x80, yaw=0x80, cmd=0, headless=0x02, byte1=0x00):
    buf = bytearray(20)
    buf[0] = 0x66
    buf[1] = byte1
    buf[2] = roll
    buf[3] = pitch
    buf[4] = throttle
    buf[5] = yaw
    buf[6] = cmd
    buf[7] = headless
    buf[18] = roll ^ pitch ^ throttle ^ yaw ^ cmd ^ headless
    buf[19] = 0x99
    return bytes(buf)

for _ in range(10):
    send(wifi_uav_v2(cmd=0x01, byte1=0x00), "takeoff byte1=0x00")
    time.sleep(0.05)
for _ in range(40):
    send(wifi_uav_v2(byte1=0x00, throttle=0xC0), "throttle-up byte1=0x00")
    time.sleep(0.05)
pause(2.0, "FORMAT 5: Did it move?")

# =====================================================================
# FORMAT 6: Combine EF02 wrapper + text takeoff cmd at correct IP
# =====================================================================
print("\n" + "-" * 60)
print("[6] EF02 control + text cmd takeoff (various cmd IDs)")
print("-" * 60)

# Try different potential takeoff command IDs
for cmd_id in [1, 2, 7, 8, 100, 101]:
    send(text_cmd(cmd_id), f"cmd={cmd_id}")
    time.sleep(0.2)
    for _ in range(10):
        send(ef02_packet(sub_type=1, throttle=0xA0))
        time.sleep(0.05)
pause(2.0, "FORMAT 6: Did it move with any cmd ID?")

print("\n" + "=" * 60)
print("  TEST COMPLETE")
print("  Which format (1-6) made the drone react?")
print("=" * 60)

sock.close()
