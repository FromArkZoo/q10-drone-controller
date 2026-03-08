#!/usr/bin/env python3
"""
Quick probe to find what the drone actually responds to.
Run while connected to drone WiFi.

Usage: python3 tools/probe_drone.py
"""
import socket
import subprocess
import sys
import time

def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")

# 1. Show network config
section("NETWORK CONFIGURATION")
try:
    result = subprocess.run(["ifconfig"], capture_output=True, text=True)
    for line in result.stdout.split('\n'):
        if 'inet ' in line or (line and not line.startswith('\t')):
            print(line)
except:
    pass

print()
try:
    result = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        line = line.strip()
        if line:
            print(f"  {line}")
except:
    pass

# 2. Ping test
section("PING TEST")
for ip in ["192.168.0.1", "192.168.169.1", "192.168.1.1", "172.16.10.1"]:
    try:
        result = subprocess.run(["ping", "-c", "1", "-t", "1", ip],
                                capture_output=True, text=True, timeout=3)
        ok = result.returncode == 0
        print(f"  {ip:20s} {'REACHABLE' if ok else 'no response'}")
    except:
        print(f"  {ip:20s} timeout")

# 3. ARP table
section("ARP TABLE (devices on network)")
try:
    result = subprocess.run(["arp", "-a"], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if "192.168" in line or "172.16" in line or "10.0" in line:
            print(f"  {line.strip()}")
except:
    pass

# 4. UDP port scan on reachable IPs
section("UDP PORT PROBE")
print("Sending probe packets and listening for responses...\n")

# The heartbeat packet that the stock app sends
heartbeat = bytes([0xEF, 0x00, 0x04, 0x00])

# Also try just a generic probe
generic = b'\x00' * 4

ips_to_try = ["192.168.0.1", "192.168.169.1"]
ports_to_try = [8800, 8080, 80, 7060, 7070, 8888, 8889, 6666, 4000, 2001, 9000, 1234, 40000, 50000]

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(0.3)

for ip in ips_to_try:
    for port in ports_to_try:
        for label, probe in [("heartbeat", heartbeat), ("generic", generic)]:
            try:
                sock.sendto(probe, (ip, port))
                data, addr = sock.recvfrom(2048)
                print(f"  *** RESPONSE from {addr} on {ip}:{port} ({label}): {data[:20].hex(' ')}")
            except socket.timeout:
                pass
            except OSError as e:
                if "Network is unreachable" in str(e):
                    print(f"  {ip}:{port:5d} - UNREACHABLE")
                    break  # skip this IP
                # Other errors (connection refused etc) mean the host exists but port closed
                if "Connection refused" in str(e):
                    print(f"  {ip}:{port:5d} - host alive, port closed ({label})")

sock.close()

# 5. TCP port scan (quick)
section("TCP PORT SCAN (quick)")
for ip in ips_to_try:
    print(f"\n  Scanning {ip}...")
    for port in [80, 443, 554, 8080, 8800, 7060, 7070, 8888, 8889, 1234, 21, 23, 9000]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"    *** PORT {port} OPEN on {ip} ***")
                # Try to grab banner
                try:
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                    banner = sock.recv(256)
                    print(f"        Banner: {banner[:100]}")
                except:
                    pass
        except OSError as e:
            if "Network is unreachable" in str(e):
                print(f"    {ip} is unreachable, skipping")
                sock.close()
                break
        finally:
            sock.close()

# 6. Try the full handshake to both IPs and report
section("FULL HANDSHAKE TEST")
for ip in ips_to_try:
    print(f"\n  Testing handshake to {ip}:8800...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)

        # Send heartbeats
        for i in range(3):
            s.sendto(heartbeat, (ip, 8800))
            time.sleep(0.2)

        # Send enable
        enable = bytes([0xEF, 0x20, 0x06, 0x00, 0x01, 0x65])
        s.sendto(enable, (ip, 8800))

        # Send cmd=2 (connect)
        cmd2 = bytes([0xEF, 0x20, 0x0C, 0x00, 0x00, 0x01, 0x67]) + b"cmd=2"
        s.sendto(cmd2, (ip, 8800))

        # Wait for response
        try:
            data, addr = s.recvfrom(2048)
            print(f"    *** GOT RESPONSE from {addr}: {data[:30].hex(' ')}")
        except socket.timeout:
            print(f"    No response from {ip}:8800")

        s.close()
    except OSError as e:
        print(f"    Error: {e}")

print(f"\n{'='*60}")
print("  DONE")
print(f"{'='*60}\n")
