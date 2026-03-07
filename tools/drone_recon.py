#!/usr/bin/env python3
"""
AVIALOGIC Q10 Drone Reconnaissance Toolkit
===========================================
Run this while connected to the drone's Wi-Fi hotspot.
It will discover the drone's IP, scan ports, and probe for video streams.

Usage:
    pip install scapy requests
    python drone_recon.py

No arguments needed — it auto-detects everything.
"""

import socket
import subprocess
import sys
import struct
import time
import os
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Common ports used by budget Wi-Fi drones
KNOWN_DRONE_PORTS = {
    80: "HTTP (web config)",
    554: "RTSP (video stream)",
    7060: "Common drone video stream",
    7070: "Common drone video stream alt",
    8080: "HTTP alt / video",
    8485: "Drone command port (common)",
    8800: "Drone control",
    8888: "Common drone video stream",
    8889: "Drone command alt",
    9000: "Video stream alt",
    2001: "Drone telemetry",
    4000: "Drone control alt",
    4646: "Drone video (some models)",
    6666: "Drone control (some models)",
    10000: "Video stream alt",
    10001: "Video stream alt",
}

# Full scan range for thorough discovery
FULL_SCAN_PORTS = list(range(1, 10001))

REPORT = []


def log(msg, level="INFO"):
    """Log with timestamp and collect for final report."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    prefix = {"INFO": "ℹ️ ", "OK": "✅ ", "WARN": "⚠️ ", "FIND": "🔍 ", "VIDEO": "📹 ", "ERROR": "❌ "}
    icon = prefix.get(level, "  ")
    line = f"[{timestamp}] {icon}{msg}"
    print(line)
    REPORT.append(line)


def get_gateway_ip():
    """Find the default gateway (likely the drone's IP)."""
    log("Detecting default gateway (drone IP)...")
    
    system = sys.platform
    gateway = None
    
    try:
        if system == "darwin":  # macOS
            result = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "gateway" in line:
                    gateway = line.split(":")[1].strip()
                    break
        elif system == "linux":
            result = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True)
            parts = result.stdout.split()
            if "via" in parts:
                gateway = parts[parts.index("via") + 1]
        elif system == "win32":
            result = subprocess.run(["ipconfig"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "Default Gateway" in line and ":" in line:
                    gw = line.split(":")[-1].strip()
                    if gw:
                        gateway = gw
                        break
    except Exception as e:
        log(f"Gateway detection failed: {e}", "ERROR")
    
    if not gateway:
        # Fallback: most budget drones use these
        for candidate in ["192.168.4.1", "192.168.0.1", "172.16.10.1", "192.168.1.1"]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((candidate, 80))
                sock.close()
                if result == 0:
                    gateway = candidate
                    break
            except:
                pass
    
    if gateway:
        log(f"Gateway/Drone IP: {gateway}", "OK")
    else:
        log("Could not detect gateway. Are you connected to the drone's Wi-Fi?", "ERROR")
    
    return gateway


def get_wifi_name():
    """Get the current Wi-Fi network name."""
    try:
        system = sys.platform
        if system == "darwin":
            # macOS 14+ uses different command
            try:
                result = subprocess.run(
                    ["networksetup", "-getairportnetwork", "en0"],
                    capture_output=True, text=True
                )
                if "Current Wi-Fi Network" in result.stdout:
                    return result.stdout.split(":")[1].strip()
            except:
                pass
        elif system == "linux":
            result = subprocess.run(["iwgetid", "-r"], capture_output=True, text=True)
            return result.stdout.strip()
        elif system == "win32":
            result = subprocess.run(["netsh", "wlan", "show", "interfaces"], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "SSID" in line and "BSSID" not in line:
                    return line.split(":")[1].strip()
    except:
        pass
    return "Unknown"


def scan_port(ip, port, timeout=1.0):
    """Check if a single TCP port is open."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None


def scan_ports(ip, ports, max_workers=100):
    """Scan multiple ports concurrently."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in ports}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)
    return sorted(open_ports)


def probe_udp_ports(ip):
    """Probe common UDP ports used by drones."""
    log("Probing common UDP ports...")
    udp_ports = [7060, 7070, 8080, 8485, 8800, 8888, 8889, 9000, 2001, 4000, 4646, 6666, 40000, 50000]
    responsive = []
    
    for port in udp_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(2)
            
            # Send a few different probe packets
            probes = [
                b"\x00" * 4,           # Null probe
                b"\x63\x63",           # Common drone handshake
                b"command",            # Tello-style command
                b"\x01\x00\x00\x00",  # Generic init
            ]
            
            for probe in probes:
                sock.sendto(probe, (ip, port))
                try:
                    data, addr = sock.recvfrom(4096)
                    if data:
                        responsive.append((port, data[:32]))
                        log(f"UDP port {port} responded: {data[:32].hex()} ({len(data)} bytes)", "FIND")
                        break
                except socket.timeout:
                    pass
            
            sock.close()
        except Exception as e:
            pass
    
    return responsive


def probe_video_stream(ip, port, timeout=5):
    """Try to receive video data from a port."""
    log(f"Probing {ip}:{port} for video stream...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        
        # Some drones need a trigger packet
        triggers = [
            b"",  # Just connect
            b"\x01\x00\x00\x00",
            b"GET / HTTP/1.0\r\n\r\n",
        ]
        
        for trigger in triggers:
            if trigger:
                sock.send(trigger)
            
            try:
                data = sock.recv(4096)
                if data:
                    # Check for JPEG markers (MJPEG stream)
                    if b"\xff\xd8\xff" in data:
                        log(f"🎉 MJPEG video stream detected on port {port}!", "VIDEO")
                        sock.close()
                        return {"port": port, "type": "MJPEG", "sample": data[:64].hex()}
                    
                    # Check for H.264 NAL units
                    if b"\x00\x00\x00\x01" in data or b"\x00\x00\x01" in data:
                        log(f"🎉 H.264 video stream detected on port {port}!", "VIDEO")
                        sock.close()
                        return {"port": port, "type": "H264", "sample": data[:64].hex()}
                    
                    # Check for RTSP
                    if b"RTSP" in data or b"rtsp" in data:
                        log(f"🎉 RTSP stream detected on port {port}!", "VIDEO")
                        sock.close()
                        return {"port": port, "type": "RTSP", "sample": data[:64].hex()}
                    
                    # Unknown data — still interesting
                    log(f"Data received on port {port}: {data[:48].hex()} ({len(data)} bytes)", "FIND")
                    sock.close()
                    return {"port": port, "type": "UNKNOWN", "sample": data[:64].hex(), "size": len(data)}
            except socket.timeout:
                pass
        
        sock.close()
    except Exception as e:
        pass
    
    return None


def check_rtsp(ip):
    """Check for RTSP streams on common paths."""
    log("Checking for RTSP streams...")
    rtsp_paths = [
        f"rtsp://{ip}:554/",
        f"rtsp://{ip}:554/live",
        f"rtsp://{ip}:554/stream",
        f"rtsp://{ip}:8554/",
        f"rtsp://{ip}:8554/live",
    ]
    
    for path in rtsp_paths:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            port = 554 if ":554" in path else 8554
            sock.connect((ip, port))
            
            describe = f"DESCRIBE {path} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
            sock.send(describe.encode())
            
            response = sock.recv(4096)
            if b"RTSP" in response:
                log(f"RTSP endpoint found: {path}", "VIDEO")
                log(f"Response: {response[:200].decode(errors='replace')}", "FIND")
                sock.close()
                return path
            sock.close()
        except:
            pass
    
    return None


def check_http(ip, port=80):
    """Check for HTTP server (web config / video endpoint)."""
    log(f"Checking HTTP on port {port}...")
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))
        
        request = f"GET / HTTP/1.0\r\nHost: {ip}\r\n\r\n"
        sock.send(request.encode())
        
        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
                if len(response) > 16384:
                    break
            except:
                break
        
        sock.close()
        
        if response:
            decoded = response[:500].decode(errors="replace")
            log(f"HTTP response on port {port}:\n{decoded[:300]}", "FIND")
            
            # Check if it's serving video
            if b"multipart" in response.lower() or b"mjpeg" in response.lower():
                log(f"HTTP MJPEG stream endpoint on port {port}!", "VIDEO")
            
            return decoded
    except Exception as e:
        log(f"HTTP check failed on port {port}: {e}", "WARN")
    
    return None


def capture_sample_data(ip, port, duration=3):
    """Capture raw data from a port for analysis."""
    log(f"Capturing {duration}s of data from {ip}:{port}...")
    
    samples = []
    
    # TCP capture
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(duration)
        sock.connect((ip, port))
        
        start = time.time()
        total_bytes = 0
        
        while time.time() - start < duration:
            try:
                data = sock.recv(8192)
                if data:
                    total_bytes += len(data)
                    if len(samples) < 5:
                        samples.append(data[:128].hex())
                else:
                    break
            except socket.timeout:
                break
        
        sock.close()
        
        if total_bytes > 0:
            rate = total_bytes / duration
            log(f"TCP port {port}: received {total_bytes} bytes ({rate:.0f} bytes/sec)", "FIND")
            if rate > 10000:
                log(f"High data rate on port {port} — likely video!", "VIDEO")
            return {"port": port, "protocol": "TCP", "bytes": total_bytes, "rate": rate, "samples": samples}
    except:
        pass
    
    # UDP capture
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(duration)
        sock.bind(("", port))
        
        start = time.time()
        total_bytes = 0
        
        while time.time() - start < duration:
            try:
                data, addr = sock.recvfrom(8192)
                if data:
                    total_bytes += len(data)
                    if len(samples) < 5:
                        samples.append(data[:128].hex())
            except socket.timeout:
                break
        
        sock.close()
        
        if total_bytes > 0:
            rate = total_bytes / duration
            log(f"UDP port {port}: received {total_bytes} bytes ({rate:.0f} bytes/sec)", "FIND")
            return {"port": port, "protocol": "UDP", "bytes": total_bytes, "rate": rate, "samples": samples}
    except:
        pass
    
    return None


def save_report(results):
    """Save the full recon report."""
    report_path = "drone_recon_report.json"
    with open(report_path, "w") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"Full report saved to {report_path}", "OK")
    
    # Also save human-readable version
    txt_path = "drone_recon_report.txt"
    with open(txt_path, "w") as f:
        f.write("AVIALOGIC Q10 DRONE RECON REPORT\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write("=" * 60 + "\n\n")
        for line in REPORT:
            f.write(line + "\n")
    log(f"Text report saved to {txt_path}", "OK")


def main():
    print()
    print("=" * 60)
    print("  🛸 AVIALOGIC Q10 DRONE RECON TOOLKIT")
    print("=" * 60)
    print()
    
    results = {
        "timestamp": datetime.now().isoformat(),
        "drone_model": "AVIALOGIC Q10 / HASAKEE Q10",
    }
    
    # Step 1: Check Wi-Fi connection
    wifi_name = get_wifi_name()
    log(f"Connected Wi-Fi network: {wifi_name}")
    results["wifi_name"] = wifi_name
    
    if "Q10" not in wifi_name.upper() and "HASAKEE" not in wifi_name.upper() and "DRONE" not in wifi_name.upper():
        log("Wi-Fi name doesn't look like a drone network. Make sure you're connected to the drone's Wi-Fi!", "WARN")
        log("Common Q10 SSIDs look like: 'HASAKEE-XXXXXX' or 'WiFi-720P-XXXXXX'", "WARN")
        response = input("\nContinue anyway? (y/n): ").strip().lower()
        if response != "y":
            print("Exiting. Connect to the drone's Wi-Fi and try again.")
            return
    
    # Step 2: Find the drone's IP
    drone_ip = get_gateway_ip()
    if not drone_ip:
        # Try common drone IPs directly
        for ip in ["192.168.4.1", "192.168.0.1", "172.16.10.1"]:
            log(f"Trying fallback IP: {ip}...")
            if scan_port(ip, 80) or scan_port(ip, 8080):
                drone_ip = ip
                log(f"Found drone at {ip}", "OK")
                break
    
    if not drone_ip:
        log("Cannot find the drone on the network. Exiting.", "ERROR")
        return
    
    results["drone_ip"] = drone_ip
    
    # Step 3: Quick scan of known drone ports
    print()
    log("=== PHASE 1: Known drone port scan ===")
    known_open = scan_ports(drone_ip, list(KNOWN_DRONE_PORTS.keys()))
    
    for port in known_open:
        desc = KNOWN_DRONE_PORTS.get(port, "Unknown")
        log(f"TCP port {port} OPEN — {desc}", "FIND")
    
    results["known_ports_open"] = known_open
    
    # Step 4: Full port scan (1-10000)
    print()
    log("=== PHASE 2: Full TCP port scan (1-10000) ===")
    log("This may take 30-60 seconds...")
    all_open = scan_ports(drone_ip, FULL_SCAN_PORTS)
    
    new_ports = [p for p in all_open if p not in known_open]
    if new_ports:
        for port in new_ports:
            log(f"TCP port {port} OPEN (discovered)", "FIND")
    
    results["all_tcp_open"] = all_open
    
    # Step 5: UDP probing
    print()
    log("=== PHASE 3: UDP port probing ===")
    udp_results = probe_udp_ports(drone_ip)
    results["udp_responsive"] = [(p, d.hex()) for p, d in udp_results]
    
    # Step 6: Probe each open port for video
    print()
    log("=== PHASE 4: Video stream detection ===")
    video_streams = []
    
    for port in all_open:
        result = probe_video_stream(drone_ip, port)
        if result:
            video_streams.append(result)
    
    # Check RTSP
    rtsp = check_rtsp(drone_ip)
    if rtsp:
        video_streams.append({"type": "RTSP", "url": rtsp})
    
    results["video_streams"] = video_streams
    
    # Step 7: Check HTTP endpoints
    print()
    log("=== PHASE 5: HTTP endpoint check ===")
    http_ports = [p for p in all_open if p in [80, 8080, 8888, 8800, 9000]]
    for port in http_ports:
        check_http(drone_ip, port)
    
    # Step 8: Capture data samples from promising ports
    print()
    log("=== PHASE 6: Data capture from open ports ===")
    captures = []
    for port in all_open:
        cap = capture_sample_data(drone_ip, port, duration=3)
        if cap:
            captures.append(cap)
    
    results["data_captures"] = captures
    
    # Summary
    print()
    print("=" * 60)
    print("  📋 RECON SUMMARY")
    print("=" * 60)
    print()
    log(f"Drone IP: {drone_ip}")
    log(f"Open TCP ports: {all_open}")
    log(f"Responsive UDP ports: {[p for p, _ in udp_results]}")
    log(f"Video streams found: {len(video_streams)}")
    
    if video_streams:
        print()
        log("🎬 VIDEO STREAM DETAILS:")
        for vs in video_streams:
            log(f"  Type: {vs['type']}, Port: {vs.get('port', 'N/A')}", "VIDEO")
    
    if captures:
        print()
        log("📊 HIGH-BANDWIDTH PORTS (likely video/telemetry):")
        for cap in sorted(captures, key=lambda x: x["rate"], reverse=True):
            log(f"  Port {cap['port']} ({cap['protocol']}): {cap['rate']:.0f} bytes/sec")
    
    print()
    log("=" * 50)
    log("NEXT STEPS:")
    log("1. Share the output of this script with Claude")
    log("2. If video stream found: we'll build a viewer app")
    log("3. If command ports found: we'll reverse-engineer controls")
    log(f"4. Try: vlc tcp://{drone_ip}:<video_port>")
    log(f"5. Try: ffplay -i tcp://{drone_ip}:<video_port>")
    log("=" * 50)
    
    # Save report
    save_report(results)
    
    print()
    print("Done! Share drone_recon_report.json with Claude to proceed.")
    print()


if __name__ == "__main__":
    main()
