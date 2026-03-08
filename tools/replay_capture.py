#!/usr/bin/env python3
"""
Replay the EXACT packets from the stock app capture to the drone.
This is the ultimate test — if replaying real captured packets doesn't work,
the issue is network-level (IP address, source port, etc), not protocol.

Usage: python tools/replay_capture.py [path_to_pcap]
"""
import socket
import struct
import time
import sys
import os

# Try to find the pcap file
pcap_paths = [
    sys.argv[1] if len(sys.argv) > 1 else None,
    "captures/iphone_stock.pcap",
    os.path.expanduser("~/iphone_stock_20260307_093143.pcap"),
]

# We'll use dpkt to read the pcap
try:
    import dpkt
except ImportError:
    print("Installing dpkt...")
    os.system("pip install dpkt --break-system-packages 2>/dev/null || pip install dpkt")
    import dpkt

DRONE_IP = "192.168.169.1"

def load_packets(pcap_path):
    """Load control packets from pcap file."""
    packets = []
    with open(pcap_path, 'rb') as f:
        try:
            pc = dpkt.pcapng.Reader(f)
        except:
            f.seek(0)
            pc = dpkt.pcap.Reader(f)
        for ts, buf in pc:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    continue
                ip = eth.data
                if not isinstance(ip.data, dpkt.udp.UDP):
                    continue
                udp = ip.data
                dst_ip = socket.inet_ntoa(ip.dst)
                if dst_ip == "192.168.169.1" and udp.dport in (8800, 8801):
                    packets.append((ts, udp.data, udp.dport, udp.sport))
            except:
                continue
    return packets

def replay(pcap_path):
    print(f"Loading packets from {pcap_path}...")
    packets = load_packets(pcap_path)
    if not packets:
        print("ERROR: No control packets found in capture!")
        return

    print(f"Found {len(packets)} control packets to replay")
    first_ts = packets[0][0]

    # Create sockets - bind to same source port as stock app
    src_port_8800 = packets[0][3]  # Source port used for 8800
    src_port_8801 = None
    for _, _, dport, sport in packets:
        if dport == 8801 and src_port_8801 is None:
            src_port_8801 = sport
            break

    print(f"Stock app source port for 8800: {src_port_8800}")
    print(f"Stock app source port for 8801: {src_port_8801}")

    # CRITICAL: Bind to 192.168.169.3 (the IP the stock app uses)
    # The drone firmware may only accept commands from this IP.
    # Run `sudo bash setup_network.sh` to add .3 as an alias first.
    CLIENT_IP = "192.168.169.3"

    sock_8800 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock_8801 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock_8800.bind((CLIENT_IP, src_port_8800))
        print(f"Bound to {CLIENT_IP}:{src_port_8800} (matching stock app exactly!)")
    except OSError:
        try:
            sock_8800.bind((CLIENT_IP, 0))
            actual = sock_8800.getsockname()[1]
            print(f"Bound to {CLIENT_IP}:{actual} (IP matches, port differs)")
        except OSError:
            sock_8800.bind(('', src_port_8800))
            print(f"WARNING: Cannot bind to {CLIENT_IP} — run: sudo bash setup_network.sh")
            print(f"Bound to 0.0.0.0:{src_port_8800} instead")

    if src_port_8801:
        try:
            sock_8801.bind((CLIENT_IP, src_port_8801))
            print(f"Bound to {CLIENT_IP}:{src_port_8801} for 8801")
        except OSError:
            try:
                sock_8801.bind((CLIENT_IP, 0))
                actual = sock_8801.getsockname()[1]
                print(f"Bound to {CLIENT_IP}:{actual} for 8801")
            except OSError:
                sock_8801.bind(('', 0))
                actual = sock_8801.getsockname()[1]
                print(f"WARNING: Bound 8801 to 0.0.0.0:{actual}")

    # Also listen for responses
    sock_8800.settimeout(0.01)

    print()
    print("=" * 60)
    print("  REPLAYING EXACT STOCK APP PACKETS")
    print("  Make sure you're on the drone WiFi!")
    print("=" * 60)
    print()

    video_count = 0
    rx_count = 0

    # Replay first 200 packets with exact timing
    replay_count = min(len(packets), 500)
    print(f"Replaying {replay_count} packets with original timing...")
    print()

    start_time = time.monotonic()

    for i, (ts, data, dport, sport) in enumerate(packets[:replay_count]):
        # Wait for correct timing
        target_elapsed = ts - first_ts
        actual_elapsed = time.monotonic() - start_time
        wait = target_elapsed - actual_elapsed
        if wait > 0:
            time.sleep(wait)

        # Send the EXACT packet bytes
        sock = sock_8800 if dport == 8800 else sock_8801
        sock.sendto(data, (DRONE_IP, dport))

        # Log important packets
        if len(data) <= 27 or i < 20:
            if len(data) == 4:
                ptype = "HEARTBEAT"
            elif len(data) == 6:
                ptype = "ENABLE"
            elif len(data) >= 6 and data[4] == 0x01 and data[5] == 0x67:
                text = data[6:].decode('ascii', errors='replace')
                ptype = f"TEXT: {text}"
            else:
                ptype = f"CONTROL ({len(data)}B)"
            elapsed_ms = (ts - first_ts) * 1000
            print(f"  #{i+1:3d} +{elapsed_ms:6.0f}ms -> :{dport} [{len(data):3d}B] {ptype}")

        # Check for responses
        try:
            resp, addr = sock_8800.recvfrom(2048)
            if resp[0:1] == b'\x93':
                video_count += 1
                if video_count == 1:
                    print(f"\n  *** VIDEO STREAM STARTED from {addr} ***\n")
                elif video_count % 100 == 0:
                    print(f"  [Video: {video_count} packets]")
            else:
                rx_count += 1
                print(f"  RX from {addr}: {resp[:20].hex(' ')}")
        except socket.timeout:
            pass

    # Now continue sending control packets for a few more seconds
    print()
    print(f"Replay done. Video packets: {video_count}, Other RX: {rx_count}")
    print()

    if video_count > 0:
        print("Video stream is active! Now sending takeoff command...")
        # Send takeoff (cmd=1) using exact format from capture
        takeoff_pkt = bytes.fromhex("ef201900016" + "73c693d325e62665f737369643d636d643d313e")
        # Correct: ef 20 19 00 01 67 3c 69 3d 32 5e 62 66 5f 73 73 69 64 3d 63 6d 64 3d 31 3e
        takeoff_pkt = b'\xef\x20\x19\x00\x01\x67' + b'<i=2^bf_ssid=cmd=1>'
        print(f"  Sending: {takeoff_pkt.hex(' ')}")
        for _ in range(3):
            sock_8800.sendto(takeoff_pkt, (DRONE_IP, 8800))
            time.sleep(0.05)

        # Continue sending control packets for 5 seconds
        print("  Sending control packets for 5 seconds...")
        # Use last control packet from capture as template
        last_ctrl = None
        for ts, data, dport, sport in reversed(packets):
            if dport == 8800 and len(data) >= 88 and data[0] == 0xEF and data[1] == 0x02:
                last_ctrl = bytearray(data)
                break

        if last_ctrl:
            end_time = time.monotonic() + 5
            seq = 0
            while time.monotonic() < end_time:
                struct.pack_into("<H", last_ctrl, 12, seq & 0xFFFF)
                sock_8800.sendto(bytes(last_ctrl), (DRONE_IP, 8800))
                seq += 1
                time.sleep(0.05)

                # Check for responses
                try:
                    resp, addr = sock_8800.recvfrom(2048)
                    if resp[0:1] == b'\x93':
                        video_count += 1
                except socket.timeout:
                    pass

        print(f"\nDone. Total video packets: {video_count}")
    else:
        print("No video stream — drone may not be responding to this IP.")
        print("The stock app uses 192.168.169.3, your Mac might be .2")
        print("Check: ifconfig | grep 192.168.169")

    sock_8800.close()
    sock_8801.close()

if __name__ == "__main__":
    # Find the pcap file
    pcap_path = None
    for p in pcap_paths:
        if p and os.path.exists(p):
            pcap_path = p
            break

    # Also check uploads directory
    if not pcap_path:
        import glob
        uploads = glob.glob(os.path.expanduser("~/*/uploads/iphone_stock*.pcap"))
        if uploads:
            pcap_path = uploads[0]
        else:
            # Check common locations
            for d in ['.', 'captures', os.path.expanduser('~')]:
                files = glob.glob(os.path.join(d, "*.pcap")) + glob.glob(os.path.join(d, "*.pcapng"))
                if files:
                    pcap_path = files[0]
                    break

    if not pcap_path:
        print("ERROR: Cannot find pcap file!")
        print("Usage: python tools/replay_capture.py <path_to_pcap>")
        print()
        print("Please provide the path to your iPhone stock app capture.")
        sys.exit(1)

    replay(pcap_path)
