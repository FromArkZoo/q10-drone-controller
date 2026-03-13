#!/usr/bin/env python3
"""
Safe replay: sends EXACT stock app packet bytes but neutralizes joystick
values to prevent the drone from taking off.

Modifies ONLY bytes 19-22 (roll/pitch/throttle/yaw) to 0x80 (center)
in packets that have the 0x66 joystick marker at byte 18.
All other bytes remain EXACTLY as captured from the stock app.
"""
import socket
import struct
import time
import sys
import os
import threading
from collections import defaultdict

try:
    import dpkt
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "dpkt", "--break-system-packages", "-q"])
    import dpkt

DRONE_IP = "192.168.169.1"
CLIENT_IP = "192.168.169.3"


def load_packets(pcap_path):
    packets = []
    first_ts = None
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
                if dst_ip == DRONE_IP and udp.dport in (8800, 8801):
                    if first_ts is None:
                        first_ts = ts
                    packets.append({
                        "t": ts - first_ts,
                        "data": bytearray(udp.data),  # mutable copy
                        "dport": udp.dport,
                        "sport": udp.sport,
                    })
            except:
                continue
    return packets


def neutralize_joystick(data):
    """Replace joystick values with center (0x80) if 0x66 marker present."""
    if len(data) > 25 and data[0] == 0xEF and data[1] == 0x02 and data[18] == 0x66:
        data[19] = 0x80  # roll center
        data[20] = 0x80  # pitch center
        data[21] = 0x80  # throttle center
        data[22] = 0x80  # yaw center
    return bytes(data)


def main():
    # Find pcap
    paths = [sys.argv[1] if len(sys.argv) > 1 else None]
    import glob
    paths += glob.glob("*.pcap") + glob.glob("*.pcapng")
    paths += glob.glob("captures/*.pcap") + glob.glob("captures/*.pcapng")
    pcap_path = None
    for p in paths:
        if p and os.path.exists(p):
            pcap_path = p
            break
    if not pcap_path:
        print("ERROR: No pcap file found!")
        sys.exit(1)

    packets = load_packets(pcap_path)
    print(f"Loaded {len(packets)} control packets from {pcap_path}")
    print(f"  Duration: {packets[-1]['t']:.1f}s")

    # Count how many will be neutralized
    neutralized = sum(1 for p in packets if len(p['data']) > 25
                      and p['data'][0] == 0xEF and p['data'][1] == 0x02
                      and p['data'][18] == 0x66)
    print(f"  Packets with joystick data (will be neutralized): {neutralized}")

    sport_8800 = packets[0]["sport"]
    sport_8801 = None
    for p in packets:
        if p["dport"] == 8801:
            sport_8801 = p["sport"]
            break

    # Create sockets
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for buf_size in [4*1024*1024, 2*1024*1024, 1*1024*1024, 512*1024]:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
            break
        except:
            continue
    sock.settimeout(0.5)
    sock.bind((CLIENT_IP, sport_8800))
    print(f"  Bound to {CLIENT_IP}:{sport_8800}")

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if sport_8801:
        try:
            sock2.bind((CLIENT_IP, sport_8801))
            print(f"  Bound to {CLIENT_IP}:{sport_8801} for 8801")
        except:
            sock2.bind((CLIENT_IP, 0))
            p = sock2.getsockname()[1]
            print(f"  Bound to {CLIENT_IP}:{p} for 8801")

    # Video counter
    video_count = 0
    other_count = 0
    stop_event = threading.Event()
    lock = threading.Lock()
    second_counts = defaultdict(int)
    rx_start = [0.0]

    def rx_loop():
        nonlocal video_count, other_count
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
                with lock:
                    if data and data[0] == 0x93 and len(data) > 100:
                        video_count += 1
                        if rx_start[0] > 0:
                            sec = int(time.time() - rx_start[0])
                            second_counts[sec] += 1
                        if video_count == 1:
                            print(f"\n  *** VIDEO STARTED from {addr} ***")
                    else:
                        other_count += 1
            except socket.timeout:
                continue
            except:
                if not stop_event.is_set():
                    break

    rx_thread = threading.Thread(target=rx_loop, daemon=True)
    rx_thread.start()

    print()
    print("=" * 60)
    print("  SAFE REPLAY (joystick neutralized to center)")
    print("=" * 60)
    print()

    rx_start[0] = time.time()
    start = time.monotonic()

    max_time = 40.0
    sent = 0
    for p in packets:
        if p["t"] > max_time:
            break

        target = p["t"]
        elapsed = time.monotonic() - start
        wait = target - elapsed
        if wait > 0:
            time.sleep(wait)

        # Neutralize joystick but keep ALL other bytes exact
        safe_data = neutralize_joystick(p["data"])

        s = sock if p["dport"] == 8800 else sock2
        s.sendto(safe_data, (DRONE_IP, p["dport"]))
        sent += 1

        # Periodic status
        if sent % 100 == 0:
            with lock:
                v = video_count
            print(f"  ... sent {sent} packets, video={v}")

    elapsed = time.monotonic() - start
    with lock:
        v = video_count
    print(f"\n  Replay complete: sent {sent} packets in {elapsed:.1f}s, video={v}")

    # Monitor for 5 more seconds
    print(f"\n  Monitoring for 5 more seconds...")
    for i in range(5):
        time.sleep(1)
        with lock:
            v = video_count
        print(f"  +{elapsed + i + 1:.0f}s: video={v}")

    stop_event.set()
    rx_thread.join(timeout=2)

    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}")
    with lock:
        print(f"  Total video packets: {video_count}")
        print(f"  Total other packets: {other_count}")
    if second_counts:
        print(f"\n  Video packets per second:")
        for sec in range(max(second_counts.keys()) + 1):
            c = second_counts.get(sec, 0)
            bar = "#" * min(c // 3, 50)
            print(f"    {sec:3d}s: {c:5d}  {bar}")

    sock.close()
    sock2.close()


if __name__ == "__main__":
    main()
