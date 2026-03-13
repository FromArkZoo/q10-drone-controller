#!/usr/bin/env python3
"""
Hybrid test: replay exact pcap bytes for first N seconds, then switch to
our generated packets. This identifies whether the handshake or the ongoing
packets are causing the video to stop.
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
SWITCH_TIME = 5.0  # seconds: switch from pcap to generated after this


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
                        "data": bytearray(udp.data),
                        "dport": udp.dport,
                        "sport": udp.sport,
                    })
            except:
                continue
    return packets


def neutralize_joystick(data):
    if len(data) > 25 and data[0] == 0xEF and data[1] == 0x02 and data[18] == 0x66:
        data[19] = 0x80
        data[20] = 0x80
        data[21] = 0x80
        data[22] = 0x80
    return bytes(data)


def make_ctrl_88(seq, state):
    buf = bytearray(88)
    buf[0] = 0xEF
    buf[1] = 0x02
    struct.pack_into("<H", buf, 2, 88)
    buf[4:8] = b'\x02\x02\x00\x01'
    buf[8] = 0
    struct.pack_into("<H", buf, 12, seq)
    if state >= 2:
        buf[16] = 0x08
    if state >= 3:
        buf[18] = 0x66
        buf[19] = 0x80
        buf[20] = 0x80
        buf[21] = 0x80
        buf[22] = 0x80
        buf[23] = 0x40
        buf[24] = 0x40
        buf[25] = 0x99
    buf[82:86] = b'\x32\x4B\x14\x2D'
    return bytes(buf)


def make_ctrl_112(seq, state):
    buf = bytearray(112)
    buf[0] = 0xEF
    buf[1] = 0x02
    struct.pack_into("<H", buf, 2, 112)
    buf[4:8] = b'\x02\x02\x00\x01'
    buf[8] = 1
    struct.pack_into("<H", buf, 12, seq)
    if state >= 2:
        buf[16] = 0x08
    if state >= 3:
        buf[18] = 0x66
        buf[19] = 0x80
        buf[20] = 0x80
        buf[21] = 0x80
        buf[22] = 0x80
        buf[23] = 0x40
        buf[24] = 0x40
        buf[25] = 0x99
    buf[82:86] = b'\x32\x4B\x14\x2D'
    buf[100] = 0x18
    buf[104:112] = b'\xff' * 8
    return bytes(buf)


def main():
    paths = [sys.argv[1] if len(sys.argv) > 1 else None]
    import glob
    paths += glob.glob("*.pcap") + glob.glob("captures/*.pcap")
    pcap_path = None
    for p in paths:
        if p and os.path.exists(p):
            pcap_path = p
            break
    if not pcap_path:
        print("ERROR: No pcap file found!")
        sys.exit(1)

    packets = load_packets(pcap_path)
    print(f"Loaded {len(packets)} packets from {pcap_path}")

    # Get the last seq number from pcap at SWITCH_TIME
    last_pcap_seq = 0
    for p in packets:
        if p["t"] > SWITCH_TIME:
            break
        d = p["data"]
        if len(d) > 13 and d[0] == 0xEF and d[1] == 0x02:
            s = struct.unpack_from("<H", bytes(d), 12)[0]
            if s > last_pcap_seq:
                last_pcap_seq = s
    print(f"  Will replay pcap for {SWITCH_TIME}s (last seq={last_pcap_seq})")
    print(f"  Then switch to generated packets")

    sport_8800 = packets[0]["sport"]
    sport_8801 = None
    for p in packets:
        if p["dport"] == 8801:
            sport_8801 = p["sport"]
            break

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

    sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if sport_8801:
        try:
            sock2.bind((CLIENT_IP, sport_8801))
        except:
            sock2.bind((CLIENT_IP, 0))

    video_count = 0
    stop_event = threading.Event()
    lock = threading.Lock()
    second_counts = defaultdict(int)

    def rx_loop():
        nonlocal video_count
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(2048)
                with lock:
                    if data and data[0] == 0x93 and len(data) > 100:
                        video_count += 1
                        sec = int(time.time() - rx_start)
                        second_counts[sec] += 1
                        if video_count == 1:
                            print(f"  *** VIDEO STARTED ***")
            except socket.timeout:
                continue
            except:
                if not stop_event.is_set():
                    break

    rx_start = time.time()
    rx_thread = threading.Thread(target=rx_loop, daemon=True)
    rx_thread.start()

    print(f"\n{'='*60}")
    print(f"  PHASE 1: Exact pcap replay (0-{SWITCH_TIME}s)")
    print(f"{'='*60}")

    start = time.monotonic()
    sent = 0
    for p in packets:
        if p["t"] > SWITCH_TIME:
            break
        target = p["t"]
        elapsed = time.monotonic() - start
        wait = target - elapsed
        if wait > 0:
            time.sleep(wait)
        safe_data = neutralize_joystick(p["data"])
        s = sock if p["dport"] == 8800 else sock2
        s.sendto(safe_data, (DRONE_IP, p["dport"]))
        sent += 1

    with lock:
        v = video_count
    elapsed = time.monotonic() - start
    print(f"  Sent {sent} pcap packets in {elapsed:.1f}s, video={v}")

    print(f"\n{'='*60}")
    print(f"  PHASE 2: Generated packets ({SWITCH_TIME}s-35s)")
    print(f"{'='*60}")

    seq = last_pcap_seq + 1
    pkt_counter = 0
    gen_start = time.monotonic()

    while time.monotonic() - start < 35.0:
        now = time.monotonic()
        gen_elapsed = now - gen_start

        # All generated packets in state 3 (FULL)
        seq += 1
        pkt_counter += 1
        if pkt_counter % 3 == 0:
            sock.sendto(make_ctrl_112(seq, 3), (DRONE_IP, 8800))
        else:
            sock.sendto(make_ctrl_88(seq, 3), (DRONE_IP, 8800))

        time.sleep(0.028)  # ~35Hz

        # Report every second
        if int(gen_elapsed) > int(gen_elapsed - 0.028):
            with lock:
                v = video_count
            total_elapsed = now - start
            print(f"  +{total_elapsed:.0f}s | video={v} | seq={seq}")

    stop_event.set()
    rx_thread.join(timeout=2)

    print(f"\n{'='*60}")
    print(f"  RESULTS")
    print(f"{'='*60}")
    with lock:
        print(f"  Total video: {video_count}")
    if second_counts:
        print(f"\n  Per second:")
        for sec in range(max(second_counts.keys()) + 1):
            c = second_counts.get(sec, 0)
            bar = "#" * min(c // 5, 50)
            print(f"    {sec:3d}s: {c:5d}  {bar}")

    sock.close()
    sock2.close()


if __name__ == "__main__":
    main()
