#!/usr/bin/env python3
"""
Hunt for the video keepalive mechanism in the stock app capture.

Specifically looks for:
1. ANY packets from client to ANY port on the drone (not just 8800/8801)
2. Traffic to/from port 1234 (video port)
3. Client->drone traffic patterns that correlate with video staying alive
4. Any bidirectional traffic on the video channel
"""
import sys
import os
import struct
import socket
from collections import defaultdict

try:
    import dpkt
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "dpkt", "--break-system-packages", "-q"])
    import dpkt


def analyze(pcap_file):
    print(f"Loading {pcap_file}...")

    all_packets = []
    with open(pcap_file, 'rb') as f:
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
                all_packets.append({
                    "ts": ts,
                    "src": socket.inet_ntoa(ip.src),
                    "dst": socket.inet_ntoa(ip.dst),
                    "sport": udp.sport,
                    "dport": udp.dport,
                    "data": bytes(udp.data),
                    "len": len(udp.data),
                })
            except:
                continue

    first_ts = all_packets[0]["ts"] if all_packets else 0
    for p in all_packets:
        p["t"] = p["ts"] - first_ts

    print(f"Total UDP packets: {len(all_packets)}")

    # ---------------------------------------------------------------
    # 1. ALL unique flows (src:sport -> dst:dport)
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("ALL UNIQUE UDP FLOWS")
    print("=" * 80)

    flows = defaultdict(list)
    for p in all_packets:
        key = f"{p['src']}:{p['sport']} -> {p['dst']}:{p['dport']}"
        flows[key].append(p)

    for key, pkts in sorted(flows.items(), key=lambda x: -len(x[1])):
        ts_range = f"{pkts[0]['t']:.2f}s - {pkts[-1]['t']:.2f}s"
        sizes = set(p['len'] for p in pkts)
        size_str = f"sizes={sorted(sizes)[:8]}" if len(sizes) <= 8 else f"sizes={min(sizes)}-{max(sizes)} ({len(sizes)} unique)"
        print(f"  {key:55s} {len(pkts):6d} pkts  {ts_range}  {size_str}")

    # ---------------------------------------------------------------
    # 2. Client -> drone on ALL ports (not just 8800)
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("CLIENT -> DRONE: ALL PORTS")
    print("=" * 80)

    client_to_drone = [p for p in all_packets if p["dst"] == "192.168.169.1"]
    by_dport = defaultdict(list)
    for p in client_to_drone:
        by_dport[p["dport"]].append(p)

    for port, pkts in sorted(by_dport.items()):
        ts_range = f"{pkts[0]['t']:.2f}s - {pkts[-1]['t']:.2f}s"
        print(f"\n  Port {port}: {len(pkts)} packets ({ts_range})")
        for i, p in enumerate(pkts[:5]):
            d = p["data"]
            print(f"    [{i}] +{p['t']:.3f}s [{p['len']}B] from :{p['sport']}: {d[:30].hex(' ')}")
        if len(pkts) > 5:
            print(f"    ... ({len(pkts) - 5} more)")

    # ---------------------------------------------------------------
    # 3. Drone -> client on ALL ports
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("DRONE -> CLIENT: ALL PORTS")
    print("=" * 80)

    drone_to_client = [p for p in all_packets if p["src"] == "192.168.169.1"]
    by_sport = defaultdict(list)
    for p in drone_to_client:
        key = f"drone:{p['sport']} -> client:{p['dport']}"
        by_sport[key].append(p)

    for key, pkts in sorted(by_sport.items()):
        ts_range = f"{pkts[0]['t']:.2f}s - {pkts[-1]['t']:.2f}s"
        print(f"\n  {key}: {len(pkts)} packets ({ts_range})")
        for i, p in enumerate(pkts[:3]):
            d = p["data"]
            print(f"    [{i}] +{p['t']:.3f}s [{p['len']}B]: {d[:20].hex(' ')}")

    # ---------------------------------------------------------------
    # 4. Video flow timing analysis
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("VIDEO PACKET TIMING (drone:1234 -> client)")
    print("=" * 80)

    video_pkts = [p for p in all_packets
                  if p["src"] == "192.168.169.1" and p["sport"] == 1234]
    print(f"Total video packets: {len(video_pkts)}")

    if video_pkts:
        # Bucket by second
        buckets = defaultdict(int)
        for p in video_pkts:
            sec = int(p["t"])
            buckets[sec] += 1

        print("\nPackets per second:")
        for sec in range(max(buckets.keys()) + 1):
            count = buckets.get(sec, 0)
            bar = "#" * min(count // 5, 60)
            print(f"  {sec:3d}s: {count:5d} pkts  {bar}")

        # Check for gaps
        print("\nGaps > 0.5s in video stream:")
        prev_t = video_pkts[0]["t"]
        for p in video_pkts[1:]:
            gap = p["t"] - prev_t
            if gap > 0.5:
                print(f"  Gap at +{prev_t:.2f}s: {gap:.2f}s")
            prev_t = p["t"]

    # ---------------------------------------------------------------
    # 5. Client -> drone:1234 (video port responses?)
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("CLIENT -> DRONE:1234 (video responses/ACKs)")
    print("=" * 80)

    to_1234 = [p for p in all_packets
               if p["dst"] == "192.168.169.1" and p["dport"] == 1234]
    print(f"Total: {len(to_1234)} packets")
    for i, p in enumerate(to_1234[:20]):
        d = p["data"]
        print(f"  [{i}] +{p['t']:.3f}s [{p['len']}B] from :{p['sport']}: {d[:30].hex(' ')}")

    # ---------------------------------------------------------------
    # 6. Correlate: what does client send around the time video is active?
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("CLIENT ACTIVITY DURING FIRST 5 SECONDS (when video starts)")
    print("=" * 80)

    early_client = [p for p in client_to_drone if p["t"] < 5.0]
    print(f"Client->drone packets in first 5s: {len(early_client)}")

    for p in early_client:
        d = p["data"]
        desc = ""
        if d and d[0] == 0xEF:
            if d[1] == 0x00:
                desc = "HEARTBEAT"
            elif d[1] == 0x20:
                text = d[6:].decode('ascii', errors='replace') if len(d) > 6 else ""
                desc = f"TEXT: {text}"
            elif d[1] == 0x02:
                sub = d[8] if len(d) > 8 else '?'
                desc = f"CTRL sub={sub} [{p['len']}B]"
        else:
            desc = f"NON-EF: {d[:10].hex(' ')}" if d else "EMPTY"

        print(f"  +{p['t']:.3f}s -> :{p['dport']} [{p['len']}B] {desc}")

    # ---------------------------------------------------------------
    # 7. What's the stock app's source port for video reception?
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("VIDEO RECEPTION PORT ANALYSIS")
    print("=" * 80)

    if video_pkts:
        video_dports = set(p["dport"] for p in video_pkts)
        print(f"Video packets received on client port(s): {video_dports}")

        # What does the client send FROM each of these ports?
        for vport in video_dports:
            from_vport = [p for p in client_to_drone if p["sport"] == vport]
            print(f"\n  Packets sent FROM client:{vport} (same port receiving video):")
            print(f"    Total: {len(from_vport)}")
            for i, p in enumerate(from_vport[:10]):
                d = p["data"]
                print(f"    [{i}] +{p['t']:.3f}s -> :{p['dport']} [{p['len']}B]: {d[:20].hex(' ')}")


if __name__ == "__main__":
    paths = [
        "captures/iphone_stock_20260307_093143.pcap",
    ]
    if len(sys.argv) > 1:
        paths.insert(0, sys.argv[1])

    import glob
    paths += glob.glob("captures/*.pcap") + glob.glob("captures/*.pcapng")

    pcap = None
    for p in paths:
        if p and os.path.exists(p):
            pcap = p
            break

    if not pcap:
        print("ERROR: No pcap file found!")
        sys.exit(1)

    analyze(pcap)
