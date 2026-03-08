#!/usr/bin/env python3
"""
Analyze a pcap capture from the stock HASAKEE Q10 app.
Extracts the exact packet format used for drone control.

Usage: python3 tools/analyze_capture.py captures/iphone_stock_*.pcap
"""
import sys
from collections import Counter

try:
    from scapy.all import rdpcap, UDP, IP, Raw
except ImportError:
    print("Installing scapy...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "scapy", "--break-system-packages", "-q"])
    from scapy.all import rdpcap, UDP, IP, Raw

def analyze(pcap_file):
    print(f"\nLoading {pcap_file}...")
    pkts = rdpcap(pcap_file)
    print(f"Total packets: {len(pkts)}")

    udp_pkts = [p for p in pkts if p.haslayer(UDP) and p.haslayer(Raw)]
    print(f"UDP packets with payload: {len(udp_pkts)}")

    # ---- Traffic flows ----
    print("\n" + "=" * 70)
    print("TRAFFIC FLOWS")
    print("=" * 70)
    flows = Counter()
    for p in udp_pkts:
        key = f"{p[IP].src}:{p[UDP].sport} -> {p[IP].dst}:{p[UDP].dport}"
        flows[key] += 1
    for flow, count in flows.most_common(20):
        print(f"  {flow:55s} {count:5d} packets")

    # ---- Identify control traffic (client -> drone, not video) ----
    print("\n" + "=" * 70)
    print("OUTGOING PACKETS (phone -> drone, likely control)")
    print("=" * 70)

    # Find packets NOT starting with 0x93 (video) and going to drone IPs
    control_pkts = []
    for p in udp_pkts:
        raw = bytes(p[Raw].load)
        dst = p[IP].dst
        # Drone-bound traffic (not video responses)
        if dst in ("192.168.169.1", "192.168.0.1") and p[UDP].dport != 53:
            control_pkts.append({
                "raw": raw,
                "len": len(raw),
                "sport": p[UDP].sport,
                "dport": p[UDP].dport,
                "time": float(p.time),
            })

    if not control_pkts:
        # Try any non-video outgoing
        for p in udp_pkts:
            raw = bytes(p[Raw].load)
            if raw[0:1] != b'\x93' and len(raw) < 500:
                control_pkts.append({
                    "raw": raw,
                    "len": len(raw),
                    "sport": p[UDP].sport,
                    "dport": p[UDP].dport,
                    "dst": p[IP].dst,
                    "time": float(p.time),
                })

    print(f"\nFound {len(control_pkts)} potential control packets")

    if not control_pkts:
        print("No control packets found!")
        return

    # Group by length
    by_len = Counter(p["len"] for p in control_pkts)
    print("\nPacket lengths:")
    for length, count in by_len.most_common(10):
        print(f"  {length:4d} bytes: {count:5d} packets")

    # Group by destination port
    by_port = Counter(p["dport"] for p in control_pkts)
    print("\nDestination ports:")
    for port, count in by_port.most_common(10):
        print(f"  port {port:5d}: {count:5d} packets")

    # Group by first byte
    by_first = Counter(p["raw"][0] for p in control_pkts)
    print("\nFirst byte values:")
    for byte, count in by_first.most_common(10):
        print(f"  0x{byte:02x}: {count:5d} packets")

    # ---- Detailed hex dumps ----
    print("\n" + "=" * 70)
    print("FIRST 20 CONTROL PACKETS (full hex)")
    print("=" * 70)
    for i, p in enumerate(control_pkts[:20]):
        raw = p["raw"]
        hexdump = raw.hex(' ')
        port_info = f"-> :{p['dport']}"
        print(f"\n  [{i:3d}] {p['len']:4d}B {port_info}")
        # Print in rows of 16 bytes
        for offset in range(0, len(raw), 16):
            chunk = raw[offset:offset+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"        {offset:04x}: {hex_part:<48s}  {ascii_part}")

    # ---- Look for changing bytes (joystick data) ----
    print("\n" + "=" * 70)
    print("BYTE VARIATION ANALYSIS (which bytes change = joystick data)")
    print("=" * 70)

    # Get most common packet length
    common_len = by_len.most_common(1)[0][0]
    same_len = [p["raw"] for p in control_pkts if p["len"] == common_len]

    if len(same_len) > 10:
        print(f"\nAnalyzing {len(same_len)} packets of length {common_len}:")
        for byte_pos in range(min(common_len, 30)):
            values = set(p[byte_pos] for p in same_len)
            val_range = max(values) - min(values)
            sample = sorted(values)[:8]
            sample_str = ' '.join(f'{v:02x}' for v in sample)
            if len(values) > 1:
                marker = " <-- VARIES" + (f" (range={val_range})" if val_range > 10 else "")
            else:
                marker = f"  (constant: 0x{sample[0]:02x})"
            print(f"  Byte {byte_pos:2d}: {len(values):3d} unique values  [{sample_str}]{marker}")

    # ---- Show packets around likely events ----
    print("\n" + "=" * 70)
    print("UNIQUE PACKET TYPES (deduplicated)")
    print("=" * 70)
    seen = set()
    for p in control_pkts:
        raw = p["raw"]
        # Normalize varying bytes to find unique packet types
        key = (len(raw), raw[0] if raw else 0)
        if key not in seen:
            seen.add(key)
            print(f"\n  Length {p['len']}, first byte 0x{raw[0]:02x}:")
            print(f"    {raw[:40].hex(' ')}")

    print("\n" + "=" * 70)
    print("ANALYSIS COMPLETE")
    print("=" * 70)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)
    analyze(sys.argv[1])
