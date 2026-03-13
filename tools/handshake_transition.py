#!/usr/bin/env python3
"""
Analyze the exact handshake-to-ongoing transition in the stock app capture.
Focus on the first 30 control packets to see when/how the stock app transitions
from init packets to full joystick packets.
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
                })
            except:
                continue

    # Find first control packet timestamp
    first_ts = None
    for p in all_packets:
        if p["dst"] == "192.168.169.1" and p["dport"] == 8800:
            first_ts = p["ts"]
            break

    if first_ts is None:
        print("No control packets found!")
        return

    # Extract all control packets
    control = []
    for p in all_packets:
        if p["dst"] == "192.168.169.1" and p["dport"] == 8800:
            control.append({"raw": p["data"], "t": p["ts"] - first_ts, "len": len(p["data"])})

    # Also track video packets for correlation
    video = []
    for p in all_packets:
        if p["src"] == "192.168.169.1" and p["sport"] == 1234:
            video.append({"t": p["ts"] - first_ts, "len": len(p["data"])})

    # ---------------------------------------------------------------
    # FIRST 50 control packets: full hex dump of key regions
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("FIRST 50 CONTROL PACKETS (handshake → ongoing transition)")
    print("=" * 80)

    for i, p in enumerate(control[:50]):
        r = p["raw"]
        ptype = ""
        if r[0] == 0xEF:
            if r[1] == 0x00:
                ptype = "HEARTBEAT"
            elif r[1] == 0x20:
                text = r[6:].decode('ascii', errors='replace') if len(r) > 6 else ""
                ptype = f"TEXT({text})"
            elif r[1] == 0x02:
                sub = r[8]
                seq = struct.unpack_from('<H', r, 12)[0] if len(r) > 13 else 0
                b16 = r[16] if len(r) > 16 else 0
                joystick = r[18:26].hex(' ') if len(r) > 25 else "N/A"
                ptype = f"CTRL sub={sub} seq={seq:4d} b16=0x{b16:02x} joy=[{joystick}]"

                # Check for 0x66 marker
                has_66 = "0x66" if (len(r) > 18 and r[18] == 0x66) else "    "
                has_99 = "0x99" if (len(r) > 25 and r[25] == 0x99) else "    "
                ptype += f" {has_66} {has_99}"
        else:
            ptype = f"UNKNOWN(0x{r[0]:02x})"

        # Count video packets received so far
        vid_count = sum(1 for v in video if v["t"] <= p["t"])

        print(f"  [{i:3d}] +{p['t']:.3f}s [{p['len']:4d}B] {ptype}  (vid:{vid_count})")

    # ---------------------------------------------------------------
    # When does 0x66 first appear?
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("TRANSITION ANALYSIS: When does 0x66 joystick block first appear?")
    print("=" * 80)

    first_66 = None
    first_08 = None
    for i, p in enumerate(control):
        r = p["raw"]
        if r[0] != 0xEF or r[1] != 0x02:
            continue
        if len(r) > 16 and r[16] == 0x08 and first_08 is None:
            first_08 = (i, p["t"])
            print(f"  First byte16=0x08: packet [{i}] at +{p['t']:.3f}s")
        if len(r) > 18 and r[18] == 0x66 and first_66 is None:
            first_66 = (i, p["t"])
            print(f"  First 0x66 marker: packet [{i}] at +{p['t']:.3f}s")
            # Show full packet
            print(f"    Full packet [{len(r)}B]:")
            for offset in range(0, min(len(r), 128), 16):
                chunk = r[offset:offset+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                print(f"      {offset:04x}: {hex_part}")
            break

    if first_08 and first_66:
        gap = first_66[1] - first_08[1]
        pkt_gap = first_66[0] - first_08[0]
        print(f"\n  Time from 0x08 to 0x66: {gap:.3f}s ({pkt_gap} packets)")

    # ---------------------------------------------------------------
    # Stock app packet at +1s, +2s, +5s, +10s
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("SAMPLE PACKETS AT KEY TIMEPOINTS (full bytes 0-87)")
    print("=" * 80)

    for target_t in [0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0]:
        # Find closest EF 02 packet to target time
        closest = None
        for p in control:
            if p["raw"][0] == 0xEF and p["raw"][1] == 0x02 and p["t"] >= target_t:
                closest = p
                break
        if closest:
            r = closest["raw"]
            print(f"\n  At +{closest['t']:.3f}s [{len(r)}B]:")
            for offset in range(0, min(len(r), 160), 16):
                chunk = r[offset:offset+16]
                hex_part = ' '.join(f'{b:02x}' for b in chunk)
                ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
                print(f"    {offset:04x}: {hex_part:48s}  {ascii_part}")

    # ---------------------------------------------------------------
    # Byte-by-byte: what changes over time in control packets?
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("BYTE EVOLUTION: bytes 0-87 across ALL 88-byte packets")
    print("=" * 80)

    ctrl_88 = [p for p in control if p["raw"][0] == 0xEF and p["raw"][1] == 0x02
               and len(p["raw"]) == 88]

    if ctrl_88:
        print(f"Total 88-byte control packets: {len(ctrl_88)}")
        # For each byte position, show unique values over time
        for pos in range(88):
            vals = [(p["t"], p["raw"][pos]) for p in ctrl_88]
            unique = sorted(set(v for _, v in vals))
            if len(unique) > 1 and pos not in (2, 3, 12, 13):  # Skip length and seq
                changes = []
                prev_val = vals[0][1]
                for t, v in vals[1:]:
                    if v != prev_val:
                        changes.append((t, v))
                        prev_val = v
                first_change_t = changes[0][0] if changes else 0
                print(f"  Byte {pos:3d}: {len(unique)} values {[f'0x{v:02x}' for v in unique[:8]]}  "
                      f"first change at +{first_change_t:.3f}s")

    # ---------------------------------------------------------------
    # Same for 112-byte packets
    # ---------------------------------------------------------------
    print("\n" + "=" * 80)
    print("BYTE EVOLUTION: bytes 0-111 across 112+ byte sub_type=1 packets")
    print("=" * 80)

    ctrl_112 = [p for p in control if p["raw"][0] == 0xEF and p["raw"][1] == 0x02
                and p["raw"][8] == 1 and len(p["raw"]) >= 112]

    if ctrl_112:
        print(f"Total sub_type=1 packets (112+ bytes): {len(ctrl_112)}")
        sizes = sorted(set(len(p["raw"]) for p in ctrl_112))
        print(f"Sizes seen: {sizes}")

        for pos in range(min(112, min(len(p["raw"]) for p in ctrl_112))):
            vals = [(p["t"], p["raw"][pos]) for p in ctrl_112]
            unique = sorted(set(v for _, v in vals))
            if len(unique) > 1 and pos not in (2, 3, 12, 13, 88, 89, 90, 91):
                changes = []
                prev_val = vals[0][1]
                for t, v in vals[1:]:
                    if v != prev_val:
                        changes.append((t, v))
                        prev_val = v
                first_change_t = changes[0][0] if changes else 0
                print(f"  Byte {pos:3d}: {len(unique)} values {[f'0x{v:02x}' for v in unique[:8]]}  "
                      f"first change at +{first_change_t:.3f}s")


if __name__ == "__main__":
    paths = ["captures/iphone_stock_20260307_093143.pcap"]
    if len(sys.argv) > 1:
        paths.insert(0, sys.argv[1])

    import glob
    paths += glob.glob("captures/*.pcap")

    pcap = None
    for p in paths:
        if p and os.path.exists(p):
            pcap = p
            break

    if not pcap:
        print("ERROR: No pcap file found!")
        sys.exit(1)

    analyze(pcap)
