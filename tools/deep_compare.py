#!/usr/bin/env python3
"""
Deep byte-by-byte comparison of stock app control packets.
Focuses on ONGOING packets (after handshake) to find what keeps video alive.
"""
import sys
import os
import struct
import socket

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

    # Extract all control packets (phone -> drone on port 8800)
    control = []
    first_ts = None
    for p in all_packets:
        if p["dst"] != "192.168.169.1" or p["dport"] != 8800:
            continue
        raw = p["data"]
        if not raw or raw[0] != 0xEF:
            continue
        if first_ts is None:
            first_ts = p["ts"]
        control.append({"raw": raw, "len": len(raw), "ts": p["ts"] - first_ts})

    print(f"Total EF control packets to 8800: {len(control)}")

    # Separate by type
    by_type = {}
    for p in control:
        r = p["raw"]
        if r[1] == 0x00:
            ptype = "heartbeat"
        elif r[1] == 0x20:
            ptype = f"text_cmd"
        elif r[1] == 0x02:
            sub = r[8]
            ptype = f"ctrl_sub{sub}_{p['len']}B"
        else:
            ptype = f"type_0x{r[1]:02x}"
        p["ptype"] = ptype
        by_type.setdefault(ptype, []).append(p)

    print("\nPacket type distribution:")
    for ptype, pkts_list in sorted(by_type.items()):
        ts_range = f"{pkts_list[0]['ts']:.1f}s - {pkts_list[-1]['ts']:.1f}s"
        print(f"  {ptype:25s}: {len(pkts_list):5d} packets  ({ts_range})")

    # Focus on 112-byte sub_type=1 packets (the ones with extended fields)
    print("\n" + "=" * 80)
    print("DETAILED ANALYSIS: 112-byte sub_type=1 packets (extended fields)")
    print("=" * 80)

    sub1 = by_type.get("ctrl_sub1_112B", [])
    if not sub1:
        print("No 112-byte sub_type=1 packets found!")
        # Try other sizes
        for k, v in by_type.items():
            if "sub1" in k:
                print(f"  Found: {k}: {len(v)} packets")
                sub1 = v
                break

    if sub1:
        print(f"\n{len(sub1)} packets. First 10 with full hex of bytes 82-111:")
        for i, p in enumerate(sub1[:10]):
            r = p["raw"]
            print(f"\n  [{i}] +{p['ts']:.3f}s  seq={struct.unpack_from('<H', r, 12)[0]}")
            # Bytes 16-25 (joystick block)
            print(f"    Joystick [16:26]: {r[16:26].hex(' ')}")
            # Bytes 82-111 (extended)
            print(f"    DevSig   [82:86]: {r[82:86].hex(' ')}")
            print(f"    Extended [86:112]: {r[86:112].hex(' ')}")
            # Parse extended fields
            if len(r) >= 112:
                seq2 = struct.unpack_from('<I', r, 88)[0]
                flag = r[96]
                marker = r[100]
                sensor = r[104:112]
                print(f"    -> seq2={seq2}, flag={flag}, marker=0x{marker:02x}, sensor={sensor.hex(' ')}")

        # Now look at ONGOING packets (after 5 seconds = well past handshake)
        late = [p for p in sub1 if p["ts"] > 5.0]
        print(f"\n\nONGOING packets (after 5s): {len(late)}")
        if late:
            print("First 10:")
            for i, p in enumerate(late[:10]):
                r = p["raw"]
                seq = struct.unpack_from('<H', r, 12)[0]
                print(f"\n  [{i}] +{p['ts']:.3f}s  seq={seq}")
                print(f"    Joystick [16:26]: {r[16:26].hex(' ')}")
                print(f"    Extended [86:112]: {r[86:112].hex(' ')}")
                if len(r) >= 112:
                    seq2 = struct.unpack_from('<I', r, 88)[0]
                    flag = r[96]
                    marker = r[100]
                    sensor = r[104:112]
                    print(f"    -> seq2={seq2}, flag={flag}, marker=0x{marker:02x}, sensor={sensor.hex(' ')}")

    # Now look at ALL sub_types in ongoing phase
    print("\n" + "=" * 80)
    print("ALL PACKET TYPES IN ONGOING PHASE (after 5s)")
    print("=" * 80)

    late_all = [p for p in control if p["ts"] > 5.0]
    print(f"\nTotal packets after 5s: {len(late_all)}")

    by_type_late = {}
    for p in late_all:
        by_type_late.setdefault(p["ptype"], []).append(p)

    for ptype, pkts_list in sorted(by_type_late.items()):
        print(f"\n  {ptype}: {len(pkts_list)} packets")
        for i, p in enumerate(pkts_list[:3]):
            r = p["raw"]
            print(f"    [{i}] +{p['ts']:.3f}s [{len(r)}B]: {r[:30].hex(' ')} ...")
            if len(r) >= 86:
                print(f"         [82:86]={r[82:86].hex(' ')} [86:]={r[86:].hex(' ')}")

    # CRITICAL: Check for ANY bytes that differ between handshake and ongoing packets
    print("\n" + "=" * 80)
    print("BYTE-BY-BYTE COMPARISON: handshake vs ongoing 88-byte packets")
    print("=" * 80)

    sub0 = by_type.get("ctrl_sub0_88B", [])
    if sub0:
        early0 = [p for p in sub0 if p["ts"] < 2.0]
        late0 = [p for p in sub0 if p["ts"] > 5.0]
        print(f"  Early (handshake): {len(early0)} packets")
        print(f"  Late (ongoing): {len(late0)} packets")

        if early0 and late0:
            # Compare byte by byte
            print("\n  Byte-by-byte differences:")
            for pos in range(min(88, min(len(early0[0]["raw"]), len(late0[0]["raw"])))):
                early_vals = set(p["raw"][pos] for p in early0)
                late_vals = set(p["raw"][pos] for p in late0[:50])
                all_vals = early_vals | late_vals
                if len(all_vals) > 1:
                    e_sample = sorted(early_vals)[:5]
                    l_sample = sorted(late_vals)[:5]
                    print(f"    Byte {pos:3d}: early={[f'0x{v:02x}' for v in e_sample]}  "
                          f"late={[f'0x{v:02x}' for v in l_sample]}")

    # Check for sub_type 3 packets
    print("\n" + "=" * 80)
    print("SUB_TYPE 3 PACKETS (rare, potentially video keepalive)")
    print("=" * 80)

    for k, v in by_type.items():
        if "sub3" in k:
            print(f"\n{k}: {len(v)} packets")
            for i, p in enumerate(v):
                r = p["raw"]
                print(f"\n  [{i}] +{p['ts']:.3f}s [{len(r)}B]")
                for offset in range(0, min(len(r), 160), 16):
                    chunk = r[offset:offset+16]
                    hex_part = ' '.join(f'{b:02x}' for b in chunk)
                    print(f"    {offset:04x}: {hex_part}")

    # Check for text commands after handshake
    print("\n" + "=" * 80)
    print("TEXT COMMANDS (timing)")
    print("=" * 80)
    text_cmds = by_type.get("text_cmd", [])
    for i, p in enumerate(text_cmds):
        r = p["raw"]
        text = r[6:].decode('ascii', errors='replace')
        print(f"  [{i}] +{p['ts']:.3f}s: {text}")

    # Check for packets to port 8801
    print("\n" + "=" * 80)
    print("PACKETS TO PORT 8801")
    print("=" * 80)
    port8801 = []
    for p in all_packets:
        if p["dst"] == "192.168.169.1" and p["dport"] == 8801:
            port8801.append({"raw": p["data"], "ts": p["ts"] - first_ts})

    print(f"Total: {len(port8801)} packets")
    for i, p in enumerate(port8801):
        print(f"  [{i}] +{p['ts']:.3f}s [{len(p['raw'])}B]: {p['raw'].hex(' ')}")

    # CRITICAL: Compute what our packets look like vs stock app
    print("\n" + "=" * 80)
    print("OUR PACKETS vs STOCK APP (side-by-side)")
    print("=" * 80)

    # Build what our _control_packet(sub_type=1) would produce
    our_pkt = bytearray(112)
    our_pkt[0] = 0xEF
    our_pkt[1] = 0x02
    struct.pack_into("<H", our_pkt, 2, 112)
    our_pkt[4:8] = bytes([0x02, 0x02, 0x00, 0x01])
    our_pkt[8] = 1  # sub_type
    # seq at 12-13 (varies)
    our_pkt[16] = 0x08
    our_pkt[18] = 0x66
    our_pkt[19] = 0x80  # roll center
    our_pkt[20] = 0x80  # pitch center
    our_pkt[21] = 0x80  # throttle center
    our_pkt[22] = 0x80  # yaw center
    our_pkt[23] = 0x40  # trim
    our_pkt[24] = 0x40  # trim
    our_pkt[25] = 0x99
    our_pkt[82:86] = bytes([0x32, 0x4B, 0x14, 0x2D])
    # Extended (our new additions)
    struct.pack_into("<I", our_pkt, 88, 0)  # seq2
    our_pkt[96] = 0  # alt flag
    our_pkt[100] = 0x18
    our_pkt[104:112] = bytes([0xFF] * 8)

    # Compare with first ongoing stock app 112-byte packet
    stock_ongoing = [p for p in sub1 if p["ts"] > 5.0]
    if stock_ongoing:
        stock_pkt = stock_ongoing[0]["raw"]
        print(f"\nComparing our 112-byte packet vs stock app (first ongoing):")
        print(f"{'Byte':>6} {'Ours':>6} {'Stock':>6} {'Match':>6}")
        print("-" * 30)
        for pos in range(min(112, len(stock_pkt))):
            ours = our_pkt[pos]
            theirs = stock_pkt[pos]
            match = "  OK" if ours == theirs else " DIFF"
            # Skip seq counters (12-13, 88-91) and joystick values (19-22)
            if pos in (12, 13, 88, 89, 90, 91):
                match = " (seq)"
            elif pos in (19, 20, 21, 22):
                match = " (joy)"
            elif pos == 96:
                match = " (flag)"
            if ours != theirs or pos < 26 or pos >= 82:
                print(f"  {pos:4d}  0x{ours:02x}  0x{theirs:02x}  {match}")

    # Also compare 88-byte packets
    sub0_late = [p for p in sub0 if p["ts"] > 5.0] if sub0 else []
    if sub0_late:
        our88 = bytearray(88)
        our88[0] = 0xEF
        our88[1] = 0x02
        struct.pack_into("<H", our88, 2, 88)
        our88[4:8] = bytes([0x02, 0x02, 0x00, 0x01])
        our88[8] = 0  # sub_type
        our88[16] = 0x08
        our88[18] = 0x66
        our88[19] = 0x80
        our88[20] = 0x80
        our88[21] = 0x80
        our88[22] = 0x80
        our88[23] = 0x40
        our88[24] = 0x40
        our88[25] = 0x99
        our88[82:86] = bytes([0x32, 0x4B, 0x14, 0x2D])

        stock88 = sub0_late[0]["raw"]
        print(f"\n\nComparing our 88-byte packet vs stock app (first ongoing):")
        print(f"{'Byte':>6} {'Ours':>6} {'Stock':>6} {'Match':>6}")
        print("-" * 30)
        for pos in range(min(88, len(stock88))):
            ours = our88[pos]
            theirs = stock88[pos]
            match = "  OK" if ours == theirs else " DIFF"
            if pos in (12, 13):
                match = " (seq)"
            elif pos in (19, 20, 21, 22):
                match = " (joy)"
            if ours != theirs or pos < 26 or pos >= 82:
                print(f"  {pos:4d}  0x{ours:02x}  0x{theirs:02x}  {match}")


if __name__ == "__main__":
    # Find pcap
    paths = [
        "captures/iphone_stock_20260307_093143.pcap",
        os.path.expanduser("~/iphone_stock_20260307_093143.pcap"),
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
