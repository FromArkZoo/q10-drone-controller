#!/usr/bin/env python3
"""
Compare stock app packets from pcap with our generated packets
at the same time offset. Shows byte-by-byte differences.
"""
import socket
import struct
import sys
import os

try:
    import dpkt
except ImportError:
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "dpkt", "--break-system-packages", "-q"])
    import dpkt

DRONE_IP = "192.168.169.1"


def load_control_packets(pcap_path):
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
                if dst_ip == DRONE_IP and udp.dport == 8800:
                    if first_ts is None:
                        first_ts = ts
                    data = bytes(udp.data)
                    if data[0] == 0xEF and data[1] == 0x02:
                        packets.append({
                            "t": ts - first_ts,
                            "data": data,
                            "len": len(data),
                            "sub_type": data[8],
                        })
            except:
                continue
    return packets


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


def compare_packets(label, stock, ours):
    print(f"\n{'='*70}")
    print(f"  {label}")
    print(f"  Stock: {len(stock)}B  Ours: {len(ours)}B")
    print(f"{'='*70}")

    max_len = max(len(stock), len(ours))
    diffs = []

    for i in range(max_len):
        s = stock[i] if i < len(stock) else None
        o = ours[i] if i < len(ours) else None
        if s != o:
            diffs.append(i)

    if not diffs:
        print("  IDENTICAL!")
        return

    print(f"  {len(diffs)} bytes differ:")
    print(f"  {'Byte':>6s}  {'Stock':>8s}  {'Ours':>8s}  Note")
    print(f"  {'-'*6}  {'-'*8}  {'-'*8}  {'-'*30}")

    byte_names = {
        0: "magic", 1: "type", 2: "len_lo", 3: "len_hi",
        4: "hdr0", 5: "hdr1", 6: "hdr2", 7: "hdr3",
        8: "sub_type", 9: "?", 10: "?", 11: "?",
        12: "seq_lo", 13: "seq_hi", 14: "?", 15: "?",
        16: "b16_marker", 17: "?",
        18: "joy_start(0x66)", 19: "roll", 20: "pitch",
        21: "throttle", 22: "yaw", 23: "trim1", 24: "trim2",
        25: "joy_end(0x99)",
        82: "sig0", 83: "sig1", 84: "sig2", 85: "sig3",
        100: "ext_len", 104: "ext_data",
    }

    for i in diffs:
        s = stock[i] if i < len(stock) else "N/A"
        o = ours[i] if i < len(ours) else "N/A"
        s_str = f"0x{s:02x}" if isinstance(s, int) else s
        o_str = f"0x{o:02x}" if isinstance(o, int) else o
        name = byte_names.get(i, "")
        # Skip seq differences (expected)
        skip = " (expected)" if i in (12, 13) else ""
        print(f"  {i:6d}  {s_str:>8s}  {o_str:>8s}  {name}{skip}")

    # Show full hex dump for context
    print(f"\n  Stock packet hex dump:")
    for offset in range(0, min(len(stock), 112), 16):
        chunk = stock[offset:offset+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        diff_markers = ''.join('^' if (offset+j) in diffs else ' '
                              for j in range(len(chunk)))
        print(f"    {offset:04x}: {hex_part}")
        if any(c == '^' for c in diff_markers):
            padding = '    ' + '      '  # match offset prefix
            print(f"          {' '.join(diff_markers.replace(' ', ' ').split())}")

    print(f"\n  Our packet hex dump:")
    for offset in range(0, min(len(ours), 112), 16):
        chunk = ours[offset:offset+16]
        hex_part = ' '.join(f'{b:02x}' for b in chunk)
        print(f"    {offset:04x}: {hex_part}")


def main():
    paths = [sys.argv[1] if len(sys.argv) > 1 else None]
    import glob
    paths += glob.glob("captures/*.pcap") + glob.glob("*.pcap")
    pcap_path = None
    for p in paths:
        if p and os.path.exists(p):
            pcap_path = p
            break
    if not pcap_path:
        print("ERROR: No pcap file found!")
        sys.exit(1)

    packets = load_control_packets(pcap_path)
    print(f"Loaded {len(packets)} control packets")

    # Compare at several time points
    for target_t in [0.5, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0]:
        # Find stock packet closest to target time
        for p in packets:
            if p["t"] >= target_t:
                stock = p
                break
        else:
            continue

        sub = stock["sub_type"]
        seq = struct.unpack_from("<H", stock["data"], 12)[0]

        # Determine state
        b16 = stock["data"][16]
        has_66 = len(stock["data"]) > 18 and stock["data"][18] == 0x66

        if b16 == 0x00:
            state = 1
        elif has_66:
            state = 3
        else:
            state = 2

        state_name = ["", "INIT", "MARKER", "FULL"][state]

        # Generate equivalent packet
        if sub == 0:
            ours = make_ctrl_88(seq, state)
        else:
            ours = make_ctrl_112(seq, state)

        label = (f"t={stock['t']:.3f}s  sub_type={sub}  seq={seq}  "
                f"state={state_name}  stock_len={len(stock['data'])}B")
        compare_packets(label, stock["data"], ours)


if __name__ == "__main__":
    main()
