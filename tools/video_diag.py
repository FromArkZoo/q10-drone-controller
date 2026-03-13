#!/usr/bin/env python3
"""
Minimal video stream diagnostic — bypasses all app logic.
Tests whether the Mac can sustain receiving video packets from the drone.

Run while connected to drone WiFi:
    python tools/video_diag.py

If this also stops at ~250 packets, the issue is Mac networking (firewall, WiFi power save, etc.)
If this gets continuous packets, the issue is in our app code.
"""
import socket
import struct
import time
import sys
import os
import threading

DRONE_IP = "192.168.169.1"
CLIENT_IP = "192.168.169.3"
CMD_PORT = 8800
SRC_PORT = 54288

def make_ctrl_88():
    """Minimal 88-byte all-zero control packet (matching stock app Phase 1)."""
    buf = bytearray(88)
    buf[0] = 0xEF
    buf[1] = 0x02
    struct.pack_into("<H", buf, 2, 88)
    buf[4:8] = b'\x02\x02\x00\x01'
    buf[82:86] = b'\x32\x4B\x14\x2D'
    return bytes(buf)

def make_ctrl_112():
    """Minimal 112-byte all-zero control packet."""
    buf = bytearray(112)
    buf[0] = 0xEF
    buf[1] = 0x02
    struct.pack_into("<H", buf, 2, 112)
    buf[4:8] = b'\x02\x02\x00\x01'
    buf[8] = 1  # sub_type=1
    buf[82:86] = b'\x32\x4B\x14\x2D'
    buf[100] = 0x18
    buf[104:112] = b'\xff' * 8
    return bytes(buf)

def make_text_cmd(cmd_id):
    text = f"<i=2^bf_ssid=cmd={cmd_id}>".encode("ascii")
    total_len = 4 + 2 + len(text)
    buf = bytearray()
    buf.append(0xEF)
    buf.append(0x20)
    buf += struct.pack("<H", total_len)
    buf.append(0x01)
    buf.append(0x67)
    buf += text
    return bytes(buf)

def main():
    print("=" * 60)
    print("  Q10 Video Stream Diagnostic")
    print("=" * 60)

    # Check .3 is available
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.bind((CLIENT_IP, 0))
        test_sock.close()
        print(f"  [OK] {CLIENT_IP} is available")
    except OSError:
        print(f"  [FAIL] {CLIENT_IP} not available — run: sudo bash setup_network.sh")
        sys.exit(1)

    # Open socket with LARGE receive buffer
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Maximize receive buffer
    for buf_size in [4*1024*1024, 2*1024*1024, 1*1024*1024, 512*1024]:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
            break
        except:
            continue

    actual_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    print(f"  Socket receive buffer: {actual_buf} bytes ({actual_buf//1024} KB)")

    sock.settimeout(0.5)  # Short timeout for fast polling
    sock.bind((CLIENT_IP, SRC_PORT))
    print(f"  Bound to {CLIENT_IP}:{SRC_PORT}")

    DRONE = (DRONE_IP, CMD_PORT)
    ctrl88 = make_ctrl_88()
    ctrl112 = make_ctrl_112()

    # --- Handshake (exact stock app sequence) ---
    print("\n--- Handshake ---")

    # 3 heartbeats
    for i in range(3):
        sock.sendto(b'\xef\x00\x04\x00', DRONE)
        time.sleep(0.1)
    print("  Sent 3 heartbeats")

    # Init control packets
    for _ in range(3):
        sock.sendto(ctrl88, DRONE)
        time.sleep(0.03)
    sock.sendto(ctrl112, DRONE)
    time.sleep(0.03)
    sock.sendto(ctrl88, DRONE)
    print("  Sent 5 init control packets")

    # Enable
    sock.sendto(b'\xef\x20\x06\x00\x01\x65', DRONE)
    time.sleep(0.03)
    sock.sendto(ctrl112, DRONE)
    time.sleep(0.025)
    print("  Sent ENABLE")

    # cmd=2, cmd=3, cmd=106
    sock.sendto(make_text_cmd(2), DRONE)
    sock.sendto(ctrl88, DRONE)
    time.sleep(0.02)
    sock.sendto(make_text_cmd(3), DRONE)
    sock.sendto(ctrl88, DRONE)
    time.sleep(0.02)
    sock.sendto(make_text_cmd(106), DRONE)
    time.sleep(0.05)
    print("  Sent cmd=2, cmd=3, cmd=106")

    # --- Receive + control loop ---
    print("\n--- Monitoring video packets (Ctrl+C to stop) ---")
    print(f"  Also sending 33Hz all-zero control packets (matching stock app Phase 1)")
    print()

    video_count = 0
    other_count = 0
    start_time = time.time()
    last_video_time = 0
    last_report = start_time
    last_send = start_time
    second_counts = {}  # packets per second bucket

    try:
        while True:
            now = time.time()

            # Send control packet at ~33Hz
            if now - last_send >= 0.03:
                try:
                    sock.sendto(ctrl88, DRONE)
                except:
                    pass
                last_send = now

            # Try to receive
            try:
                data, addr = sock.recvfrom(2048)
                if data and data[0] == 0x93 and len(data) > 100:
                    video_count += 1
                    last_video_time = now
                    sec = int(now - start_time)
                    second_counts[sec] = second_counts.get(sec, 0) + 1
                else:
                    other_count += 1
                    if other_count <= 5:
                        print(f"  Non-video: [{len(data)}B] {data[:20].hex(' ')}")
            except socket.timeout:
                pass

            # Report every second
            if now - last_report >= 1.0:
                elapsed = now - start_time
                gap = now - last_video_time if last_video_time else 0
                sec = int(elapsed) - 1
                sec_count = second_counts.get(sec, 0)
                status = "STREAMING" if gap < 1.0 else f"STOPPED ({gap:.1f}s ago)"
                print(f"  +{elapsed:5.1f}s | video={video_count:5d} | this_sec={sec_count:4d} | "
                      f"other={other_count} | {status}")
                last_report = now

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n--- Results after {elapsed:.1f}s ---")
        print(f"  Total video packets: {video_count}")
        print(f"  Total other packets: {other_count}")
        print(f"  Average rate: {video_count/elapsed:.1f} pkt/s" if elapsed > 0 else "")

        if second_counts:
            print(f"\n  Packets per second:")
            for sec in range(max(second_counts.keys()) + 1):
                c = second_counts.get(sec, 0)
                bar = "#" * min(c // 5, 50)
                print(f"    {sec:3d}s: {c:5d}  {bar}")

    sock.close()


if __name__ == "__main__":
    main()
