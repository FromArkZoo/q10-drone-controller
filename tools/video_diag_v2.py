#!/usr/bin/env python3
"""
Video diagnostic v2 — sends proper mix of 88B/112B packets with three-state protocol.

The stock app sends a MIX of sub_type=0 (88B) and sub_type=1 (112B) packets,
and transitions through three states:
  1. INIT (first 2.5s): byte16=0x00, seq=0, all zeros
  2. MARKER (2.5-3s): byte16=0x08, seq incrementing, no 0x66 joystick
  3. FULL (3s+): byte16=0x08, 0x66/joystick/0x99

The old video_diag.py only sent 88B all-zero packets, which caused video to stop
after ~1 second. This version matches the stock app pattern.
"""
import socket
import struct
import time
import sys

DRONE_IP = "192.168.169.1"
CLIENT_IP = "192.168.169.3"
CMD_PORT = 8800
SRC_PORT = 54288


def make_ctrl_88(seq=0, state=1):
    """88-byte control packet (sub_type=0)."""
    buf = bytearray(88)
    buf[0] = 0xEF
    buf[1] = 0x02
    struct.pack_into("<H", buf, 2, 88)
    buf[4:8] = b'\x02\x02\x00\x01'
    buf[8] = 0  # sub_type=0
    struct.pack_into("<H", buf, 12, seq)

    if state >= 2:
        # MARKER state: byte16=0x08
        buf[16] = 0x08
    if state >= 3:
        # FULL state: add 0x66 joystick block
        buf[18] = 0x66
        buf[19] = 0x80  # roll center
        buf[20] = 0x80  # pitch center
        buf[21] = 0x80  # throttle center
        buf[22] = 0x80  # yaw center
        buf[23] = 0x40  # trim
        buf[24] = 0x40  # trim
        buf[25] = 0x99  # joystick block end

    buf[82:86] = b'\x32\x4B\x14\x2D'
    return bytes(buf)


def make_ctrl_112(seq=0, state=1, ext_counter=0):
    """112-byte control packet (sub_type=1)."""
    buf = bytearray(112)
    buf[0] = 0xEF
    buf[1] = 0x02
    struct.pack_into("<H", buf, 2, 112)
    buf[4:8] = b'\x02\x02\x00\x01'
    buf[8] = 1  # sub_type=1
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
    # Extended region — bytes 88-91 are a 32-bit LE incrementing counter (critical!)
    struct.pack_into("<I", buf, 88, ext_counter)
    buf[96] = 0x01  # flag byte (stock app always sets this)
    buf[100] = 0x18  # ext_len
    buf[104:108] = b'\xff\xff\xff\xff'
    buf[108:112] = b'\x00\x00\xe0\xff'  # matches stock app at ~3s
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
    print("  Q10 Video Diagnostic v2 (mixed 88B/112B + 3-state)")
    print("=" * 60)

    # Check .3 is available
    try:
        test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        test_sock.bind((CLIENT_IP, 0))
        test_sock.close()
        print(f"  [OK] {CLIENT_IP} is available")
    except OSError:
        print(f"  [FAIL] {CLIENT_IP} not available")
        sys.exit(1)

    # Open socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for buf_size in [4*1024*1024, 2*1024*1024, 1*1024*1024, 512*1024]:
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, buf_size)
            break
        except:
            continue

    actual_buf = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
    print(f"  Socket buffer: {actual_buf // 1024} KB")
    sock.setblocking(False)
    sock.bind((CLIENT_IP, SRC_PORT))
    print(f"  Bound to {CLIENT_IP}:{SRC_PORT}")

    DRONE = (DRONE_IP, CMD_PORT)

    # --- Handshake (matching stock app sequence from pcap) ---
    print("\n--- Handshake ---")

    # Heartbeats (stock app: 200ms apart, sends to both 8800 and 8801)
    sock.sendto(b'\xef\x00\x04\x00', DRONE)
    time.sleep(0.01)
    sock.sendto(b'\xef\x00\x04\x00', (DRONE_IP, 8801))
    time.sleep(0.1)
    sock.sendto(b'\xef\x00\x04\x00', DRONE)
    time.sleep(0.1)
    sock.sendto(b'\xef\x00\x04\x00', DRONE)
    time.sleep(0.03)
    print("  Sent heartbeats (including 8801)")

    # Init control packets: mix of 88B and 112B (state=1, seq=0)
    sock.sendto(make_ctrl_88(0, 1), DRONE)
    time.sleep(0.03)
    sock.sendto(make_ctrl_88(0, 1), DRONE)
    time.sleep(0.03)
    sock.sendto(make_ctrl_88(0, 1), DRONE)
    time.sleep(0.03)
    sock.sendto(make_ctrl_112(0, 1), DRONE)
    time.sleep(0.03)
    sock.sendto(make_ctrl_88(0, 1), DRONE)
    print("  Sent 5 init control (3x88B + 1x112B + 1x88B)")

    # Enable
    time.sleep(0.01)
    sock.sendto(b'\xef\x20\x06\x00\x01\x65', DRONE)
    time.sleep(0.03)
    sock.sendto(make_ctrl_112(0, 1), DRONE)
    time.sleep(0.025)
    print("  Sent ENABLE + 112B")

    # Text commands
    sock.sendto(make_text_cmd(2), DRONE)
    sock.sendto(make_ctrl_88(0, 1), DRONE)
    time.sleep(0.02)
    sock.sendto(make_text_cmd(3), DRONE)
    sock.sendto(make_ctrl_88(0, 1), DRONE)
    time.sleep(0.02)
    sock.sendto(make_text_cmd(106), DRONE)
    time.sleep(0.03)
    sock.sendto(make_ctrl_112(0, 1), DRONE)
    time.sleep(0.03)
    sock.sendto(make_ctrl_112(0, 1), DRONE)
    print("  Sent cmd=2, cmd=3, cmd=106")

    # --- Control loop with 3-state protocol ---
    print("\n--- Monitoring (3-state protocol, mixed 88B/112B at ~35Hz) ---")
    print("  State 1: INIT (0-2.5s) → State 2: MARKER (2.5-3s) → State 3: FULL (3s+)")
    print()

    video_count = 0
    other_count = 0
    start_time = time.time()
    last_video_time = 0
    last_report = start_time
    last_send = start_time
    second_counts = {}
    seq = 0
    ext_counter = 0  # incrementing counter for byte 88 in 112B packets
    pkt_counter = 0  # alternates 88B/112B

    try:
        while True:
            now = time.time()
            elapsed = now - start_time

            # Determine state based on elapsed time
            if elapsed < 2.5:
                state = 1  # INIT: all zeros, seq=0
            elif elapsed < 3.0:
                state = 2  # MARKER: byte16=0x08, seq incrementing
            else:
                state = 3  # FULL: 0x66 joystick block

            # Send control packet at ~35Hz, alternating 88B/112B
            if now - last_send >= 0.028:
                try:
                    if state >= 2:
                        seq += 1

                    # Alternate: roughly 2x 88B, 1x 112B (matching stock app ratio)
                    pkt_counter += 1
                    if pkt_counter % 3 == 0:
                        ext_counter += 1
                        sock.sendto(make_ctrl_112(seq, state, ext_counter), DRONE)
                    else:
                        sock.sendto(make_ctrl_88(seq, state), DRONE)
                except:
                    pass
                last_send = now

            # Receive (drain all available packets)
            for _ in range(50):  # Read up to 50 packets per loop
                try:
                    data, addr = sock.recvfrom(2048)
                    if data and data[0] == 0x93 and len(data) > 100:
                        video_count += 1
                        last_video_time = now
                        sec = int(elapsed)
                        second_counts[sec] = second_counts.get(sec, 0) + 1
                    else:
                        other_count += 1
                        if other_count <= 5:
                            print(f"  Non-video: [{len(data)}B] {data[:20].hex(' ')}")
                except (BlockingIOError, socket.timeout):
                    break

            # Small sleep to prevent CPU spinning
            time.sleep(0.001)

            # Report every second
            if now - last_report >= 1.0:
                gap = now - last_video_time if last_video_time else elapsed
                sec = int(elapsed) - 1
                sec_count = second_counts.get(sec, 0)
                status = "STREAMING" if gap < 1.0 else f"STOPPED ({gap:.1f}s ago)"
                state_name = ["", "INIT", "MARKER", "FULL"][state]
                print(f"  +{elapsed:5.1f}s | video={video_count:5d} | this_sec={sec_count:4d} | "
                      f"seq={seq:5d} | {state_name:6s} | {status}")
                last_report = now

    except KeyboardInterrupt:
        elapsed = time.time() - start_time
        print(f"\n--- Results after {elapsed:.1f}s ---")
        print(f"  Total video packets: {video_count}")
        print(f"  Total other packets: {other_count}")
        if elapsed > 0:
            print(f"  Average rate: {video_count/elapsed:.1f} pkt/s")

        if second_counts:
            print(f"\n  Packets per second:")
            for sec in range(max(second_counts.keys()) + 1):
                c = second_counts.get(sec, 0)
                bar = "#" * min(c // 5, 50)
                print(f"    {sec:3d}s: {c:5d}  {bar}")

    sock.close()


if __name__ == "__main__":
    main()
