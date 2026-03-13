#!/usr/bin/env python3
"""
AVIALOGIC Q10 Drone Controller
===============================
Web-based controller for the Q10/HASAKEE Q10 mini drone.
Protocol reverse-engineered from iPhone stock app packet captures.

Usage:
    pip install flask
    python q10_controller.py

Then open http://localhost:5050 in your browser.
You must be connected to the drone's WiFi hotspot first.
"""

import socket
import struct
import threading
import time
import json
import logging
import io
from flask import Flask, render_template_string, jsonify, request, Response

import cv2
import numpy as np

from autopilot.video_pipeline import VideoDecoder
from autopilot.obstacle_detector import ObstacleDetector
from autopilot.autopilot_controller import AutopilotController
try:
    from ml.data_collector import DataCollector
except ImportError:
    DataCollector = None

# ---------------------------------------------------------------------------
# Protocol constants (reverse-engineered from stock HASAKEE Q10 app)
# ---------------------------------------------------------------------------
DRONE_IP = "192.168.169.1"
COMMAND_PORT = 8800
VIDEO_PORT = 8801           # Second port for heartbeats (stock app sends to both)
CONTROL_RATE = 0.03         # ~33 Hz (30ms) — stock app sends at ~35Hz

# The stock iPhone app sends from 192.168.169.3.
# When a Mac connects to the drone WiFi it typically gets .2 instead of .3.
# The drone firmware appears to only accept control from .3.
# Run `sudo bash setup_network.sh` to add .3 as an alias on your WiFi interface.
CLIENT_IP = "192.168.169.3"

# Stock app source port for command socket (from capture)
STOCK_SOURCE_PORT = 54288

# Stream init / heartbeat (4 bytes)
STREAM_INIT = bytes([0xEF, 0x00, 0x04, 0x00])

# Enable command (6 bytes)
ENABLE_CMD = bytes([0xEF, 0x20, 0x06, 0x00, 0x01, 0x65])

# Device signature (from stock app captures, bytes 82-85 of 88-byte packets)
DEVICE_SIG = bytes([0x32, 0x4B, 0x14, 0x2D])


# ---------------------------------------------------------------------------
# Drone controller
# ---------------------------------------------------------------------------

class Q10Controller:
    def __init__(self, drone_ip=DRONE_IP, command_port=COMMAND_PORT):
        self.drone_ip = drone_ip
        self.command_port = command_port
        self.sock = None
        self.sock2 = None  # Second socket for port 8801 heartbeats
        self.connected = False
        self.armed = False
        self._handshake_done = False  # Track if handshake is complete
        self._joystick_active = False  # True when full joystick block (0x66...0x99) should be sent

        # Joystick state
        # Roll/Pitch/Yaw: centered at 0x80 (128)
        # Throttle: centered at 0x80 (128) like other axes
        self.roll = 0x80
        self.pitch = 0x80
        self.throttle = 0x80      # Center — joystick default position
        self.yaw = 0x80

        # Trim offsets — applied to joystick center values
        # Positive pitch_trim = push forward (counteract backward drift)
        # Positive roll_trim = push right (counteract left drift)
        # These offset the 0x80 center: e.g. pitch_trim=10 means center becomes 0x76 (more forward)
        self.pitch_trim = 0
        self.roll_trim = 0

        # Trim bytes in protocol (bytes 23-24 of control packet)
        # Stock app uses 0x40 for both — these may also affect trim
        self.proto_trim_roll = 0x40
        self.proto_trim_pitch = 0x40

        # Sequence counter for EF 02 packets
        self._seq = 0
        # Secondary sequence counter (bytes 88-91 in 112+ byte packets)
        self._seq2 = 0

        # Pending text commands
        self._pending_text_cmds = []

        self._control_thread = None
        self._heartbeat_thread = None
        self._rx_thread = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

        self.video_packets = 0
        self.log = logging.getLogger("Q10")

        # Autopilot subsystem
        self.video_decoder = VideoDecoder()
        self.autopilot = AutopilotController(self, self.video_decoder)

    # -- socket helpers -----------------------------------------------------

    def _open_socket(self):
        if self.sock is None:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # Maximize receive buffer for video packets (~1080B each)
            try:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
            except OSError:
                pass
            actual_buf = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            self.log.info("Socket receive buffer: %d KB", actual_buf // 1024)
            self.sock.settimeout(2)
            # Bind to the same IP + source port the stock app uses
            # This is critical: the drone may only accept commands from .3
            try:
                self.sock.bind((CLIENT_IP, STOCK_SOURCE_PORT))
                self.log.info("Bound command socket to %s:%d (matching stock app)",
                              CLIENT_IP, STOCK_SOURCE_PORT)
            except OSError as e:
                self.log.warning("Cannot bind to %s:%d (%s), trying %s:0...",
                                 CLIENT_IP, STOCK_SOURCE_PORT, e, CLIENT_IP)
                try:
                    self.sock.bind((CLIENT_IP, 0))
                    actual_port = self.sock.getsockname()[1]
                    self.log.info("Bound command socket to %s:%d", CLIENT_IP, actual_port)
                except OSError as e2:
                    self.sock.close()
                    self.sock = None
                    raise RuntimeError(
                        f"Cannot bind to {CLIENT_IP} — the IP alias is not set up. "
                        f"Run: sudo bash setup_network.sh\n"
                        f"(Error: {e2})"
                    )
        if self.sock2 is None:
            self.sock2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock2.settimeout(2)
            # Stock app also uses a second socket for port 8801 heartbeats
            try:
                self.sock2.bind((CLIENT_IP, 0))
                actual_port = self.sock2.getsockname()[1]
                self.log.info("Bound heartbeat socket to %s:%d", CLIENT_IP, actual_port)
            except OSError:
                self.sock2.bind(('', 0))

    def _send(self, data: bytes, port=None):
        self._open_socket()
        target_port = port or self.command_port
        self.log.debug("TX :%d [%d bytes]: %s", target_port, len(data), data.hex(' '))
        self.sock.sendto(data, (self.drone_ip, target_port))

    def _send2(self, data: bytes, port=VIDEO_PORT):
        """Send on the second socket (for port 8801 heartbeats)."""
        self._open_socket()
        self.log.debug("TX2 :%d [%d bytes]: %s", port, len(data), data.hex(' '))
        self.sock2.sendto(data, (self.drone_ip, port))

    # -- packet builders (EF 02 protocol from stock app) --------------------

    def _control_packet(self, sub_type=0, include_joystick=True) -> bytes:
        """Build an EF 02 control packet matching the stock app's three states.

        The stock app capture reveals THREE protocol states:

        1. INIT (during handshake): byte 16=0x00, seq=0, all joystick zeros
        2. MARKER-ONLY (settle phase): byte 16=0x08 with seq incrementing,
           but NO 0x66/0x99 joystick block — joystick bytes stay at 0x00
        3. FULL (active flight): byte 16=0x08, 0x66/joystick/0x99, seq incrementing

        State transitions:
          _handshake_done=False                → State 1 (INIT)
          _handshake_done=True, _joystick_active=False → State 2 (MARKER-ONLY)
          _handshake_done=True, _joystick_active=True  → State 3 (FULL)

        Sub_type=2 packets have a 16-byte footer after the sensor record:
          {seq2+1}(LE32) 00 00 00 00 03 00 00 00 10 00 00 00
        """
        if sub_type == 0:
            pkt_len = 88
        elif sub_type == 1:
            pkt_len = 112
        elif sub_type == 2:
            pkt_len = 128  # 112 + 16-byte footer
        else:
            pkt_len = 88

        buf = bytearray(pkt_len)

        # Header
        buf[0] = 0xEF
        buf[1] = 0x02
        struct.pack_into("<H", buf, 2, pkt_len)

        # Protocol header
        buf[4] = 0x02
        buf[5] = 0x02
        buf[6] = 0x00
        buf[7] = 0x01

        # Sub-type
        buf[8] = sub_type

        # --- Three protocol states for bytes 12-25 ---
        if include_joystick and self._handshake_done:
            # States 2 and 3: seq incrementing, byte 16 = 0x08
            struct.pack_into("<H", buf, 12, self._seq & 0xFFFF)
            self._seq += 1
            buf[16] = 0x08  # joystick data marker

            if self._joystick_active:
                # State 3 (FULL): complete joystick block with 0x66...0x99
                trimmed_pitch = max(0, min(255, self.pitch - self.pitch_trim))
                trimmed_roll = max(0, min(255, self.roll + self.roll_trim))
                buf[18] = 0x66  # block start
                buf[19] = trimmed_roll
                buf[20] = trimmed_pitch
                buf[21] = self.throttle
                buf[22] = self.yaw
                buf[23] = self.proto_trim_roll
                buf[24] = self.proto_trim_pitch
                buf[25] = 0x99  # block end
            # else: State 2 (MARKER-ONLY): byte 16=0x08, bytes 18-25 stay zeros
        # else: State 1 (INIT): bytes 12-25 all zeros

        # Device signature at bytes 82-85 (for packets >= 86 bytes)
        if pkt_len >= 86:
            buf[82] = 0x32
            buf[83] = 0x4B
            buf[84] = 0x14
            buf[85] = 0x2D

        # Extended fields at bytes 86-111 (for 112+ byte packets)
        # Record format (24 bytes): seq2(4) + zeros(4) + flag(4) + length(4) + sensor(8)
        # Preceded by 2-byte preamble (00 00)
        if pkt_len >= 112:
            # Bytes 86-87: preamble (00 00)
            # Bytes 88-91: secondary LE32 sequence counter
            struct.pack_into("<I", buf, 88, self._seq2 & 0xFFFFFFFF)
            # Bytes 92-95: 00 00 00 00
            # Byte 96: flag — stock app always sets to 0x01 (critical for video!)
            buf[96] = 0x01
            # Bytes 100-103: record length (0x18=24, self-describing)
            buf[100] = 0x18
            # Bytes 104-111: sensor/gyro data
            # Stock app uses ff ff ff ff 00 00 e0 ff (not all 0xff!)
            buf[104:108] = b'\xff\xff\xff\xff'
            buf[108:112] = b'\x00\x00\xe0\xff'

        # Sub_type=2 footer: 16 bytes at bytes 112-127
        # Stock app always includes this: {seq2+1}(LE32) + zeros(4) + type=3(LE32) + len=0x10(LE32)
        if sub_type == 2 and pkt_len >= 128:
            struct.pack_into("<I", buf, 112, (self._seq2 + 1) & 0xFFFFFFFF)
            # Bytes 116-119: 00 00 00 00
            struct.pack_into("<I", buf, 120, 3)  # type = 3
            struct.pack_into("<I", buf, 124, 0x10)  # length = 16

        # Increment seq2 AFTER both record and footer use it
        if pkt_len >= 112:
            self._seq2 += 1

        return bytes(buf)

    def _text_command_packet(self, cmd_id: int) -> bytes:
        """Build a text command packet matching the stock app format.

        Format from capture:
          Byte 0:    0xEF
          Byte 1:    0x20
          Bytes 2-3: total packet length (LE16)
          Byte 4:    0x01
          Byte 5:    0x67
          Bytes 6+:  ASCII command string: <i=2^bf_ssid=cmd=N>
        """
        text = f"<i=2^bf_ssid=cmd={cmd_id}>".encode("ascii")
        total_len = 4 + 2 + len(text)  # 4-byte header + 2 bytes (01 67) + text

        buf = bytearray()
        buf.append(0xEF)
        buf.append(0x20)
        buf += struct.pack("<H", total_len)
        buf.append(0x01)
        buf.append(0x67)
        buf += text

        return bytes(buf)

    # -- response listener --------------------------------------------------

    def _rx_loop(self):
        """Listen for any responses from the drone (video, ack, etc)."""
        while not self._stop_event.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
                if data[0:1] == b'\x93':
                    self.video_packets += 1
                    # Feed video packets to decoder (for autopilot and UI)
                    self.video_decoder.feed_packet(data)
                    if self.video_packets == 1:
                        self.log.info("Video stream started from %s (%d bytes)", addr, len(data))
                    elif self.video_packets <= 300 and self.video_packets % 50 == 0:
                        self.log.info("Video: %d pkts, %d frames, %d assembled (%d bytes payload)",
                                      self.video_packets, self.video_decoder.frames_decoded,
                                      self.video_decoder._assembler.frames_assembled,
                                      len(data))
                    elif self.video_packets % 500 == 0:
                        self.log.info("Video: %d pkts, %d frames decoded, assembler: %d assembled, %d frags",
                                      self.video_packets, self.video_decoder.frames_decoded,
                                      self.video_decoder._assembler.frames_assembled,
                                      self.video_decoder._assembler.fragments_received)
                else:
                    # Log first few non-video responses, then only every 100th
                    self._rx_other = getattr(self, '_rx_other', 0) + 1
                    if self._rx_other <= 3 or self._rx_other % 100 == 0:
                        self.log.info("RX from %s [%d bytes]: %s (count=%d)",
                                      addr, len(data), data[:20].hex(' '), self._rx_other)
            except socket.timeout:
                continue
            except Exception:
                if not self._stop_event.is_set():
                    break

    # -- heartbeat loop -----------------------------------------------------

    def _heartbeat_loop(self):
        """Video stats monitor. No keepalive needed — stock app uses only control packets."""
        self.log.info("Video monitor started")
        cycle = 0
        last_video_pkts = 0
        while not self._stop_event.is_set():
            self._stop_event.wait(2.0)
            if self._stop_event.is_set():
                break
            cycle += 1
            delta = self.video_packets - last_video_pkts
            last_video_pkts = self.video_packets
            self.log.info("Video stats [%ds]: pkts=%d (+%d), frames=%d, assembled=%d, "
                          "state=%s",
                          cycle * 2, self.video_packets, delta,
                          self.video_decoder.frames_decoded,
                          self.video_decoder._assembler.frames_assembled,
                          "INIT" if not self._handshake_done else (
                              "FULL" if self._joystick_active else "MARKER"))

    # -- control loop -------------------------------------------------------

    def _control_loop(self):
        """Send control packets at 20Hz, alternating sub_type 0 and 1."""
        tick = 0
        errors = 0
        while not self._stop_event.is_set():
            if self.armed:
                try:
                    # Send any pending text commands
                    with self._lock:
                        cmds = list(self._pending_text_cmds)
                        self._pending_text_cmds.clear()

                    for cmd_pkt in cmds:
                        self._send(cmd_pkt)
                        time.sleep(0.02)

                    # Mix sub_types 0, 1, 2 matching stock app distribution:
                    # ~47% sub_type=0 (88B), ~41% sub_type=1 (112B), ~12% sub_type=2 (128B+)
                    r = tick % 8
                    if r == 7:
                        sub = 2
                    elif r % 2 == 0:
                        sub = 0
                    else:
                        sub = 1
                    pkt = self._control_packet(sub_type=sub)
                    self._send(pkt)

                    # Diagnostic packet logging
                    should_log = (tick < 3 or
                                  (tick < 500 and tick % 100 == 0) or
                                  tick % 1000 == 0 or
                                  (self.throttle > 0x80 and tick % 50 == 0))
                    if should_log:
                        ext = ""
                        if len(pkt) >= 128:
                            ext = f" ext[86:128]={pkt[86:128].hex(' ')}"
                        elif len(pkt) >= 112:
                            ext = f" ext[86:112]={pkt[86:112].hex(' ')}"
                        state = "INIT" if not self._handshake_done else (
                            "FULL" if self._joystick_active else "MARKER")
                        self.log.info(
                            "TX pkt[%d] sub=%d seq=%d state=%s [16:26]=%s "
                            "T=0x%02X%s",
                            tick, sub, self._seq, state, pkt[16:26].hex(' '),
                            self.throttle, ext)
                    tick += 1
                    errors = 0  # Reset error counter on success
                except Exception as e:
                    errors += 1
                    self.log.warning("Control send failed (#%d): %s", errors, e)
                    if errors > 50:
                        self.log.error("Too many control errors, stopping control loop")
                        break
            self._stop_event.wait(CONTROL_RATE)
        self.log.info("Control loop ended (tick=%d)", tick)

    # -- connection ---------------------------------------------------------

    def connect(self):
        """Connect to drone using the EXACT handshake sequence from the stock app capture.

        The stock app capture shows this precise sequence:
          +0ms:    ef 00 04 00 -> :8800 (heartbeat)
          +9ms:    ef 00 04 00 -> :8801 (heartbeat on second port!)
          +103ms:  ef 00 04 00 -> :8800
          +206ms:  ef 00 04 00 -> :8800
          +212ms:  ef 00 04 00 -> :8801
          +240ms:  88-byte control (sub_type=0, seq=0, ALL ZEROS in joystick)
          +269ms:  88-byte control (sub_type=0, seq=0, ALL ZEROS)
          +298ms:  88-byte control (sub_type=0, seq=0, ALL ZEROS)
          +328ms:  112-byte control (sub_type=1, seq=0, ALL ZEROS)
          +358ms:  88-byte control (sub_type=0, seq=0, ALL ZEROS)
          +359ms:  ef 20 06 00 01 65 (ENABLE)
          +387ms:  112-byte control (sub_type=1, seq=0, ALL ZEROS)
          +412ms:  ef 20 19 00 01 67 <i=2^bf_ssid=cmd=2> (CONNECT)
          +412ms:  88-byte control
          +433ms:  ef 20 19 00 01 67 <i=2^bf_ssid=cmd=3> (START VIDEO)
          +443ms:  88-byte control
          +455ms:  ef 20 1b 00 01 67 <i=2^bf_ssid=cmd=106> (CALIBRATE)
          +472ms+: continuous mix of 88/112 byte control packets
        """
        if self.connected:
            return

        self.log.info("Connecting to %s:%d", self.drone_ip, self.command_port)
        self._open_socket()
        self._stop_event.clear()
        self._seq = 0
        self._seq2 = 0
        self._handshake_done = False
        self._joystick_active = False

        # Start video decoder BEFORE handshake so it's ready when 0x93 packets arrive
        if not self.video_decoder._started:
            try:
                self.video_decoder.start()
                self.log.info("Video decoder pre-started for incoming packets")
            except Exception as e:
                self.log.warning("Video decoder failed to start: %s", e)

        # Step 1: Heartbeats to BOTH ports (matching stock app exactly)
        # Stock app uses port 54288 for 8800 and a DIFFERENT port (53169) for 8801
        # Only 2 STREAM_INIT packets go to 8801 during entire session
        self.log.info("Step 1: Sending stream init to ports 8800 + 8801...")
        self._send(STREAM_INIT)                     # +0ms -> :8800
        self._send2(STREAM_INIT, VIDEO_PORT)         # +9ms -> :8801
        time.sleep(0.1)
        self._send(STREAM_INIT)                     # +103ms -> :8800
        time.sleep(0.1)
        self._send(STREAM_INIT)                     # +206ms -> :8800
        self._send2(STREAM_INIT, VIDEO_PORT)         # +212ms -> :8801
        time.sleep(0.03)

        # Start RX listener to pick up video + responses
        self._rx_thread = threading.Thread(target=self._rx_loop, daemon=True)
        self._rx_thread.start()

        # Step 2: Init control packets (88-byte, ALL ZEROS, seq=0)
        self.log.info("Step 2: Sending init control packets (88-byte, zeros)...")
        for _ in range(3):
            self._send(self._control_packet(sub_type=0, include_joystick=False))
            time.sleep(0.03)

        # Step 3: One 112-byte init packet
        self.log.info("Step 3: Sending 112-byte init...")
        self._send(self._control_packet(sub_type=1, include_joystick=False))
        time.sleep(0.03)

        # Step 4: Another 88-byte + Enable command (sent almost simultaneously)
        self.log.info("Step 4: Sending enable command...")
        self._send(self._control_packet(sub_type=0, include_joystick=False))
        self._send(ENABLE_CMD)
        time.sleep(0.03)

        # Step 5: Another 112-byte init
        self._send(self._control_packet(sub_type=1, include_joystick=False))
        time.sleep(0.025)

        # Step 6: Text command: connect (cmd=2) + 88-byte control
        self.log.info("Step 5: Sending cmd=2 (connect)...")
        self._send(self._text_command_packet(2))
        self._send(self._control_packet(sub_type=0, include_joystick=False))
        time.sleep(0.02)

        # Step 7: Text command: start video (cmd=3) + 88-byte control
        self.log.info("Step 6: Sending cmd=3 (start video)...")
        self._send(self._text_command_packet(3))
        self._send(self._control_packet(sub_type=0, include_joystick=False))
        time.sleep(0.02)

        # Step 8: Text command: calibrate gyro (cmd=106)
        self.log.info("Step 7: Sending cmd=106 (calibrate)...")
        self._send(self._text_command_packet(106))
        time.sleep(0.05)

        # CRITICAL: Stock app capture shows it sends ALL-ZERO control packets
        # (seq=0, byte16=0x00, no joystick) for ~2.5 seconds (82 packets!) after
        # the handshake commands, BEFORE transitioning to byte16=0x08 + joystick.
        # Video flows continuously during this all-zero phase.
        # Setting _handshake_done immediately was killing video because the drone
        # expects this idle period first.
        self._handshake_done = False   # Keep sending State 1 (all-zero) packets
        self._joystick_active = False

        # Start monitor thread
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
        self._heartbeat_thread.start()

        # Start control loop (33Hz) — sends State 1 (all-zero) packets
        self._control_thread = threading.Thread(target=self._control_loop, daemon=True)
        self._control_thread.start()

        self.connected = True
        self.armed = True
        self.log.info("Handshake done — sending all-zero idle packets (State 1), "
                      "transitioning to joystick in 2.5s")

        # After 2.5s (matching stock app timing), transition to State 3
        def _activate_joystick():
            self._handshake_done = True
            self._joystick_active = True
            self.log.info("State 1 complete → State 3 (seq incrementing + full joystick block)")

        self._settle_timer = threading.Timer(2.5, _activate_joystick)
        self._settle_timer.daemon = True
        self._settle_timer.start()

    def disconnect(self):
        """Stop all loops and close sockets."""
        # Stop autopilot first
        if self.autopilot.enabled:
            self.autopilot.disable()
        if self.video_decoder._started:
            self.video_decoder.stop()
        if hasattr(self, '_settle_timer') and self._settle_timer:
            self._settle_timer.cancel()
        self._stop_event.set()
        self.connected = False
        self.armed = False
        self._handshake_done = False
        if self._control_thread:
            self._control_thread.join(timeout=2)
        if self._heartbeat_thread:
            self._heartbeat_thread.join(timeout=2)
        if self._rx_thread:
            self._rx_thread.join(timeout=2)
        if self.sock:
            self.sock.close()
            self.sock = None
        if self.sock2:
            self.sock2.close()
            self.sock2 = None
        self.log.info("Disconnected (video packets received: %d)", self.video_packets)

    # -- flight commands ----------------------------------------------------

    def set_joystick(self, roll=None, pitch=None, throttle=None, yaw=None):
        if roll is not None:
            self.roll = max(0, min(255, int(roll)))
        if pitch is not None:
            self.pitch = max(0, min(255, int(pitch)))
        if throttle is not None:
            self.throttle = max(0, min(255, int(throttle)))
        if yaw is not None:
            self.yaw = max(0, min(255, int(yaw)))

    def center_sticks(self):
        self.roll = 0x80
        self.pitch = 0x80
        self.throttle = 0x80      # Throttle to center (joystick default)
        self.yaw = 0x80

    def _queue_text_cmd(self, cmd_id: int):
        """Queue a text command to be sent at the next control tick."""
        pkt = self._text_command_packet(cmd_id)
        with self._lock:
            self._pending_text_cmds.append(pkt)
        self.log.info("Queued text command: cmd=%d", cmd_id)

    def rearm(self):
        """Re-send the enable + connect commands to re-arm motors.

        The drone firmware appears to disarm after prolonged zero-throttle.
        Re-sending these commands re-arms without a full reconnect.
        """
        if not self.connected:
            self.log.warning("rearm() called but not connected")
            return
        self.log.info("Re-arming: sending ENABLE + cmd=2...")
        self._send(ENABLE_CMD)
        time.sleep(0.05)
        self._send(self._text_command_packet(2))  # cmd=2 = connect/start
        time.sleep(0.05)
        self._send(ENABLE_CMD)  # double-tap for reliability
        time.sleep(0.3)
        self.log.info("Re-arm commands sent")

    def takeoff(self):
        self._queue_text_cmd(1)
        self.log.info("Takeoff command queued (cmd=1)")

    def land(self):
        self._queue_text_cmd(1)  # Toggle — same command as takeoff for this drone
        self.log.info("Land command queued (cmd=1)")

    def emergency_stop(self):
        # Send emergency immediately (multiple times for reliability)
        pkt = self._text_command_packet(7)
        for _ in range(5):
            self._send(pkt)
            time.sleep(0.02)
        self.center_sticks()
        self.log.info("EMERGENCY STOP sent (cmd=7)")

    def calibrate_gyro(self):
        self._queue_text_cmd(106)
        self.log.info("Gyro calibration queued (cmd=106)")

    def take_photo(self):
        self._queue_text_cmd(5)
        self.log.info("Photo command queued (cmd=5)")

    def toggle_video(self):
        self._queue_text_cmd(6)
        self.log.info("Video toggle queued (cmd=6)")

    def set_speed(self, level: int):
        cmd_map = {1: 100, 2: 101, 3: 102}
        cmd = cmd_map.get(level, 100)
        self._queue_text_cmd(cmd)
        self.log.info("Speed level %d queued (cmd=%d)", level, cmd)

    def headless_mode(self, on: bool):
        cmd = 103 if on else 104
        self._queue_text_cmd(cmd)
        self.log.info("Headless mode %s queued (cmd=%d)", "ON" if on else "OFF", cmd)

    def flip(self):
        self._queue_text_cmd(105)
        self.log.info("Flip queued (cmd=105)")

    def adjust_trim(self, pitch_delta=0, roll_delta=0):
        """Adjust trim offsets. Positive pitch = more forward, positive roll = more right."""
        self.pitch_trim = max(-50, min(50, self.pitch_trim + pitch_delta))
        self.roll_trim = max(-50, min(50, self.roll_trim + roll_delta))
        self.log.info("Trim adjusted: pitch=%+d roll=%+d", self.pitch_trim, self.roll_trim)

    def set_trim(self, pitch=None, roll=None):
        """Set trim offsets directly."""
        if pitch is not None:
            self.pitch_trim = max(-50, min(50, int(pitch)))
        if roll is not None:
            self.roll_trim = max(-50, min(50, int(roll)))
        self.log.info("Trim set: pitch=%+d roll=%+d", self.pitch_trim, self.roll_trim)

    def get_state(self) -> dict:
        return {
            "connected": self.connected,
            "armed": self.armed,
            "roll": self.roll,
            "pitch": self.pitch,
            "throttle": self.throttle,
            "yaw": self.yaw,
            "pitch_trim": self.pitch_trim,
            "roll_trim": self.roll_trim,
            "video_packets": self.video_packets,
            "video_fps": round(self.video_decoder.fps, 1),
            "video_frames_decoded": self.video_decoder.frames_decoded,
        }


# ---------------------------------------------------------------------------
# Flask web UI
# ---------------------------------------------------------------------------

app = Flask(__name__)
drone = Q10Controller()

# ML subsystems (optional — controller works without ml/ package)
ml_collector = DataCollector(drone.video_decoder, drone) if DataCollector else None
ml_predictor = None  # Initialized lazily when first needed
ml_trainer = None    # Created on-demand per training run

def _get_predictor():
    global ml_predictor
    if ml_predictor is None:
        from ml.predictor import Predictor
        ml_predictor = Predictor()
        drone.autopilot.set_predictor(ml_predictor)
    return ml_predictor

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
<title>Q10 Drone Controller</title>
<style>
  :root {
    --bg: #0f1117;
    --surface: #1a1d27;
    --border: #2a2d3a;
    --accent: #3b82f6;
    --danger: #ef4444;
    --success: #22c55e;
    --warn: #f59e0b;
    --text: #e2e8f0;
    --muted: #64748b;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    overflow-x: hidden;
    touch-action: manipulation;
  }

  /* Header */
  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }
  .header h1 { font-size: 18px; font-weight: 600; letter-spacing: -0.5px; }
  .status-dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: var(--danger);
    display: inline-block;
    margin-right: 8px;
  }
  .status-dot.on { background: var(--success); }
  .status { display: flex; align-items: center; font-size: 13px; color: var(--muted); }

  /* Layout */
  .main {
    display: grid;
    grid-template-columns: 1fr 1fr;
    grid-template-rows: auto auto auto;
    gap: 16px;
    padding: 16px;
    max-width: 900px;
    margin: 0 auto;
  }

  /* Panels */
  .panel {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 16px;
  }
  .panel-title {
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
    margin-bottom: 12px;
  }

  /* Connection panel spans full width */
  .connect-panel { grid-column: 1 / -1; }
  .connect-panel .btn-row {
    display: flex; gap: 8px; flex-wrap: wrap;
  }

  /* Joystick areas */
  .joystick-container {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 100%;
    aspect-ratio: 1;
    max-width: 280px;
    margin: 0 auto;
  }
  .joystick-zone {
    width: 200px;
    height: 200px;
    background: radial-gradient(circle, #1e2130 0%, #141620 100%);
    border: 2px solid var(--border);
    border-radius: 50%;
    position: relative;
    touch-action: none;
    cursor: grab;
  }
  .joystick-zone:active { cursor: grabbing; }
  .joystick-crosshair {
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    width: 80%; height: 80%;
    pointer-events: none;
  }
  .joystick-crosshair::before,
  .joystick-crosshair::after {
    content: '';
    position: absolute;
    background: var(--border);
  }
  .joystick-crosshair::before {
    width: 1px; height: 100%;
    left: 50%; top: 0;
  }
  .joystick-crosshair::after {
    width: 100%; height: 1px;
    top: 50%; left: 0;
  }
  .joystick-thumb {
    width: 48px; height: 48px;
    background: radial-gradient(circle at 30% 30%, #5b9bf5, var(--accent));
    border: 2px solid rgba(255,255,255,0.15);
    border-radius: 50%;
    position: absolute;
    top: 50%; left: 50%;
    transform: translate(-50%, -50%);
    pointer-events: none;
    transition: box-shadow 0.15s;
    box-shadow: 0 2px 12px rgba(59,130,246,0.3);
  }
  .joystick-zone:active .joystick-thumb {
    box-shadow: 0 2px 20px rgba(59,130,246,0.6);
  }
  .joystick-values {
    text-align: center;
    font-size: 12px;
    color: var(--muted);
    margin-top: 4px;
    font-family: 'SF Mono', 'Fira Code', monospace;
  }

  /* Buttons */
  .btn {
    padding: 8px 16px;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--surface);
    color: var(--text);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.15s;
    white-space: nowrap;
  }
  .btn:hover { background: #22253a; border-color: var(--accent); }
  .btn:active { transform: scale(0.97); }
  .btn-primary { background: var(--accent); border-color: var(--accent); color: #fff; }
  .btn-primary:hover { background: #2563eb; }
  .btn-danger { background: var(--danger); border-color: var(--danger); color: #fff; }
  .btn-danger:hover { background: #dc2626; }
  .btn-success { background: var(--success); border-color: var(--success); color: #fff; }
  .btn-success:hover { background: #16a34a; }
  .btn-warn { background: var(--warn); border-color: var(--warn); color: #000; }
  .btn-warn:hover { background: #d97706; }
  .btn-sm { padding: 6px 12px; font-size: 12px; }
  .btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .ap-btn.active { background: var(--accent); border-color: var(--accent); color: #fff; }

  /* Actions grid */
  .actions-panel { grid-column: 1 / -1; }
  .actions-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(110px, 1fr));
    gap: 8px;
  }
  .actions-grid .btn { width: 100%; text-align: center; }

  /* Telemetry */
  .telemetry-panel { grid-column: 1 / -1; }
  .telem-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
  }
  .telem-item {
    background: var(--bg);
    border-radius: 8px;
    padding: 10px;
    text-align: center;
  }
  .telem-item .label { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
  .telem-item .value { font-size: 20px; font-weight: 600; font-family: 'SF Mono', 'Fira Code', monospace; margin-top: 2px; }

  /* Log */
  .log-panel { grid-column: 1 / -1; }
  #log {
    background: var(--bg);
    border-radius: 8px;
    padding: 10px;
    height: 150px;
    overflow-y: auto;
    font-family: 'SF Mono', 'Fira Code', monospace;
    font-size: 12px;
    line-height: 1.6;
    color: var(--muted);
  }
  #log .entry { }
  #log .entry.error { color: var(--danger); }
  #log .entry.ok { color: var(--success); }
  #log .entry.warn { color: var(--warn); }

  /* Responsive */
  @media (max-width: 500px) {
    .main { grid-template-columns: 1fr 1fr; gap: 10px; padding: 10px; }
    .joystick-zone { width: 160px; height: 160px; }
    .joystick-thumb { width: 40px; height: 40px; }
    .telem-grid { grid-template-columns: repeat(2, 1fr); }
    .actions-grid { grid-template-columns: repeat(3, 1fr); }
  }
</style>
</head>
<body>

<div class="header">
  <h1>Q10 Drone Controller</h1>
  <div class="status">
    <span class="status-dot" id="statusDot"></span>
    <span id="statusText">Disconnected</span>
  </div>
</div>

<div class="main">

  <!-- Connection -->
  <div class="panel connect-panel">
    <div class="panel-title">Connection</div>
    <div class="btn-row">
      <button class="btn btn-primary" id="btnConnect" onclick="doConnect()">Connect</button>
      <button class="btn btn-danger" id="btnDisconnect" onclick="doDisconnect()" disabled>Disconnect</button>
      <button class="btn btn-success" id="btnTakeoff" onclick="doCmd('takeoff')" disabled>Takeoff</button>
      <button class="btn btn-warn" id="btnLand" onclick="doCmd('land')" disabled>Land</button>
      <button class="btn btn-danger" id="btnEmergency" onclick="doCmd('emergency')" style="font-weight:700;">EMERGENCY STOP</button>
    </div>
  </div>

  <!-- Camera Feed -->
  <div class="panel" style="grid-column: 1 / -1;">
    <div class="panel-title">Camera Feed</div>
    <div style="text-align:center;">
      <img id="videoFeed" style="width:100%; max-width:480px; border-radius:8px; border:1px solid var(--border); background:#000;">
      <div style="font-size:11px; color:var(--muted); margin-top:6px;">
        FPS: <span id="videoFps">0</span> &nbsp;|&nbsp; Frames: <span id="videoFrames">0</span>
      </div>
    </div>
  </div>

  <!-- Left stick: Throttle / Yaw -->
  <div class="panel">
    <div class="panel-title">Left Stick &mdash; Throttle / Yaw</div>
    <div class="joystick-container">
      <div class="joystick-zone" id="leftStick">
        <div class="joystick-crosshair"></div>
        <div class="joystick-thumb" id="leftThumb"></div>
      </div>
    </div>
    <div class="joystick-values" id="leftValues">T: 128 &nbsp; Y: 128</div>
  </div>

  <!-- Right stick: Pitch / Roll -->
  <div class="panel">
    <div class="panel-title">Right Stick &mdash; Pitch / Roll</div>
    <div class="joystick-container">
      <div class="joystick-zone" id="rightStick">
        <div class="joystick-crosshair"></div>
        <div class="joystick-thumb" id="rightThumb"></div>
      </div>
    </div>
    <div class="joystick-values" id="rightValues">P: 128 &nbsp; R: 128</div>
  </div>

  <!-- Trim -->
  <div class="panel" style="grid-column: 1 / -1;">
    <div class="panel-title">Trim (adjust if drone drifts)</div>
    <div style="display:flex; gap:24px; align-items:center; justify-content:center; flex-wrap:wrap;">
      <div style="text-align:center;">
        <div style="font-size:12px; color:var(--muted); margin-bottom:6px;">Pitch (fwd/back)</div>
        <div style="display:flex; gap:6px; align-items:center;">
          <button class="btn btn-sm" onclick="doTrim('pitch', -5)">&#9664; Back</button>
          <span id="trimPitch" style="font-family:monospace; min-width:40px; text-align:center;">0</span>
          <button class="btn btn-sm" onclick="doTrim('pitch', 5)">Fwd &#9654;</button>
        </div>
      </div>
      <div style="text-align:center;">
        <div style="font-size:12px; color:var(--muted); margin-bottom:6px;">Roll (left/right)</div>
        <div style="display:flex; gap:6px; align-items:center;">
          <button class="btn btn-sm" onclick="doTrim('roll', -5)">&#9664; Left</button>
          <span id="trimRoll" style="font-family:monospace; min-width:40px; text-align:center;">0</span>
          <button class="btn btn-sm" onclick="doTrim('roll', 5)">Right &#9654;</button>
        </div>
      </div>
      <button class="btn btn-sm" onclick="doTrimReset()" style="align-self:flex-end;">Reset Trim</button>
    </div>
  </div>

  <!-- Autopilot -->
  <div class="panel" style="grid-column: 1 / -1;">
    <div class="panel-title">Autopilot</div>
    <div style="display:flex; gap:12px; align-items:center; flex-wrap:wrap; margin-bottom:12px;">
      <button class="btn btn-sm ap-btn active" id="btnAPOff" onclick="setAutopilot('off')">OFF (Manual)</button>
      <button class="btn btn-sm ap-btn" id="btnAPHover" onclick="setAutopilot('hover')">Hover + Avoid</button>
      <button class="btn btn-sm ap-btn" id="btnAPExplore" onclick="setAutopilot('explore')">Explore</button>
      <button class="btn btn-sm ap-btn" id="btnAPML" onclick="setAutopilot('ml')" style="background:#537; border-color:#759;">ML Pilot</button>
      <button class="btn btn-sm" id="btnTestRamp" onclick="doTestRamp()" style="background:#553; border-color:#885; color:#ee8;">Test Ramp</button>
      <span style="font-size:12px; color:var(--muted); margin-left:8px;" id="apStatus">Autopilot off</span>
    </div>
    <!-- Autopilot Event Log -->
    <div id="apEventLog" style="display:none; background:#111; border:1px solid var(--border); border-radius:6px; padding:8px 12px; margin-bottom:12px; max-height:150px; overflow-y:auto; font-family:monospace; font-size:11px; line-height:1.6; color:#8f8;">
    </div>
    <div style="display:flex; gap:16px; align-items:flex-start; flex-wrap:wrap;">
      <!-- Threat levels -->
      <div style="flex:1; min-width:180px;">
        <div style="font-size:11px; color:var(--muted); margin-bottom:4px;">Obstacle Threat</div>
        <div style="display:flex; flex-direction:column; gap:6px;">
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:12px; width:50px;">Left</span>
            <div style="flex:1; height:16px; background:var(--bg); border-radius:4px; overflow:hidden;">
              <div id="threatLeft" style="height:100%; width:0%; background:var(--success); transition:width 0.2s, background 0.2s;"></div>
            </div>
            <span id="threatLeftVal" style="font-size:11px; font-family:monospace; width:35px;">0%</span>
          </div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:12px; width:50px;">Center</span>
            <div style="flex:1; height:16px; background:var(--bg); border-radius:4px; overflow:hidden;">
              <div id="threatCenter" style="height:100%; width:0%; background:var(--success); transition:width 0.2s, background 0.2s;"></div>
            </div>
            <span id="threatCenterVal" style="font-size:11px; font-family:monospace; width:35px;">0%</span>
          </div>
          <div style="display:flex; align-items:center; gap:8px;">
            <span style="font-size:12px; width:50px;">Right</span>
            <div style="flex:1; height:16px; background:var(--bg); border-radius:4px; overflow:hidden;">
              <div id="threatRight" style="height:100%; width:0%; background:var(--success); transition:width 0.2s, background 0.2s;"></div>
            </div>
            <span id="threatRightVal" style="font-size:11px; font-family:monospace; width:35px;">0%</span>
          </div>
        </div>
        <div style="font-size:11px; color:var(--muted); margin-top:8px;">
          Frames: <span id="apFrames">0</span> &nbsp;|&nbsp; Avoidance: <span id="apAvoid">0</span>
        </div>
      </div>
    </div>
  </div>

  <!-- ML Behavioral Cloning -->
  <div class="panel" style="grid-column: 1 / -1;">
    <div class="panel-title">ML Behavioral Cloning</div>
    <div style="display:grid; grid-template-columns:1fr 1fr; gap:16px;">
      <!-- Recording -->
      <div>
        <div style="font-size:12px; color:var(--muted); margin-bottom:8px;">Record Flight Data</div>
        <div style="display:flex; gap:6px; align-items:center; margin-bottom:8px;">
          <input type="text" id="mlSessionName" placeholder="Session name" style="flex:1; padding:6px 10px; border:1px solid var(--border); border-radius:6px; background:var(--bg); color:var(--text); font-size:13px;">
          <button class="btn btn-sm btn-success" id="btnRecord" onclick="mlToggleRecord()">Record</button>
        </div>
        <div id="mlRecordStatus" style="font-size:11px; color:var(--muted);">Not recording</div>
        <!-- Sessions list -->
        <div style="font-size:12px; color:var(--muted); margin:10px 0 6px;">Sessions</div>
        <div id="mlSessionsList" style="background:var(--bg); border-radius:6px; padding:6px; max-height:120px; overflow-y:auto; font-size:12px;">
          <div style="color:var(--muted);">No sessions</div>
        </div>
      </div>
      <!-- Training & Models -->
      <div>
        <div style="font-size:12px; color:var(--muted); margin-bottom:8px;">Train Model</div>
        <div style="display:flex; gap:6px; margin-bottom:8px;">
          <button class="btn btn-sm btn-primary" id="btnTrain" onclick="mlStartTrain()">Train Selected</button>
          <button class="btn btn-sm btn-danger" id="btnTrainStop" onclick="mlStopTrain()" style="display:none;">Stop</button>
        </div>
        <div id="mlTrainStatus" style="font-size:11px; color:var(--muted); margin-bottom:8px;">Idle</div>
        <div id="mlTrainProgress" style="display:none; margin-bottom:8px;">
          <div style="height:6px; background:var(--bg); border-radius:3px; overflow:hidden;">
            <div id="mlTrainBar" style="height:100%; width:0%; background:var(--accent); transition:width 0.3s;"></div>
          </div>
          <div style="font-size:10px; color:var(--muted); margin-top:2px;">
            Epoch <span id="mlTrainEpoch">0</span>/<span id="mlTrainTotal">50</span>
            | Loss: <span id="mlTrainLoss">-</span> / <span id="mlValLoss">-</span>
          </div>
        </div>
        <!-- Models list -->
        <div style="font-size:12px; color:var(--muted); margin:4px 0 6px;">Models</div>
        <div id="mlModelsList" style="background:var(--bg); border-radius:6px; padding:6px; max-height:100px; overflow-y:auto; font-size:12px;">
          <div style="color:var(--muted);">No models</div>
        </div>
        <div style="display:flex; gap:6px; margin-top:6px;">
          <button class="btn btn-sm" id="btnLoadModel" onclick="mlLoadModel()">Load Selected</button>
          <button class="btn btn-sm" id="btnUnloadModel" onclick="mlUnloadModel()">Unload</button>
        </div>
        <div id="mlModelInfo" style="font-size:11px; color:var(--muted); margin-top:4px;">No model loaded</div>
      </div>
    </div>
  </div>

  <!-- Actions -->
  <div class="panel actions-panel">
    <div class="panel-title">Actions</div>
    <div class="actions-grid">
      <button class="btn btn-sm" onclick="doCmd('calibrate')">Calibrate Gyro</button>
      <button class="btn btn-sm" onclick="doCmd('headless_on')">Headless ON</button>
      <button class="btn btn-sm" onclick="doCmd('headless_off')">Headless OFF</button>
      <button class="btn btn-sm" onclick="doCmd('flip')">Flip</button>
      <button class="btn btn-sm" onclick="doCmd('photo')">Photo</button>
      <button class="btn btn-sm" onclick="doCmd('video')">Video</button>
      <button class="btn btn-sm" onclick="doCmd('speed1')">Speed 1</button>
      <button class="btn btn-sm" onclick="doCmd('speed2')">Speed 2</button>
      <button class="btn btn-sm" onclick="doCmd('speed3')">Speed 3</button>
    </div>
  </div>

  <!-- Telemetry -->
  <div class="panel telemetry-panel">
    <div class="panel-title">Telemetry</div>
    <div class="telem-grid">
      <div class="telem-item"><div class="label">Roll</div><div class="value" id="tRoll">128</div></div>
      <div class="telem-item"><div class="label">Pitch</div><div class="value" id="tPitch">128</div></div>
      <div class="telem-item"><div class="label">Throttle</div><div class="value" id="tThrottle">0</div></div>
      <div class="telem-item"><div class="label">Yaw</div><div class="value" id="tYaw">128</div></div>
    </div>
  </div>

  <!-- Log -->
  <div class="panel log-panel">
    <div class="panel-title">Log</div>
    <div id="log"></div>
  </div>

</div>

<script>
// -- Logging ---------------------------------------------------------------
const logEl = document.getElementById('log');
function addLog(msg, cls) {
  const d = document.createElement('div');
  d.className = 'entry' + (cls ? ' ' + cls : '');
  const t = new Date().toLocaleTimeString();
  d.textContent = `[${t}] ${msg}`;
  logEl.appendChild(d);
  logEl.scrollTop = logEl.scrollHeight;
}

// -- API helpers -----------------------------------------------------------
async function api(path, body) {
  try {
    const opts = body ? { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) } : {};
    const r = await fetch('/api/' + path, opts);
    return await r.json();
  } catch(e) {
    addLog('API error: ' + e.message, 'error');
    return { ok: false };
  }
}

async function doConnect() {
  addLog('Connecting to drone...');
  const r = await api('connect', {});
  if (r.ok) { addLog('Connected!', 'ok'); updateUI(true); startVideoStream(); }
  else { addLog('Connection failed: ' + (r.error || ''), 'error'); }
}

async function doDisconnect() {
  stopVideoStream();
  const r = await api('disconnect', {});
  addLog('Disconnected', 'warn');
  updateUI(false);
}

async function doCmd(cmd) {
  const r = await api('command', { cmd });
  if (r.ok) addLog(`Command: ${cmd}`, 'ok');
  else addLog(`Command failed: ${cmd}`, 'error');
}

function updateUI(connected) {
  document.getElementById('statusDot').classList.toggle('on', connected);
  document.getElementById('statusText').textContent = connected ? 'Connected' : 'Disconnected';
  document.getElementById('btnConnect').disabled = connected;
  document.getElementById('btnDisconnect').disabled = !connected;
  document.getElementById('btnTakeoff').disabled = !connected;
  document.getElementById('btnLand').disabled = !connected;
}

// -- Joystick interaction --------------------------------------------------

function setupJoystick(zoneId, thumbId, valuesId, onChange) {
  const zone = document.getElementById(zoneId);
  const thumb = document.getElementById(thumbId);
  const valuesEl = document.getElementById(valuesId);
  let active = false;
  let rect;

  function getPos(e) {
    const clientX = e.touches ? e.touches[0].clientX : e.clientX;
    const clientY = e.touches ? e.touches[0].clientY : e.clientY;
    let x = (clientX - rect.left) / rect.width;
    let y = (clientY - rect.top) / rect.height;
    x = Math.max(0, Math.min(1, x));
    y = Math.max(0, Math.min(1, y));
    return { x, y };
  }

  function updateThumb(x, y) {
    thumb.style.left = (x * 100) + '%';
    thumb.style.top = (y * 100) + '%';
  }

  function start(e) {
    e.preventDefault();
    active = true;
    rect = zone.getBoundingClientRect();
    move(e);
  }

  function move(e) {
    if (!active) return;
    e.preventDefault();
    const p = getPos(e);
    updateThumb(p.x, p.y);
    const xVal = Math.round(p.x * 255);
    const yVal = Math.round(p.y * 255);
    onChange(xVal, yVal, valuesEl);
  }

  function end(e) {
    if (!active) return;
    active = false;
    // Both sticks: return to center on release
    updateThumb(0.5, 0.5);
    onChange(128, 128, valuesEl);
  }

  // Initialize left stick thumb at center (128 throttle)
  if (zoneId === 'leftStick') {
    updateThumb(0.5, 0.5);  // center = 128 throttle
  }

  zone.addEventListener('mousedown', start);
  zone.addEventListener('touchstart', start, { passive: false });
  window.addEventListener('mousemove', move);
  window.addEventListener('touchmove', move, { passive: false });
  window.addEventListener('mouseup', end);
  window.addEventListener('touchend', end);
}

// Throttled joystick send
let joyTimer = null;
let pendingJoy = null;

function sendJoystick() {
  if (pendingJoy) {
    api('joystick', pendingJoy);
    pendingJoy = null;
  }
}

function queueJoystick(data) {
  pendingJoy = data;
  if (!joyTimer) {
    joyTimer = setInterval(() => {
      if (pendingJoy) sendJoystick();
      else { clearInterval(joyTimer); joyTimer = null; }
    }, 50);
  }
}

// Left stick: X=Yaw, Y=Throttle (inverted: top=full, bottom=zero)
setupJoystick('leftStick', 'leftThumb', 'leftValues', (xVal, yVal, el) => {
  const throttle = 255 - yVal;
  const yaw = xVal;
  el.textContent = `T: ${throttle}  Y: ${yaw}`;
  document.getElementById('tThrottle').textContent = throttle;
  document.getElementById('tYaw').textContent = yaw;
  queueJoystick({ throttle, yaw });
});

// Right stick: X=Roll, Y=Pitch
setupJoystick('rightStick', 'rightThumb', 'rightValues', (xVal, yVal, el) => {
  const roll = xVal;
  const pitch = yVal;
  el.textContent = `P: ${pitch}  R: ${roll}`;
  document.getElementById('tRoll').textContent = roll;
  document.getElementById('tPitch').textContent = pitch;
  queueJoystick({ roll, pitch });
});

// -- Keyboard controls -----------------------------------------------------
const keysDown = new Set();
const KEY_STEP = 40;

// Track throttle level separately — it persists (like a real throttle stick)
let currentThrottle = 128;

function keyToJoy() {
  let yaw = 128, pitch = 128, roll = 128;
  // Throttle: W increases, S decreases (persists between presses)
  if (keysDown.has('w'))            currentThrottle = Math.min(255, currentThrottle + 5);
  if (keysDown.has('s'))            currentThrottle = Math.max(0, currentThrottle - 5);
  if (keysDown.has('a'))            yaw = 128 - KEY_STEP;
  if (keysDown.has('d'))            yaw = 128 + KEY_STEP;
  if (keysDown.has('i') || keysDown.has('arrowup'))    pitch = 128 - KEY_STEP;
  if (keysDown.has('k') || keysDown.has('arrowdown'))  pitch = 128 + KEY_STEP;
  if (keysDown.has('j') || keysDown.has('arrowleft'))  roll = 128 - KEY_STEP;
  if (keysDown.has('l') || keysDown.has('arrowright')) roll = 128 + KEY_STEP;
  return { throttle: currentThrottle, yaw, pitch, roll };
}

document.addEventListener('keydown', (e) => {
  const key = e.key.toLowerCase();
  if (['w','a','s','d','i','j','k','l','arrowup','arrowdown','arrowleft','arrowright'].includes(key)) {
    e.preventDefault();
    keysDown.add(key);
    const joy = keyToJoy();
    queueJoystick(joy);
    document.getElementById('tThrottle').textContent = joy.throttle;
    document.getElementById('tYaw').textContent = joy.yaw;
    document.getElementById('tPitch').textContent = joy.pitch;
    document.getElementById('tRoll').textContent = joy.roll;
  }
  if (key === ' ') { e.preventDefault(); doCmd('takeoff'); }
  if (key === 'escape') { e.preventDefault(); doCmd('emergency'); }
});

document.addEventListener('keyup', (e) => {
  keysDown.delete(e.key.toLowerCase());
  if (keysDown.size === 0) {
    // When all keys released: center everything including throttle
    currentThrottle = 128;
    queueJoystick({ throttle: 128, yaw: 128, pitch: 128, roll: 128 });
    document.getElementById('tThrottle').textContent = 128;
    document.getElementById('tYaw').textContent = 128;
    document.getElementById('tPitch').textContent = 128;
    document.getElementById('tRoll').textContent = 128;
  }
});

// -- Gamepad support -------------------------------------------------------
let gamepadIndex = null;

window.addEventListener('gamepadconnected', (e) => {
  gamepadIndex = e.gamepad.index;
  addLog('Gamepad connected: ' + e.gamepad.id, 'ok');
});

window.addEventListener('gamepaddisconnected', () => {
  gamepadIndex = null;
  addLog('Gamepad disconnected', 'warn');
});

function pollGamepad() {
  if (gamepadIndex !== null) {
    const gp = navigator.getGamepads()[gamepadIndex];
    if (gp) {
      const deadzone = 0.08;
      const apply = (v) => Math.abs(v) < deadzone ? 0 : v;
      const yaw =      Math.round(128 + apply(gp.axes[0]) * 127);
      const throttle =  Math.round(128 - apply(gp.axes[1]) * 127);
      const roll =      Math.round(128 + apply(gp.axes[2]) * 127);
      const pitch =     Math.round(128 + apply(gp.axes[3]) * 127);
      queueJoystick({ throttle, yaw, roll, pitch });
      document.getElementById('tThrottle').textContent = throttle;
      document.getElementById('tYaw').textContent = yaw;
      document.getElementById('tRoll').textContent = roll;
      document.getElementById('tPitch').textContent = pitch;
    }
  }
  requestAnimationFrame(pollGamepad);
}
requestAnimationFrame(pollGamepad);

// -- Periodic state poll ---------------------------------------------------
setInterval(async () => {
  const r = await api('state');
  if (r.connected !== undefined) {
    updateUI(r.connected);
    if (r.pitch_trim !== undefined) {
      document.getElementById('trimPitch').textContent = (r.pitch_trim > 0 ? '+' : '') + r.pitch_trim;
      document.getElementById('trimRoll').textContent = (r.roll_trim > 0 ? '+' : '') + r.roll_trim;
    }
    if (r.video_fps !== undefined) {
      document.getElementById('videoFps').textContent = r.video_fps;
      document.getElementById('videoFrames').textContent = r.video_frames_decoded;
    }
  }
}, 3000);

// -- Autopilot controls ----------------------------------------------------
let autopilotActive = false;

function highlightAPBtn(activeId) {
  document.querySelectorAll('.ap-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(activeId).classList.add('active');
}

async function setAutopilot(mode) {
  if (mode === 'off') {
    const r = await api('autopilot/disable', {});
    if (r.ok) {
      autopilotActive = false;
      highlightAPBtn('btnAPOff');
      document.getElementById('apStatus').textContent = 'Autopilot off';
      addLog('Autopilot disabled — manual control', 'warn');
      stopVideoStream();
    }
  } else {
    const r = await api('autopilot/enable', { mode });
    if (r.ok) {
      // Enable returns immediately — autopilot starts in background
      autopilotActive = true;
      apPolling = true;
      highlightAPBtn(mode === 'hover' ? 'btnAPHover' : mode === 'explore' ? 'btnAPExplore' : 'btnAPML');
      document.getElementById('apStatus').textContent = 'Starting...';
      document.getElementById('apEventLog').style.display = 'block';
      document.getElementById('apEventLog').innerHTML = '<div style="color:#888;">Waiting for autopilot events...</div>';
      addLog('Autopilot starting: ' + mode + ' (settling + ramp ~7s)', 'ok');
      startVideoStream();
    } else {
      addLog('Autopilot error: ' + (r.error || ''), 'error');
    }
  }
}

let testRampRunning = false;
async function doTestRamp() {
  if (testRampRunning) {
    addLog('Test ramp already running — wait for it to finish', 'warn');
    return;
  }
  testRampRunning = true;
  apPolling = true;
  const btn = document.getElementById('btnTestRamp');
  btn.textContent = 'Ramp Running...';
  btn.disabled = true;
  document.getElementById('apEventLog').style.display = 'block';
  document.getElementById('apEventLog').innerHTML = '<div style="color:#888;">Test ramp starting... (connect + settle 5s + ramp 2s + hold 3s)</div>';
  addLog('Test Ramp: started — watch for motors ~7s from now', 'ok');

  const r = await api('test_ramp', {});
  if (!r.ok) {
    addLog('Test Ramp failed: ' + (r.error || 'unknown'), 'error');
  }

  // Poll for 15 seconds to show progress
  let polls = 0;
  const pollTimer = setInterval(async () => {
    polls++;
    const st = await api('autopilot/state');
    // Show drone state during test ramp
    const logEl = document.getElementById('apEventLog');
    const stateInfo = 'Drone: connected=' + st.drone_connected +
                      ' armed=' + st.drone_armed +
                      ' throttle=0x' + (st.drone_throttle || 0).toString(16).toUpperCase().padStart(2, '0');
    if (polls <= 30) {
      logEl.innerHTML += '<div>' + stateInfo + '</div>';
      logEl.scrollTop = logEl.scrollHeight;
    }
    if (polls >= 30) {
      clearInterval(pollTimer);
      testRampRunning = false;
      apPolling = false;
      btn.textContent = 'Test Ramp';
      btn.disabled = false;
      addLog('Test Ramp: sequence complete', 'ok');
    }
  }, 500);
}

function startVideoStream() {
  document.getElementById('videoFeed').src = '/api/video/stream?' + Date.now();
}

function stopVideoStream() {
  document.getElementById('videoFeed').src = '';
}

function updateThreatBar(id, valId, value) {
  const bar = document.getElementById(id);
  const valEl = document.getElementById(valId);
  const pct = Math.round(value * 100);
  bar.style.width = pct + '%';
  valEl.textContent = pct + '%';
  // Color: green < 30%, yellow < 60%, red >= 60%
  if (value < 0.3) bar.style.background = 'var(--success)';
  else if (value < 0.6) bar.style.background = 'var(--warn)';
  else bar.style.background = 'var(--danger)';
}

// Poll autopilot state (also used during test ramp)
let apPolling = false;
setInterval(async () => {
  if (!autopilotActive && !apPolling) return;
  const r = await api('autopilot/state');
  if (r.obstacle_map) {
    updateThreatBar('threatLeft', 'threatLeftVal', r.obstacle_map.left_threat);
    updateThreatBar('threatCenter', 'threatCenterVal', r.obstacle_map.center_threat);
    updateThreatBar('threatRight', 'threatRightVal', r.obstacle_map.right_threat);
  }
  document.getElementById('apFrames').textContent = r.video_frames || 0;
  document.getElementById('apAvoid').textContent = r.avoidance_events || 0;

  // Show event log from autopilot
  if (r.event_log && r.event_log.length > 0) {
    const logEl = document.getElementById('apEventLog');
    logEl.style.display = 'block';
    logEl.innerHTML = r.event_log.map(e => '<div>' + e + '</div>').join('');
    logEl.scrollTop = logEl.scrollHeight;
  }

  if (r.error) {
    document.getElementById('apStatus').textContent = 'ERROR: ' + r.error;
    document.getElementById('apStatus').style.color = '#f55';
    addLog('Autopilot error: ' + r.error, 'error');
    autopilotActive = false;
    highlightAPBtn('btnAPOff');
    stopVideoStream();
  } else if (r.starting) {
    document.getElementById('apStatus').textContent =
      'Starting... T=0x' + (r.drone_throttle || 0).toString(16).toUpperCase().padStart(2, '0') +
      ' armed=' + r.drone_armed;
    document.getElementById('apStatus').style.color = '#ee8';
  } else if (r.user_override) {
    document.getElementById('apStatus').textContent = 'PAUSED (user override)';
    document.getElementById('apStatus').style.color = '#e8e';
  } else if (r.enabled) {
    document.getElementById('apStatus').textContent =
      'Mode: ' + r.mode + ' | T=0x' + (r.drone_throttle || 0).toString(16).toUpperCase().padStart(2, '0');
    document.getElementById('apStatus').style.color = '#8f8';
  } else if (!r.enabled && !r.starting && autopilotActive) {
    // Autopilot was disabled externally
    autopilotActive = false;
    highlightAPBtn('btnAPOff');
    document.getElementById('apStatus').style.color = 'var(--muted)';
    stopVideoStream();
  }
}, 500);

// -- Trim controls ---------------------------------------------------------
async function doTrim(axis, delta) {
  const body = {};
  if (axis === 'pitch') body.pitch_delta = delta;
  if (axis === 'roll') body.roll_delta = delta;
  const r = await api('trim', body);
  if (r.ok) {
    document.getElementById('trimPitch').textContent = (r.pitch_trim > 0 ? '+' : '') + r.pitch_trim;
    document.getElementById('trimRoll').textContent = (r.roll_trim > 0 ? '+' : '') + r.roll_trim;
    addLog(`Trim: pitch=${r.pitch_trim} roll=${r.roll_trim}`, 'ok');
  }
}

async function doTrimReset() {
  const r = await api('trim', { pitch: 0, roll: 0 });
  if (r.ok) {
    document.getElementById('trimPitch').textContent = '0';
    document.getElementById('trimRoll').textContent = '0';
    addLog('Trim reset to zero', 'ok');
  }
}

// -- ML Behavioral Cloning -------------------------------------------------
let mlRecording = false;
let mlSelectedSessions = new Set();
let mlSelectedModel = null;
let mlTrainPollTimer = null;

async function mlToggleRecord() {
  if (mlRecording) {
    await api('ml/record/stop', {});
    mlRecording = false;
    document.getElementById('btnRecord').textContent = 'Record';
    document.getElementById('btnRecord').className = 'btn btn-sm btn-success';
    document.getElementById('mlRecordStatus').textContent = 'Stopped';
    mlRefreshSessions();
  } else {
    const name = document.getElementById('mlSessionName').value.trim();
    if (!name) { addLog('Enter a session name first', 'warn'); return; }
    const r = await api('ml/record/start', { name });
    if (r.ok) {
      mlRecording = true;
      document.getElementById('btnRecord').textContent = 'Stop';
      document.getElementById('btnRecord').className = 'btn btn-sm btn-danger';
      addLog('Recording session: ' + name, 'ok');
    } else {
      addLog('Record error: ' + (r.error || ''), 'error');
    }
  }
}

async function mlRefreshSessions() {
  const r = await api('ml/sessions');
  const el = document.getElementById('mlSessionsList');
  if (!r.sessions || r.sessions.length === 0) {
    el.innerHTML = '<div style="color:var(--muted);">No sessions</div>';
    return;
  }
  el.innerHTML = r.sessions.map(s => {
    const sel = mlSelectedSessions.has(s.session_name);
    return '<div style="display:flex; justify-content:space-between; align-items:center; padding:3px 4px; cursor:pointer; border-radius:4px;' +
           (sel ? ' background:var(--accent); color:#fff;' : '') +
           '" onclick="mlToggleSession(\\'' + s.session_name + '\\', this)">' +
           '<span>' + s.session_name + ' (' + s.frame_count + ' frames, ' + s.duration + 's)</span>' +
           '<span style="cursor:pointer; color:#f55; font-size:14px;" onclick="event.stopPropagation(); mlDeleteSession(\\'' + s.session_name + '\\')">&times;</span>' +
           '</div>';
  }).join('');
}

function mlToggleSession(name, el) {
  if (mlSelectedSessions.has(name)) {
    mlSelectedSessions.delete(name);
    el.style.background = '';
    el.style.color = '';
  } else {
    mlSelectedSessions.add(name);
    el.style.background = 'var(--accent)';
    el.style.color = '#fff';
  }
}

async function mlDeleteSession(name) {
  await fetch('/api/ml/sessions/' + name, { method: 'DELETE' });
  mlSelectedSessions.delete(name);
  mlRefreshSessions();
  addLog('Deleted session: ' + name, 'warn');
}

async function mlStartTrain() {
  const sessions = Array.from(mlSelectedSessions);
  if (sessions.length === 0) { addLog('Select sessions first', 'warn'); return; }
  const r = await api('ml/train', { sessions, name: 'default', epochs: 50 });
  if (r.ok) {
    addLog('Training started on ' + sessions.length + ' sessions', 'ok');
    document.getElementById('btnTrainStop').style.display = '';
    document.getElementById('mlTrainProgress').style.display = '';
    mlTrainPollTimer = setInterval(mlPollTrain, 1000);
  } else {
    addLog('Train error: ' + (r.error || ''), 'error');
  }
}

async function mlStopTrain() {
  await api('ml/train/stop', {});
  if (mlTrainPollTimer) { clearInterval(mlTrainPollTimer); mlTrainPollTimer = null; }
  document.getElementById('btnTrainStop').style.display = 'none';
  document.getElementById('mlTrainStatus').textContent = 'Stopped';
  addLog('Training stopped', 'warn');
}

async function mlPollTrain() {
  const r = await api('ml/train/status');
  if (!r.running && mlTrainPollTimer) {
    clearInterval(mlTrainPollTimer);
    mlTrainPollTimer = null;
    document.getElementById('btnTrainStop').style.display = 'none';
    if (r.error) {
      document.getElementById('mlTrainStatus').textContent = 'Error: ' + r.error;
      addLog('Training error: ' + r.error, 'error');
    } else {
      document.getElementById('mlTrainStatus').textContent = 'Done! Best val: ' + (r.best_val_loss || '-');
      addLog('Training complete! Best val loss: ' + r.best_val_loss, 'ok');
      mlRefreshModels();
    }
    return;
  }
  const pct = r.total_epochs > 0 ? Math.round(r.epoch / r.total_epochs * 100) : 0;
  document.getElementById('mlTrainBar').style.width = pct + '%';
  document.getElementById('mlTrainEpoch').textContent = r.epoch;
  document.getElementById('mlTrainTotal').textContent = r.total_epochs;
  document.getElementById('mlTrainLoss').textContent = r.train_loss ? r.train_loss.toFixed(5) : '-';
  document.getElementById('mlValLoss').textContent = r.val_loss ? r.val_loss.toFixed(5) : '-';
  const eta = r.eta_s > 0 ? Math.round(r.eta_s) + 's' : '-';
  document.getElementById('mlTrainStatus').textContent = 'Training... ETA: ' + eta;
}

async function mlRefreshModels() {
  const r = await api('ml/models');
  const el = document.getElementById('mlModelsList');
  if (!r.models || r.models.length === 0) {
    el.innerHTML = '<div style="color:var(--muted);">No models</div>';
    return;
  }
  el.innerHTML = r.models.map(m => {
    const sel = mlSelectedModel === m.name;
    return '<div style="display:flex; justify-content:space-between; align-items:center; padding:3px 4px; cursor:pointer; border-radius:4px;' +
           (sel ? ' background:#537; color:#fff;' : '') +
           '" onclick="mlSelectModel(\\'' + m.name + '\\', this)">' +
           '<span>' + m.name + ' (val: ' + (m.val_loss ? m.val_loss.toFixed(5) : '?') + ', ' + m.param_count + ' params)</span>' +
           '<span style="cursor:pointer; color:#f55; font-size:14px;" onclick="event.stopPropagation(); mlDeleteModel(\\'' + m.name + '\\')">&times;</span>' +
           '</div>';
  }).join('');
}

function mlSelectModel(name, el) {
  el.parentElement.querySelectorAll('div').forEach(d => { d.style.background = ''; d.style.color = ''; });
  mlSelectedModel = name;
  el.style.background = '#537';
  el.style.color = '#fff';
}

async function mlDeleteModel(name) {
  await fetch('/api/ml/models/' + name, { method: 'DELETE' });
  if (mlSelectedModel === name) mlSelectedModel = null;
  mlRefreshModels();
  addLog('Deleted model: ' + name, 'warn');
}

async function mlLoadModel() {
  if (!mlSelectedModel) { addLog('Select a model first', 'warn'); return; }
  const r = await api('ml/model/load', { name: mlSelectedModel });
  if (r.ok) {
    document.getElementById('mlModelInfo').textContent = 'Loaded: ' + (r.name || mlSelectedModel) + ' (val: ' + (r.val_loss || '?') + ')';
    addLog('Model loaded: ' + mlSelectedModel, 'ok');
  } else {
    addLog('Load error: ' + (r.error || ''), 'error');
  }
}

async function mlUnloadModel() {
  await api('ml/model/unload', {});
  document.getElementById('mlModelInfo').textContent = 'No model loaded';
  addLog('Model unloaded', 'warn');
}

setInterval(async () => {
  if (!mlRecording) return;
  const r = await api('ml/record/state');
  if (r.is_recording) {
    document.getElementById('mlRecordStatus').textContent =
      'Recording: ' + r.frame_count + ' frames, ' + r.duration + 's';
  } else {
    mlRecording = false;
    document.getElementById('btnRecord').textContent = 'Record';
    document.getElementById('btnRecord').className = 'btn btn-sm btn-success';
    document.getElementById('mlRecordStatus').textContent = 'Stopped';
  }
}, 1000);

mlRefreshSessions();
mlRefreshModels();

addLog('Q10 Controller ready. Connect to drone WiFi, then click Connect.');
addLog('Keys: W=throttle up, S=throttle down, A/D=yaw, I/K or Arrows=pitch/roll');
addLog('Space=takeoff/land, Esc=emergency stop. Throttle starts at ZERO.');
</script>
</body>
</html>"""


# -- API routes -------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(HTML_PAGE)


@app.route("/api/connect", methods=["POST"])
def api_connect():
    try:
        drone.connect()
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/disconnect", methods=["POST"])
def api_disconnect():
    try:
        drone.disconnect()
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/joystick", methods=["POST"])
def api_joystick():
    data = request.get_json(silent=True) or {}
    # If autopilot is active, notify it of user override
    if drone.autopilot.enabled:
        drone.autopilot.notify_user_input()
    drone.set_joystick(
        roll=data.get("roll"),
        pitch=data.get("pitch"),
        throttle=data.get("throttle"),
        yaw=data.get("yaw"),
    )
    return jsonify(ok=True)


@app.route("/api/command", methods=["POST"])
def api_command():
    data = request.get_json(silent=True) or {}
    cmd = data.get("cmd", "")
    try:
        if cmd == "takeoff":
            drone.takeoff()
        elif cmd == "land":
            drone.land()
        elif cmd == "emergency":
            drone.emergency_stop()
        elif cmd == "calibrate":
            drone.calibrate_gyro()
        elif cmd == "headless_on":
            drone.headless_mode(True)
        elif cmd == "headless_off":
            drone.headless_mode(False)
        elif cmd == "flip":
            drone.flip()
        elif cmd == "photo":
            drone.take_photo()
        elif cmd == "video":
            drone.toggle_video()
        elif cmd == "speed1":
            drone.set_speed(1)
        elif cmd == "speed2":
            drone.set_speed(2)
        elif cmd == "speed3":
            drone.set_speed(3)
        else:
            return jsonify(ok=False, error=f"Unknown command: {cmd}")
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/trim", methods=["POST"])
def api_trim():
    data = request.get_json(silent=True) or {}
    if "pitch" in data or "roll" in data:
        drone.set_trim(pitch=data.get("pitch"), roll=data.get("roll"))
    else:
        drone.adjust_trim(
            pitch_delta=data.get("pitch_delta", 0),
            roll_delta=data.get("roll_delta", 0),
        )
    return jsonify(ok=True, pitch_trim=drone.pitch_trim, roll_trim=drone.roll_trim)


@app.route("/api/autopilot/enable", methods=["POST"])
def api_autopilot_enable():
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "hover")
    if mode not in ("hover", "explore", "ml"):
        return jsonify(ok=False, error=f"Unknown mode: {mode}")
    if drone.autopilot.enabled:
        return jsonify(ok=True, mode=mode, status="already_enabled")
    if drone.autopilot.starting:
        return jsonify(ok=True, mode=mode, status="starting")

    # Run enable() in background thread — it blocks for ~7s (settle + ramp)
    def _start():
        try:
            drone.autopilot.enable(mode=mode)
        except Exception as e:
            drone.autopilot.error = str(e)
            drone.autopilot.starting = False
            print(f"\n{'!'*60}")
            print(f"  AUTOPILOT ENABLE FAILED: {e}")
            print(f"{'!'*60}\n")
            drone.log.error("Autopilot enable failed: %s", e, exc_info=True)

    drone.autopilot.error = None
    drone.autopilot.starting = True
    threading.Thread(target=_start, daemon=True, name="ap-enable").start()
    return jsonify(ok=True, mode=mode, status="starting")


@app.route("/api/autopilot/disable", methods=["POST"])
def api_autopilot_disable():
    try:
        drone.autopilot.disable()
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/autopilot/state")
def api_autopilot_state():
    return jsonify(**drone.autopilot.get_state())


@app.route("/api/autopilot/configure", methods=["POST"])
def api_autopilot_configure():
    data = request.get_json(silent=True) or {}
    if "sensitivity" in data:
        drone.autopilot.set_sensitivity(int(data["sensitivity"]))
    if "threshold" in data:
        drone.autopilot.avoid_threshold = float(data["threshold"])
    if "cruise_throttle" in data:
        drone.autopilot.cruise_throttle = int(data["cruise_throttle"])
    if "forward_pitch" in data:
        drone.autopilot.forward_pitch = int(data["forward_pitch"])
    if "settle_time" in data:
        drone.autopilot.settle_time = max(1.0, min(15.0, float(data["settle_time"])))
    return jsonify(ok=True)


@app.route("/api/test_ramp", methods=["POST"])
def api_test_ramp():
    """Test throttle ramp WITHOUT autopilot — isolates connect/settle/ramp.

    Usage:
      curl -X POST localhost:5050/api/test_ramp
      curl -X POST localhost:5050/api/test_ramp -H 'Content-Type: application/json' \\
           -d '{"throttle": 112, "settle": 5, "hold": 3}'
    """
    data = request.get_json(silent=True) or {}
    target_throttle = int(data.get("throttle", 0xB0))
    settle_secs = float(data.get("settle", 5.0))
    hold_secs = float(data.get("hold", 3.0))
    steps = []

    def _ramp():
        try:
            # Step 1: FULL RECONNECT — the drone has an armed timeout.
            # After the handshake, there's a short window (~10s) where
            # throttle is accepted. After that, the drone silently ignores
            # throttle. A full disconnect+reconnect resets this window.
            print(f"\n{'='*50}")
            print(f"  TEST RAMP: Full reconnect to reset armed window...")
            print(f"{'='*50}")
            steps.append("disconnecting...")
            if drone.connected:
                drone.disconnect()
                time.sleep(0.5)
            steps.append("connecting...")
            print(f"  TEST RAMP: Connecting...")
            drone.connect()
            steps.append("connected")
            print(f"  TEST RAMP: Connected — ramping IMMEDIATELY")

            # Step 2: LAUNCH — two pump sequence: 0xFF→0x80, wait 2s, 0xFF→0x80
            drone.set_joystick(throttle=0xFF)
            steps.append("pump 1: T=0xFF")
            print(f"  TEST RAMP: Pump 1: T=0xFF")
            time.sleep(0.05)
            drone.set_joystick(throttle=0x80)
            steps.append("pump 1: T=0x80")
            print(f"  TEST RAMP: Pump 1: T=0x80")

            print(f"  TEST RAMP: Waiting 2s...")
            time.sleep(2.0)

            drone.set_joystick(throttle=0xFF)
            steps.append("pump 2: T=0xFF")
            print(f"  TEST RAMP: Pump 2: T=0xFF")
            time.sleep(0.05)
            drone.set_joystick(throttle=0x80)
            steps.append("pump 2: T=0x80")
            print(f"  TEST RAMP: Pump 2: T=0x80")

            # Hold at cruise
            time.sleep(0.5)
            drone.set_joystick(throttle=target_throttle)
            print(f"  TEST RAMP: Holding at 0x{target_throttle:02X} for {hold_secs}s...")
            print(f"  TEST RAMP: >>> MOTORS SHOULD BE SPINNING NOW <<<")
            steps.append(f"holding {hold_secs}s at 0x{target_throttle:02X}...")
            time.sleep(hold_secs)

            # Ramp down to center
            print(f"  TEST RAMP: Ramping down...")
            for i in range(10, 0, -1):
                t = int(target_throttle * i / 10)
                drone.set_joystick(throttle=t)
                time.sleep(0.1)
            drone.set_joystick(throttle=0x80)
            steps.append("ramp down complete")
            print(f"  TEST RAMP: Done — throttle back to center")
            print(f"{'='*50}\n")

        except Exception as e:
            msg = f"ERROR: {e}"
            steps.append(msg)
            print(f"  TEST RAMP: {msg}")

    # Run in background thread (takes ~10 seconds)
    threading.Thread(target=_ramp, daemon=True, name="test-ramp").start()
    return jsonify(ok=True, message="Test ramp started — watch terminal output",
                   target_throttle=f"0x{target_throttle:02X}",
                   settle_secs=settle_secs, hold_secs=hold_secs)


@app.route("/api/video/frame")
def api_video_frame():
    """Return latest decoded frame as JPEG for the web UI."""
    frame = drone.video_decoder.get_frame()
    if frame is None:
        # Return a small black placeholder image
        frame = np.zeros((240, 320, 3), dtype=np.uint8)
        cv2.putText(frame, "No Video", (80, 130),
                    cv2.FONT_HERSHEY_SIMPLEX, 1, (100, 100, 100), 2)

    # If autopilot is running, use the annotated frame instead
    if drone.autopilot.enabled and drone.autopilot.last_obstacle_map:
        obs_frame = drone.autopilot.last_obstacle_map.annotated_frame
        if obs_frame is not None:
            frame = obs_frame

    _, jpeg = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 70])
    return Response(jpeg.tobytes(), mimetype='image/jpeg',
                    headers={'Cache-Control': 'no-cache'})


@app.route("/api/video/stream")
def api_video_stream():
    """MJPEG stream — continuous multipart/x-mixed-replace of JPEG frames."""
    def generate():
        while True:
            frame = drone.video_decoder.wait_frame(0.2)
            if frame is None:
                # Generate a "No Video" placeholder
                frame = np.zeros((240, 320, 3), dtype=np.uint8)
                cv2.putText(frame, "No Video", (80, 130),
                            cv2.FONT_HERSHEY_SIMPLEX, 1, (100, 100, 100), 2)

            # If autopilot has obstacle annotations, overlay those
            if drone.autopilot.enabled and drone.autopilot.last_obstacle_map:
                obs_frame = drone.autopilot.last_obstacle_map.annotated_frame
                if obs_frame is not None:
                    frame = obs_frame

            _, jpeg = cv2.imencode('.jpg', frame, [cv2.IMWRITE_JPEG_QUALITY, 65])
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' +
                   jpeg.tobytes() + b'\r\n')

    return Response(generate(),
                    mimetype='multipart/x-mixed-replace; boundary=frame',
                    headers={'Cache-Control': 'no-cache, no-store'})


# -- ML API routes (optional — all return errors gracefully if ml/ missing) -

@app.route("/api/ml/record/start", methods=["POST"])
def api_ml_record_start():
    if ml_collector is None:
        return jsonify(ok=False, error="ML module not installed")
    data = request.get_json(silent=True) or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify(ok=False, error="Session name required")
    try:
        ml_collector.start_session(name)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/ml/record/stop", methods=["POST"])
def api_ml_record_stop():
    if ml_collector is None:
        return jsonify(ok=False, error="ML module not installed")
    try:
        ml_collector.stop_session()
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/ml/record/state")
def api_ml_record_state():
    if ml_collector is None:
        return jsonify(recording=False, session=None, frames=0)
    return jsonify(**ml_collector.get_state())


@app.route("/api/ml/sessions")
def api_ml_sessions():
    if DataCollector is None:
        return jsonify(sessions=[])
    return jsonify(sessions=DataCollector.list_sessions())


@app.route("/api/ml/sessions/<name>", methods=["DELETE"])
def api_ml_session_delete(name):
    if DataCollector is None:
        return jsonify(ok=False, error="ML module not installed")
    try:
        DataCollector.delete_session(name)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/ml/train", methods=["POST"])
def api_ml_train():
    global ml_trainer
    from ml.trainer import Trainer
    data = request.get_json(silent=True) or {}
    sessions = data.get("sessions", [])
    if not sessions:
        return jsonify(ok=False, error="No sessions selected")
    model_name = data.get("name", "default")
    epochs = int(data.get("epochs", 50))
    try:
        ml_trainer = Trainer(
            session_names=sessions,
            model_name=model_name,
            epochs=epochs,
        )
        ml_trainer.start()
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/ml/train/status")
def api_ml_train_status():
    if ml_trainer is None:
        return jsonify(running=False)
    return jsonify(**ml_trainer.get_status())


@app.route("/api/ml/train/stop", methods=["POST"])
def api_ml_train_stop():
    if ml_trainer is not None:
        ml_trainer.stop()
    return jsonify(ok=True)


@app.route("/api/ml/models")
def api_ml_models():
    from ml.trainer import Trainer
    return jsonify(models=Trainer.list_models())


@app.route("/api/ml/model/load", methods=["POST"])
def api_ml_model_load():
    data = request.get_json(silent=True) or {}
    name = data.get("name", "default")
    from ml.trainer import MODELS_PATH
    model_path = str(MODELS_PATH / f"{name}.pt")
    try:
        pred = _get_predictor()
        pred.load_model(model_path)
        return jsonify(ok=True, **pred.get_model_info())
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/ml/model/unload", methods=["POST"])
def api_ml_model_unload():
    pred = _get_predictor()
    pred._model = None
    pred._ema = None
    return jsonify(ok=True)


@app.route("/api/ml/models/<name>", methods=["DELETE"])
def api_ml_model_delete(name):
    from ml.trainer import Trainer
    try:
        Trainer.delete_model(name)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(ok=False, error=str(e))


@app.route("/api/ml/model/info")
def api_ml_model_info():
    pred = _get_predictor()
    return jsonify(**pred.get_model_info())


@app.route("/api/state")
def api_state():
    return jsonify(**drone.get_state())


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import subprocess
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(name)s] %(levelname)s %(message)s")
    # Suppress Flask/werkzeug request logs — they flood the terminal
    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    print()
    print("=" * 60)
    print("  Q10 Drone Controller (EF 02 Protocol)")
    print("  Reverse-engineered from stock app capture")
    print("=" * 60)
    print()

    # Check network setup (cross-platform: Linux ip addr, macOS ifconfig)
    has_169_3 = False
    has_drone_wifi = False
    try:
        # Try 'ip addr' first (Linux/Pi), fall back to 'ifconfig' (macOS)
        try:
            result = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=5)
        except FileNotFoundError:
            result = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.split('\n'):
            if "192.168.0." in line:
                has_drone_wifi = True
            if "192.168.169.3" in line:
                has_169_3 = True
    except Exception:
        pass

    if not has_drone_wifi and not has_169_3:
        print("  WARNING: Not connected to drone WiFi!")
        print("  Connect to the drone's WiFi hotspot first.")
        print()
    elif not has_169_3:
        print("  WARNING: 192.168.169.3 alias not set up!")
        print("  The drone only accepts commands from this IP.")
        print("  Fix: sudo bash setup_network.sh")
        print()
    else:
        print("  Network OK: 192.168.169.3 is available")
        print()

    print(f"  Binding to: {CLIENT_IP}:{STOCK_SOURCE_PORT}")
    print(f"  Open http://localhost:5050")
    print()
    try:
        app.run(host="0.0.0.0", port=5050, debug=False, threaded=True)
    finally:
        drone.disconnect()
