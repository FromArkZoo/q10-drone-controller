# Q10 Drone Controller

Custom controller for the AVIALOGIC Q10 / HASAKEE Q10 mini drone, built by reverse-engineering the WiFi protocol from packet captures.

## Drone Details
- Model: AVIALOGIC Q10 (branded HASAKEE Q10)
- Drone IP: 192.168.0.1 (drone creates its own WiFi hotspot)
- Internal tunnel: 192.168.169.x subnet (drone=.1, client=.2)
- Stock app: "HASAKEE Q10" on iOS/Android

## Reverse-Engineered Protocol

### Ports
- Command: UDP 8800 (client → drone)
- Video: UDP from drone:1234 → client ephemeral port
- HTTP: Port 80 (returns 501, config endpoint)

### Packet Format
All commands start with magic byte 0xEF.

### Heartbeat (4 bytes)
ef 00 04 00 — sent every ~500ms

### Control/Joystick Packet (88-160 bytes)
- Bytes 0: 0xEF magic
- Byte 1: 0x02 (control type)
- Bytes 2-3: packet length (LE16)
- Bytes 4-7: protocol header 02 02 00 01
- Byte 8: sub-type (0=basic, 1-3=with sub-messages)
- Bytes 12-15: sequence counter (LE32, incrementing)
- Byte 16: 0x08 (joystick data marker)
- Byte 17: 0x00
- Byte 18: 0x66 (mode flags)
- Byte 19: Roll (0x00=left, 0x80=center, 0xFF=right)
- Byte 20: Pitch (0x00=forward, 0x80=center, 0xFF=back)
- Byte 21: Throttle (0x00=zero, 0x80=hover, 0xFF=full)
- Byte 22: Yaw (0x00=CCW, 0x80=center, 0xFF=CW)
- Bytes 23-24: trim flags 40 40
- Byte 25: checksum/flags 0x99
- Bytes 82-85: device signature 32 4B 14 2D

### Text Command Packet (variable)
- Byte 0: 0xEF
- Byte 1: 0x20
- Bytes 2-3: payload length (BE16)
- Bytes 4-6: 00 01 67
- Byte 7+: ASCII command string

### Known Text Commands (confirmed from capture)
- cmd=2: Connect/Start
- cmd=3: Start video stream
- cmd=106: Calibrate gyro

### Likely Commands (unconfirmed, based on similar HASAKEE drones)
- cmd=1: Takeoff
- cmd=7: Emergency stop
- cmd=5: Take photo
- cmd=6: Toggle video recording
- cmd=100/101/102: Speed modes 1/2/3
- cmd=103/104: Headless mode on/off
- cmd=105: 3D flip

### Connection Handshake (observed sequence)
1. Heartbeat ef000400 x3 (200ms apart)
2. Init control packet (88 bytes, sub_type=0) x2
3. Enable command: ef 20 06 00 01 65
4. Init control packet (128 bytes, sub_type=2) x2
5. Text cmd=2 (connect)
6. Text cmd=3 (start video)
7. Text cmd=106 (calibrate)
8. Begin heartbeat (500ms) + control loop (20Hz)

### Video Stream Format
- UDP from drone:1234, all packets start with 0x93
- 36-byte custom header, then H.264 video payload
- ~1080 bytes per packet, sequence counter at header byte 32
- No JPEG markers — pure H.264 with custom framing
- Keyframes span multiple packets

## Project Structure
- q10_controller.py: Main controller with Flask web UI
- tools/drone_recon.py: Network discovery toolkit
- tools/drone_analyser.py: Pcap capture analyser
- captures/: Place .pcap files here

## TODO
- Verify text command IDs with targeted captures
- Build H.264 video reassembly from custom-framed UDP packets
- Add FPV video display to web UI
- Add gamepad support (Web Gamepad API)
- Test joystick range mapping
