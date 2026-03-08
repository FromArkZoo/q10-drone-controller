# Q10 Drone Controller

Custom controller for the AVIALOGIC Q10 / HASAKEE Q10 mini drone, built by reverse-engineering the WiFi protocol from iPhone stock app packet captures.

## Drone Details
- Model: AVIALOGIC Q10 (branded HASAKEE Q10)
- Drone WiFi gateway: 192.168.0.1 (NOT used for control)
- Drone control IP: 192.168.169.1 (all commands go here via 169.x tunnel subnet)
- Client tunnel IP: **192.168.169.3** (MUST be .3 — stock app uses .3, drone may reject .2)
- Stock app: "HASAKEE Q10" on iOS/Android
- Command port: UDP 8800

## Reverse-Engineered Protocol (confirmed from stock app capture)

### Ports
- Command: UDP 8800 (client → drone at 192.168.169.1)
- Video: UDP from drone:1234 → client ephemeral port
- HTTP: Port 80 (returns 501, config endpoint)

### Packet Format
All commands start with magic byte 0xEF.

### Heartbeat (4 bytes)
`ef 00 04 00` — sent every ~500ms to keep connection alive

### Enable Command (6 bytes)
`ef 20 06 00 01 65` — sent once during handshake

### Control/Joystick Packet (88-144 bytes)
- Byte 0: 0xEF (magic)
- Byte 1: 0x02 (control type)
- Bytes 2-3: packet length (LE16)
- Bytes 4-7: protocol header `02 02 00 01`
- Byte 8: sub-type (0=88-byte basic, 1=112-byte with joystick, 2=128-byte)
- Bytes 9-11: `00 00 00`
- Bytes 12-13: sequence counter (LE16, incrementing)
- Bytes 14-15: `00 00`
- Byte 16: 0x08 (joystick data marker)
- Byte 17: 0x00
- Byte 18: 0x66 (joystick block start)
- Byte 19: Roll (0x00=left, 0x80=center, 0xFF=right)
- Byte 20: Pitch (0x00=forward, 0x80=center, 0xFF=back)
- Byte 21: Throttle (0x00=zero, 0x80=hover, 0xFF=full)
- Byte 22: Yaw (0x00=CCW, 0x80=center, 0xFF=CW)
- Bytes 23-24: trim values `40 40`
- Byte 25: 0x99 (joystick block end)
- Bytes 82-85: device signature `32 4B 14 2D` (in packets >= 86 bytes)

### Text Command Packet (variable length)
- Byte 0: 0xEF
- Byte 1: 0x20
- Bytes 2-3: total packet length (LE16, NOT payload length)
- Byte 4: 0x01
- Byte 5: 0x67
- Bytes 6+: ASCII command string in format: `<i=2^bf_ssid=cmd=N>`

**IMPORTANT**: The text format is `<i=2^bf_ssid=cmd=N>`, NOT just `cmd=N`.
The header is `01 67` (2 bytes), NOT `00 01 67` (3 bytes).

### Known Text Commands (confirmed from capture)
- cmd=1: Takeoff / Land toggle — **DOES NOT WORK on this drone** (see Lessons Learned)
- cmd=2: Connect/Start
- cmd=3: Start video stream
- cmd=7: Emergency stop
- cmd=106: Calibrate gyro

### Likely Commands (unconfirmed, based on similar HASAKEE drones)
- cmd=5: Take photo
- cmd=6: Toggle video recording
- cmd=100/101/102: Speed modes 1/2/3
- cmd=103/104: Headless mode on/off
- cmd=105: 3D flip

### Connection Handshake (exact sequence from stock app capture)
1. Heartbeat `ef 00 04 00` x3 (200ms apart)
2. Init control packets (88 bytes, sub_type=0) x2
3. Enable command: `ef 20 06 00 01 65`
4. Control packets (112 bytes, sub_type=1) x2
5. Text command: `<i=2^bf_ssid=cmd=2>` (connect)
6. Text command: `<i=2^bf_ssid=cmd=3>` (start video)
7. Text command: `<i=2^bf_ssid=cmd=106>` (calibrate gyro)
8. Begin continuous: heartbeat (500ms) + control packets (20Hz, mix of 88+112 byte)

### Video Stream Format
- UDP from drone:1234, all packets start with 0x93
- 36-byte custom header, then H.264 video payload
- ~1080 bytes per packet, sequence counter at header byte 32
- No JPEG markers — pure H.264 with custom framing
- Keyframes span multiple packets

## Project Structure
- q10_controller.py: Main controller with Flask web UI (EF 02 protocol)
- setup_network.sh: Network setup — adds 192.168.169.3 alias (run with sudo)
- autopilot/autopilot_controller.py: Autonomous flight controller
- autopilot/video_pipeline.py: H.264 video decoder (ffmpeg)
- autopilot/obstacle_detector.py: Edge/motion obstacle detection
- tools/replay_capture.py: Replay exact stock app packets from pcap capture
- tools/analyze_capture.py: Pcap capture analyser (scapy)
- tools/capture_iphone.sh: iPhone USB traffic capture (macOS rvictl)
- tools/probe_drone.py: Network probe / port scanner
- tools/test_commands.py: Multi-format command tester
- tools/drone_recon.py: Network discovery toolkit
- captures/: Place .pcap files here

## CRITICAL: Network Setup
The drone firmware appears to only accept control commands from IP 192.168.169.3.
When a Mac connects to the drone WiFi, it typically gets .2 instead of .3.

**Before running the controller**, add .3 as an alias:
```bash
sudo bash setup_network.sh
```
This adds 192.168.169.3 as a secondary IP on your WiFi interface.
The controller binds to .3 and the stock app's source port (54288) automatically.

## Lessons Learned (from debugging sessions)

### cmd=1 (Takeoff/Land) Does NOT Work
Despite being in the stock app protocol, cmd=1 has **never** made this drone take off or land. The drone is controlled **purely through throttle values** in the joystick control packets. To fly: just increase the throttle byte (byte 21) from 0x00 upward. No special takeoff command needed.

### Motor Spin Threshold is HIGH (CRITICAL DISCOVERY)
The drone motors will **NOT spin** below a certain throttle value — approximately 0xA0-0xAE (~160-174). Manual flight data shows the user's throttle ranges from 0xAE to 0xE9 (174-233) during actual flight. The old cruise_throttle of 0x70 (112) was far below the motor spin threshold, which is why autopilot never worked. **Cruise throttle must be at least 0xB0 (176) to reliably spin motors.** Max throttle safety cap is 0xE0 (224).

### Manual Flight Method
The user flies using the **on-screen touch joysticks** in the web UI. The left joystick controls throttle (drag up to fly). The `/api/joystick` endpoint and `drone.set_joystick()` are the path that actually makes the drone move.

### Throttle Centers at 0x80 Like Other Axes
All four axes (roll, pitch, throttle, yaw) default to 0x80 (128) at center position. The left joystick starts centered. Motor spin threshold is ~0xA0-0xAE. The autopilot cruise throttle is 0xB0 (~176), max safety cap is 0xE0 (~224). User manual flight typically uses 0xAE-0xE9 (174-233).

### Socket Must Bind to 192.168.169.3
The drone firmware rejects commands from any IP other than .3. The `connect()` method raises a RuntimeError if it can't bind to .3. Always run `sudo bash setup_network.sh` first.

### Autopilot Architecture
- `enable()` runs in a background thread (non-blocking API endpoint)
- Full reconnect before ramping (resets drone state)
- Throttle ramp: 10 steps over 2 seconds (0 → cruise_throttle)
- UI shows "Starting..." during ramp, then "Mode: hover/explore"
- Diagnostic packet logging: first 3 packets, every 10th when throttle>0, every 500th idle
- `self.starting` flag tracks background enable progress
- `self.error` captures any exceptions during enable
- Event log ring buffer (50 entries) queryable via `/api/autopilot/state`

### Autopilot State Machine
`self.enabled` is set to True ONLY after the throttle ramp completes, not at the start of `enable()`. `self.starting` is True during the settle+ramp phase. This prevents double-click race conditions.

## TODO
- **Test autopilot throttle ramp** — verify motors spin after settle delay
- Build H.264 video reassembly from custom-framed UDP packets
- Add FPV video display to web UI
- Test all text command IDs with the drone
- Test joystick range mapping (confirm 0x00-0xFF range for each axis)
