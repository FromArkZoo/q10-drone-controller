# Q10 Drone Controller

**Reverse-engineered WiFi protocol controller for the AVIALOGIC Q10 mini drone, with an OpenCV video pipeline and a PyTorch behavioural-cloning autopilot.**

This started as "can I fly this drone from my laptop without the stock app?" and ended as a full-stack reverse-engineering project: WiFi packet capture → protocol decode → handshake replay → manual flight → autonomous flight driven by computer vision.

## The reverse-engineering story

The Q10 ships with a closed iOS app and no public API. To talk to the drone directly I:

1. **Captured** the iPhone ↔ drone WiFi traffic via the macOS `rvictl` USB bridge while flying the stock app ([`tools/capture_iphone.sh`](tools/capture_iphone.sh)), yielding a ~23 MB `.pcap`
2. **Decoded** the UDP packets byte-by-byte. Every command is prefixed with magic byte `0xEF` and falls into one of four types: heartbeat (4 bytes), enable (6 bytes), joystick / control (88–144 bytes), or text command (variable)
3. **Replayed** the exact 8-step handshake sequence against the drone and confirmed it worked
4. **Found the key insight**: the stock app sends a `cmd=1` ("takeoff") on every flight, but it has no effect. Flight control is **purely throttle-based**, and the motor-spin threshold is empirically around `0xA0`–`0xAE`. The stock app's resting cruise value of `0x70` was below threshold — which explained why every earlier attempt at a custom controller had been silently failing
5. **Rebound the network** — the drone firmware rejects commands from any source IP except `192.168.169.3`, so [`setup_network.sh`](setup_network.sh) creates a secondary IP alias on the host to match

The packet captures and replay tooling are committed as evidence:

- [`captures/`](captures/) — raw pcaps of the stock iOS app talking to the drone
- [`tools/analyze_capture.py`](tools/analyze_capture.py) — pcap introspection (magic-byte scanning, packet classification)
- [`tools/replay_capture.py`](tools/replay_capture.py) — deterministically reproduces stock-app sequences from a pcap, which was the primary way I validated protocol understanding

Full protocol notes — packet layouts, the handshake sequence, confirmed command IDs, throttle thresholds, and lessons learned — are in [`CLAUDE.md`](CLAUDE.md).

## Architecture

```
q10-drone-controller/
├── q10_controller.py              # Flask app + Q10Controller class (protocol + joystick)
├── setup_network.sh               # Bind host to 192.168.169.3 for drone compatibility
├── autopilot/
│   ├── autopilot_controller.py    # Enable → handshake → settle → ramp → hover / explore
│   ├── video_pipeline.py          # Custom-framed video reassembly from UDP:1234
│   └── obstacle_detection.py      # Lucas-Kanade optical flow, L/C/R threat regions
├── ml/
│   ├── model.py                   # DronePilotNet (NVIDIA PilotNet-inspired CNN, ~200K params)
│   ├── predictor.py               # Inference wrapper (.pt → roll, pitch, throttle, yaw)
│   ├── trainer.py                 # Behavioural-cloning training loop
│   └── data_collector.py          # Logs joystick + frames while flying manually
├── tools/
│   ├── drone_recon.py             # Network discovery
│   ├── analyze_capture.py         # Pcap → decoded packet stream
│   ├── replay_capture.py          # Deterministic stock-app replay
│   └── capture_iphone.sh          # rvictl USB packet capture
├── captures/                      # .pcap evidence
└── templates/, static/            # Flask web UI
```

**Protocol layer.** UDP at `192.168.169.1:8800`. Four packet types (heartbeat, enable, joystick / control, text). Heartbeats every ~500 ms keep the connection alive; the enable command runs during handshake; joystick / control packets carry roll / pitch / throttle / yaw plus a device signature. Order and timing matter — the drone firmware is rigid, which is actually a feature: the protocol is deterministic and reproducible.

**Video layer.** The drone streams video over UDP:1234 in a custom framing format: each frame spans ~55 fragments, with a 36-byte outer header and 20-byte sub-header per fragment. The raw payload is "headless JPEG" — JPEG scan data without the SOI / DQT / SOF / DHT / SOS markers decoders expect. The pipeline reassembles the fragments and prepends a pre-built 128-byte quantization-table header before handing bytes to OpenCV, yielding 320 × 240 RGB at ~15 FPS into a 3-frame ring buffer.

**Autopilot.** A two-layer controller:

- **Heuristic** — sparse Lucas-Kanade optical flow on a 160 × 120 downsample, dividing the frame into left / centre / right threat regions
- **ML** — `DronePilotNet`, a PilotNet-style CNN, takes the 320 × 240 RGB frame and outputs four continuous values in `[0, 1]` (roll, pitch, throttle, yaw). Behavioural cloning from manually-flown data

The state machine goes `enable → handshake → settle (5 s) → throttle ramp (2 s, 0 → 0xB0) → hover / explore`. An event ring buffer (50 entries) logs every transition for debugging. Max throttle is capped at `0xE0` for safety, and any user joystick input cancels autonomy.

**Web UI.** Flask serves joystick sliders, an MJPEG video stream, and autopilot enable / state endpoints. `/api/autopilot/state` exposes the current obstacle map and event log for live debugging from another tab.

## Tech stack

- **Python 3.13**, Flask
- **PyTorch ≥ 2.0** for DronePilotNet training and inference
- **OpenCV (headless)** for optical flow and frame decoding
- **Scapy** for pcap analysis
- **ffmpeg** for video verification
- Cross-platform: runs on the host laptop or a Raspberry Pi Zero 2 (Pi support landed in commit `36a2268`)

## Key technical decisions

- **Network stack binding.** The drone firmware hard-validates source IP `192.168.169.3`. `setup_network.sh` adds that as a secondary IP alias on the host interface so the controller binds to it explicitly. Non-obvious constraint, documented and automated.
- **Motor-spin threshold.** Empirically measured from flight-log analysis: cruise `0xB0`, ceiling `0xE0`. All four axes centre at `0x80`, but throttle needs a significant offset before the motors engage. This single finding was the difference between "controller sends packets and nothing happens" and "drone flies."
- **Headless-JPEG workaround.** Rather than implementing a full H.264 decoder or hunting for the right libav bindings, the video pipeline prepends a pre-built quantization header so OpenCV can decode the raw scan data directly. It's a workaround, but it's stable and kept the project moving.
- **Autopilot state machine.** Separate `starting` and `enabled` flags prevent a race condition on double-click, and the event ring buffer gives a post-mortem view of every transition without a logging framework.

## Current state

**Working**
- Protocol handshake fully validated against stock-app captures
- Manual joystick control via web UI
- Video reassembly and MJPEG streaming to the browser
- Autopilot state machine with throttle calibration (cruise `0xB0`, max `0xE0`)
- DronePilotNet inference pipeline (loads trained `.pt` checkpoints)

**In progress**
- Live flight test of the calibrated throttle ramp — motors now reliably spin above threshold
- Proper H.264 reassembly (the headless-JPEG workaround is stable but not the long-term answer)
- Integrating the ML training pipeline with live autopilot (currently runs offline on collected data)

**Known rough edges**
- Pi Zero 2 occasionally drops fragments at full bitrate; needs larger ring buffer or lower source resolution
- Only a handful of text command IDs have been verified against the drone (`cmd=3`, `106`)

## Running it

```bash
sudo bash setup_network.sh                # bind 192.168.169.3
# connect host to the drone's WiFi (HASAKEE Q10 / AVIALOGIC Q10 SSID)
pip install -r requirements.txt
python q10_controller.py                  # Flask at http://localhost:5050
```

## Key files

- [`CLAUDE.md`](CLAUDE.md) — complete protocol spec, packet layouts, handshake sequence, confirmed commands, lessons learned. **Start here.**
- [`q10_controller.py`](q10_controller.py) — Flask app and the `Q10Controller` class (protocol + joystick)
- [`autopilot/autopilot_controller.py`](autopilot/autopilot_controller.py) — the autonomous state machine, throttle ramp, event logging
- [`ml/model.py`](ml/model.py) — DronePilotNet architecture
- [`tools/analyze_capture.py`](tools/analyze_capture.py) — the pcap introspection that bootstrapped the entire reverse-engineering effort
