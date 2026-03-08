"""
Autopilot Controller — autonomous flight with obstacle avoidance.

Reads obstacle maps from the detector and translates them into
joystick commands for the Q10 drone controller.

Works in two layers:
  1. Base flight: hover or explore pattern (works without video)
  2. Obstacle avoidance: overlay from camera analysis (when video available)

Modes:
  - hover:   Hold altitude, no forward movement, avoid if something approaches
  - explore: Fly slowly forward, periodically turn; avoid obstacles when camera active
"""

import logging
import threading
import time
from collections import deque
from typing import Optional

from .obstacle_detector import ObstacleDetector, ObstacleMap
from .video_pipeline import VideoDecoder

log = logging.getLogger("Q10.autopilot")

# Autopilot runs at 10 Hz (100ms per tick)
AUTOPILOT_RATE = 0.10

# Joystick protocol values
CENTER = 0x80     # 128
THROTTLE_OFF = 0


class AutopilotController:
    """Autonomous flight controller using camera-based obstacle avoidance."""

    def __init__(self, drone, video_decoder: VideoDecoder):
        """
        Args:
            drone: Q10Controller instance (we call drone.set_joystick())
            video_decoder: VideoDecoder providing frames
        """
        self.drone = drone
        self.video = video_decoder
        self.detector = ObstacleDetector(sensitivity=5)

        # State
        self.enabled = False
        self.starting = False         # True while enable() is running in background
        self.error = None             # Set to error string if enable() fails
        self.mode = "hover"  # "hover" or "explore"
        self.last_obstacle_map: Optional[ObstacleMap] = None
        self.has_video = False  # Whether video frames are being decoded

        # Tunable parameters
        self.avoid_threshold = 0.45   # Threat level to trigger avoidance
        self.cruise_throttle = 0xB0   # ~176 — matches lower end of manual flight range
        self.settle_time = 5.0        # Seconds to wait after handshake before ramping
        self.forward_pitch = 15       # Pitch offset for forward flight (subtracted from 0x80)
        self.yaw_gain = 50            # How hard to turn when avoiding (max offset from center)
        self.pitch_retreat_gain = 30  # How hard to pull back when center threat is high

        # Explore pattern (used when no video / blind explore)
        self._explore_turn_interval = 4.0   # Seconds between direction changes
        self._explore_last_turn = 0.0
        self._explore_direction = 1          # 1=right, -1=left

        # Safety
        self.max_throttle = 0xE0      # Never exceed ~224 (user manually goes to 0xE9)
        self._user_override = False   # True if user touched joystick recently
        self._user_override_time = 0.0

        # Thread
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self.ticks = 0
        self.avoidance_events = 0

        # Event log ring buffer — queryable via /api/autopilot/state
        self._event_log: deque = deque(maxlen=50)

    def _log_event(self, msg: str):
        """Add an event to the ring buffer (visible in API state)."""
        ts = time.strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self._event_log.append(entry)
        log.info(msg)

    def enable(self, mode: str = "hover"):
        """Enable autopilot in the given mode.

        Fully autonomous: connects to drone if needed, ramps throttle
        gradually, and starts flying.

        If already flying (mode switch), just changes mode without re-takeoff.
        """
        # If already enabled, just switch mode — don't land and re-takeoff
        if self.enabled:
            old_mode = self.mode
            self.mode = mode
            self._explore_last_turn = time.time()
            self._explore_direction = 1
            log.info("Autopilot mode switched: %s -> %s", old_mode, mode)
            return

        self.starting = True
        self.error = None
        self.mode = mode
        self.has_video = False
        self._stop_event.clear()
        self._user_override = False
        self._event_log.clear()
        self._log_event(f"Enable requested (mode={mode})")
        self._explore_last_turn = time.time()
        self._explore_direction = 1
        self.ticks = 0
        self.avoidance_events = 0

        try:
            self._do_enable(mode)
        except Exception:
            self.starting = False
            raise

    def _do_enable(self, mode: str):
        """Internal enable logic — may block for several seconds."""
        print(f"\n{'='*60}")
        print(f"  AUTOPILOT ENABLE: Starting (mode={mode})")
        print(f"{'='*60}")

        # Step 1: Verify network setup before anything else
        import socket
        print("  [1/6] Checking network (192.168.169.3)...")
        self._log_event("Step 1: Checking network...")
        try:
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            test_sock.bind(("192.168.169.3", 0))
            test_sock.close()
            print("  [1/6] Network OK")
            self._log_event("Step 1: Network OK")
        except OSError:
            print("  [1/6] FAILED — 192.168.169.3 not available!")
            print("         Run: sudo bash setup_network.sh")
            self._log_event("Step 1: FAILED — 192.168.169.3 not available")
            raise RuntimeError(
                "Cannot bind to 192.168.169.3 — run: sudo bash setup_network.sh"
            )

        # Step 2: FULL RECONNECT to reset the armed window.
        # DISCOVERY: The drone has an armed timeout after handshake (~10s).
        # Within that window, throttle works. After it, throttle is silently
        # ignored. A full disconnect+reconnect resets this armed window.
        # We must ramp throttle IMMEDIATELY after connect.
        print("  [2/6] Full reconnect to reset armed window...")
        self._log_event("Step 2: Full reconnect...")
        if self.drone.connected:
            self.drone.disconnect()
            time.sleep(0.5)
        self.drone.connect()
        self.drone.set_joystick(roll=CENTER, pitch=CENTER, yaw=CENTER,
                                throttle=THROTTLE_OFF)
        msg = f"Step 2: Connected (armed={self.drone.armed}, handshake={self.drone._handshake_done})"
        print(f"  [2/6] {msg[8:]}")
        self._log_event(msg)

        # Step 3: Skipped — no settle or rearm. Ramp immediately after connect!
        print("  [3/6] Skipped (ramp immediately — no settle needed)")
        self._log_event("Step 3: Skipped — ramping immediately")

        # Step 4: Try to start video decoder
        print("  [4/6] Starting video decoder...")
        if not self.video._started:
            try:
                self.video.start()
                print("  [4/6] Video decoder started")
                log.info("Video decoder started for autopilot")
            except Exception as e:
                print(f"  [4/6] Video decoder failed: {e} (flying blind)")
                log.warning("Video decoder failed to start: %s (flying blind)", e)
        else:
            print("  [4/6] Video decoder already running")

        # Step 5: Ramp throttle — NO cmd=1 takeoff command.
        print(f"  [5/6] Ramping throttle 0x00 → 0x{self.cruise_throttle:02X} "
              f"(10 steps, 2 seconds)...")
        self._log_event(f"Step 5: Ramping throttle 0x00 → 0x{self.cruise_throttle:02X}...")
        log.info("Autopilot: ramping throttle from zero to cruise (0x%02X)...",
                 self.cruise_throttle)

        ramp_steps = 10
        for i in range(1, ramp_steps + 1):
            if self._stop_event.is_set():
                print("  [5/6] ABORTED — stop event set")
                self.starting = False
                return
            t = int(self.cruise_throttle * i / ramp_steps)
            self.drone.set_joystick(throttle=t)
            actual = self.drone.throttle
            print(f"  [5/6] Ramp step {i:2d}/10: set=0x{t:02X} "
                  f"actual=0x{actual:02X} "
                  f"armed={self.drone.armed} "
                  f"handshake={self.drone._handshake_done}")
            log.info("Throttle ramp: step %d/%d set=0x%02X actual=0x%02X",
                     i, ramp_steps, t, actual)
            time.sleep(0.20)  # 200ms per step = 2 seconds total ramp

        print(f"  [5/6] Ramp complete — throttle at 0x{self.drone.throttle:02X}")
        print(f"         >>> MOTORS SHOULD BE SPINNING NOW <<<")
        self._log_event(f"Step 5: Ramp complete — throttle=0x{self.drone.throttle:02X}")
        log.info("Throttle at cruise: 0x%02X (drone.throttle=0x%02X)",
                 self.cruise_throttle, self.drone.throttle)

        # Step 6: Mark as enabled and start autopilot control loop
        # Set enabled=True AFTER ramp completes, not before
        self.starting = False
        self.enabled = True
        self._thread = threading.Thread(target=self._control_loop, daemon=True,
                                        name="autopilot")
        self._thread.start()
        print(f"  [6/6] Autopilot control loop started (mode={mode})")
        print(f"{'='*60}")
        print(f"  AUTOPILOT ENABLED — mode={mode}, cruise=0x{self.cruise_throttle:02X}")
        print(f"{'='*60}\n")
        self._log_event(f"Step 6: ENABLED (mode={mode}, cruise=0x{self.cruise_throttle:02X})")
        log.info("Autopilot ENABLED (mode=%s, cruise_throttle=0x%02X)",
                 mode, self.cruise_throttle)

    def disable(self):
        """Disable autopilot — land the drone and return to manual control."""
        was_enabled = self.enabled or self.starting
        self.enabled = False
        self.starting = False
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None

        # Ramp throttle down gradually then zero everything
        if was_enabled and self.drone.connected:
            log.info("Autopilot: ramping throttle down...")
            current_t = self.drone.throttle
            ramp_down_steps = 10
            for i in range(ramp_down_steps, 0, -1):
                t = int(current_t * i / ramp_down_steps)
                self.drone.set_joystick(throttle=t)
                time.sleep(0.1)
        self.drone.set_joystick(roll=CENTER, pitch=CENTER, yaw=CENTER,
                                throttle=THROTTLE_OFF)
        if was_enabled:
            log.info("Autopilot DISABLED (ticks=%d, avoidance=%d, had_video=%s)",
                     self.ticks, self.avoidance_events, self.has_video)

    def notify_user_input(self):
        """Call this when the user sends manual joystick input — pauses autopilot briefly."""
        self._user_override = True
        self._user_override_time = time.time()

    def set_sensitivity(self, level: int):
        """Adjust obstacle detection sensitivity (1-10)."""
        self.detector.set_sensitivity(level)

    def get_state(self) -> dict:
        """Return autopilot state for the web UI."""
        obstacle = self.last_obstacle_map.to_dict() if self.last_obstacle_map else None
        return {
            "enabled": self.enabled,
            "starting": self.starting,
            "error": self.error,
            "mode": self.mode,
            "ticks": self.ticks,
            "avoidance_events": self.avoidance_events,
            "obstacle_map": obstacle,
            "has_video": self.has_video,
            "cruise_throttle": self.cruise_throttle,
            "settle_time": self.settle_time,
            "video_fps": round(self.video.fps, 1),
            "video_frames": self.video.frames_decoded,
            "video_packets_fed": self.video.packets_fed,
            "user_override": self._user_override,
            "event_log": list(self._event_log),
            "drone_throttle": self.drone.throttle,
            "drone_armed": self.drone.armed,
            "drone_connected": self.drone.connected,
        }

    # -- control loop ---------------------------------------------------------

    def _control_loop(self):
        """Main autopilot loop — runs at 10Hz.

        Works in two layers:
        1. Base flight pattern (always active) — hover or explore
        2. Obstacle avoidance overlay (when video frames available)
        """
        log.info("Autopilot loop started (mode=%s, threshold=%.2f)",
                 self.mode, self.avoid_threshold)

        while not self._stop_event.is_set():
            try:
                # Check user override timeout (1.5s pause after manual input)
                if self._user_override:
                    if time.time() - self._user_override_time > 1.5:
                        self._user_override = False
                        log.info("User override expired, autopilot resuming")
                    else:
                        self._stop_event.wait(AUTOPILOT_RATE)
                        continue

                # Try to get a video frame for obstacle detection
                obstacle_map = None
                frame = self.video.get_frame() if self.video._started else None

                if frame is not None:
                    if not self.has_video:
                        log.info("Video frames available! Obstacle avoidance active.")
                        self.has_video = True
                    obstacle_map = self.detector.analyze(frame)
                    self.last_obstacle_map = obstacle_map

                # Execute flight mode (works with or without obstacle data)
                if self.mode == "hover":
                    self._tick_hover(obstacle_map)
                elif self.mode == "explore":
                    self._tick_explore(obstacle_map)

                self.ticks += 1

                # Periodic status log
                if self.ticks % 50 == 1:
                    t = self.drone.throttle
                    p = self.drone.pitch
                    y = self.drone.yaw
                    vid = f"video={self.video.frames_decoded}f" if self.has_video else "no video"
                    log.info("AP tick=%d mode=%s T=0x%02X P=0x%02X Y=0x%02X %s avoid=%d",
                             self.ticks, self.mode, t, p, y, vid, self.avoidance_events)

            except Exception as e:
                log.error("Autopilot error: %s", e, exc_info=True)

            self._stop_event.wait(AUTOPILOT_RATE)

        log.info("Autopilot loop ended")

    # -- hover mode -----------------------------------------------------------

    def _tick_hover(self, obs: Optional[ObstacleMap]):
        """Hover mode: maintain altitude, avoid obstacles if detected."""
        throttle = self.cruise_throttle
        pitch = CENTER    # No forward movement
        roll = CENTER
        yaw = CENTER

        # If we have obstacle data and something is too close, turn away
        if obs is not None and obs.max_threat > self.avoid_threshold:
            self.avoidance_events += 1
            yaw = self._compute_avoidance_yaw(obs)
            if obs.center_threat > self.avoid_threshold:
                pitch = CENTER + self.pitch_retreat_gain  # Back up

        self.drone.set_joystick(roll=roll, pitch=pitch, throttle=throttle, yaw=yaw)

    # -- explore mode ---------------------------------------------------------

    def _tick_explore(self, obs: Optional[ObstacleMap]):
        """Explore mode: fly forward, avoid obstacles.

        If video is available: use obstacle detection to steer.
        If no video: fly forward and periodically change direction.
        """
        throttle = self.cruise_throttle
        roll = CENTER
        yaw = CENTER

        # Default: fly forward gently
        pitch = CENTER - self.forward_pitch  # Lower pitch = forward

        if obs is not None:
            # --- Camera-guided avoidance ---
            if obs.center_threat > self.avoid_threshold:
                # Obstacle ahead — stop and back up
                self.avoidance_events += 1
                pitch = CENTER + self.pitch_retreat_gain
                yaw = self._compute_avoidance_yaw(obs)

            elif obs.left_threat > self.avoid_threshold:
                # Obstacle on left — veer right
                self.avoidance_events += 1
                yaw_offset = int(self.yaw_gain * obs.left_threat)
                yaw = min(255, CENTER + yaw_offset)

            elif obs.right_threat > self.avoid_threshold:
                # Obstacle on right — veer left
                self.avoidance_events += 1
                yaw_offset = int(self.yaw_gain * obs.right_threat)
                yaw = max(0, CENTER - yaw_offset)
        else:
            # --- Blind explore (no video) ---
            # Fly forward, periodically turn to avoid flying into walls
            now = time.time()
            if now - self._explore_last_turn > self._explore_turn_interval:
                # Time to change direction
                self._explore_direction *= -1
                self._explore_last_turn = now
                log.info("Blind explore: turning %s",
                         "right" if self._explore_direction > 0 else "left")

            # Apply a gentle yaw while exploring
            yaw_offset = int(self.yaw_gain * 0.4)  # Moderate turn
            yaw = CENTER + (yaw_offset * self._explore_direction)

        self.drone.set_joystick(roll=roll, pitch=pitch,
                                throttle=min(throttle, self.max_throttle), yaw=yaw)

    # -- helpers --------------------------------------------------------------

    def _compute_avoidance_yaw(self, obs: ObstacleMap) -> int:
        """Compute yaw to turn toward the safest direction."""
        threat_diff = obs.left_threat - obs.right_threat

        if threat_diff > 0.1:
            # More threat on left → turn right
            offset = int(self.yaw_gain * min(1.0, abs(threat_diff) + 0.3))
            return min(255, CENTER + offset)
        elif threat_diff < -0.1:
            # More threat on right → turn left
            offset = int(self.yaw_gain * min(1.0, abs(threat_diff) + 0.3))
            return max(0, CENTER - offset)
        else:
            # Threats roughly equal — turn right by default
            return min(255, CENTER + int(self.yaw_gain * 0.5))
