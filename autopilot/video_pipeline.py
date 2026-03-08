"""
Video Pipeline — decode H.264 stream from Q10 drone's custom UDP packets.

The drone sends video as UDP packets with:
  - Magic byte: 0x93
  - 36-byte custom header
  - H.264 payload (NAL units, possibly fragmented across packets)
  - Sequence counter at header byte 32 (LE32)

This module strips the headers, feeds raw H.264 into an ffmpeg subprocess,
and produces decoded BGR frames via a thread-safe queue.
"""

import logging
import subprocess
import struct
import threading
import time
from collections import deque
from typing import Optional

import numpy as np

log = logging.getLogger("Q10.video")

# Video frame dimensions — the drone likely sends 320x240 or 640x480.
# We decode at 320x240 for speed; ffmpeg will scale if needed.
FRAME_W = 320
FRAME_H = 240
FRAME_BYTES = FRAME_W * FRAME_H * 3  # BGR24

# How many decoded frames to buffer (drop old if full)
FRAME_QUEUE_SIZE = 3

# Custom header length on each 0x93 packet
HEADER_LEN = 36


class VideoDecoder:
    """Receives 0x93 video packets, decodes H.264, outputs BGR frames."""

    def __init__(self, frame_width: int = FRAME_W, frame_height: int = FRAME_H):
        self.frame_width = frame_width
        self.frame_height = frame_height
        self.frame_bytes = frame_width * frame_height * 3

        self._frame_queue: deque = deque(maxlen=FRAME_QUEUE_SIZE)
        self._frame_lock = threading.Lock()
        self._frame_event = threading.Event()

        self._ffmpeg_proc: Optional[subprocess.Popen] = None
        self._decode_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Stats
        self.packets_fed = 0
        self.frames_decoded = 0
        self.last_frame_time = 0.0
        self._started = False

    def start(self):
        """Launch the ffmpeg decoder subprocess and reader thread."""
        if self._started:
            return
        self._stop_event.clear()
        self._start_ffmpeg()
        self._decode_thread = threading.Thread(target=self._decode_loop, daemon=True,
                                               name="video-decode")
        self._decode_thread.start()
        self._started = True
        log.info("Video decoder started (output %dx%d)", self.frame_width, self.frame_height)

    def stop(self):
        """Shut down decoder."""
        self._stop_event.set()
        self._started = False
        if self._ffmpeg_proc:
            try:
                self._ffmpeg_proc.stdin.close()
            except Exception:
                pass
            try:
                self._ffmpeg_proc.terminate()
                self._ffmpeg_proc.wait(timeout=3)
            except Exception:
                self._ffmpeg_proc.kill()
            self._ffmpeg_proc = None
        if self._decode_thread:
            self._decode_thread.join(timeout=3)
            self._decode_thread = None
        log.info("Video decoder stopped (packets=%d, frames=%d)",
                 self.packets_fed, self.frames_decoded)

    def feed_packet(self, data: bytes):
        """Feed a raw 0x93 video packet from the drone.

        Strips the 36-byte header and writes the H.264 payload to ffmpeg stdin.
        """
        if not self._started or not self._ffmpeg_proc:
            return
        if len(data) <= HEADER_LEN:
            return  # Too short, no payload

        # Strip custom header, keep H.264 payload
        h264_payload = data[HEADER_LEN:]

        try:
            self._ffmpeg_proc.stdin.write(h264_payload)
            self._ffmpeg_proc.stdin.flush()
            self.packets_fed += 1

            # Log progress
            if self.packets_fed == 1:
                log.info("First video packet fed to decoder (%d payload bytes, "
                         "header: %s)", len(h264_payload), data[:12].hex(' '))
            elif self.packets_fed == 50:
                log.info("Fed 50 packets to decoder, %d frames decoded so far",
                         self.frames_decoded)
            elif self.packets_fed % 500 == 0:
                log.info("Video pipeline: %d packets fed, %d frames decoded",
                         self.packets_fed, self.frames_decoded)
        except (BrokenPipeError, OSError) as e:
            log.warning("FFmpeg pipe broken (%s), restarting decoder", e)
            self._restart_ffmpeg()

    def get_frame(self) -> Optional[np.ndarray]:
        """Get the latest decoded frame (non-blocking). Returns None if no frame available."""
        with self._frame_lock:
            if self._frame_queue:
                return self._frame_queue[-1]  # Latest frame
        return None

    def wait_frame(self, timeout: float = 1.0) -> Optional[np.ndarray]:
        """Wait for a new frame (blocking up to timeout seconds)."""
        self._frame_event.clear()
        self._frame_event.wait(timeout=timeout)
        return self.get_frame()

    @property
    def fps(self) -> float:
        """Estimated decode FPS based on recent frames."""
        if self.frames_decoded < 2 or self.last_frame_time == 0:
            return 0.0
        elapsed = time.time() - self.last_frame_time
        if elapsed > 2.0:
            return 0.0  # Stale
        # Rough estimate based on frame count and uptime
        return min(30.0, self.frames_decoded / max(1, time.time() - self._start_time))

    # -- internal -------------------------------------------------------------

    def _start_ffmpeg(self):
        """Launch ffmpeg subprocess for H.264 → raw BGR decoding."""
        cmd = [
            "ffmpeg",
            "-hide_banner",
            "-loglevel", "warning",
            # Input: raw H.264 byte stream from stdin
            "-f", "h264",
            "-i", "pipe:0",
            # Output: raw BGR24 frames scaled to target size
            "-f", "rawvideo",
            "-pix_fmt", "bgr24",
            "-s", f"{self.frame_width}x{self.frame_height}",
            # No audio, pipe output
            "-an",
            "pipe:1",
        ]
        self._ffmpeg_proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=self.frame_bytes * 4,
        )
        self._start_time = time.time()
        log.info("FFmpeg decoder launched: %s", " ".join(cmd))

    def _restart_ffmpeg(self):
        """Kill and restart ffmpeg if it dies."""
        if self._ffmpeg_proc:
            try:
                self._ffmpeg_proc.kill()
                self._ffmpeg_proc.wait(timeout=2)
            except Exception:
                pass
        self._start_ffmpeg()

    def _decode_loop(self):
        """Read raw BGR frames from ffmpeg stdout."""
        log.info("Decode loop started, reading %d bytes per frame", self.frame_bytes)
        buf = b""
        while not self._stop_event.is_set():
            try:
                if not self._ffmpeg_proc or not self._ffmpeg_proc.stdout:
                    time.sleep(0.1)
                    continue

                # Read enough bytes for one frame
                chunk = self._ffmpeg_proc.stdout.read(self.frame_bytes - len(buf))
                if not chunk:
                    # ffmpeg closed stdout — might need restart
                    if not self._stop_event.is_set():
                        log.warning("FFmpeg stdout closed, restarting")
                        self._restart_ffmpeg()
                        buf = b""
                    continue

                buf += chunk

                if len(buf) >= self.frame_bytes:
                    # Convert to numpy BGR frame
                    frame_data = buf[:self.frame_bytes]
                    buf = buf[self.frame_bytes:]

                    frame = np.frombuffer(frame_data, dtype=np.uint8).reshape(
                        (self.frame_height, self.frame_width, 3)
                    ).copy()  # Copy so buffer can be reused

                    with self._frame_lock:
                        self._frame_queue.append(frame)

                    self.frames_decoded += 1
                    self.last_frame_time = time.time()
                    self._frame_event.set()

                    if self.frames_decoded == 1:
                        log.info("First video frame decoded! (%dx%d)",
                                 self.frame_width, self.frame_height)
                    elif self.frames_decoded % 300 == 0:
                        elapsed = time.time() - self._start_time
                        avg_fps = self.frames_decoded / elapsed if elapsed > 0 else 0
                        log.info("Video: %d frames decoded (avg %.1f fps)",
                                 self.frames_decoded, avg_fps)

            except Exception as e:
                if not self._stop_event.is_set():
                    log.error("Decode loop error: %s", e)
                    time.sleep(0.1)

        log.info("Decode loop ended")
