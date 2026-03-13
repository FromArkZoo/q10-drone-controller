"""
Data collector for behavioral cloning — records video frames and joystick
inputs during manual flight sessions.
"""

import csv
import json
import logging
import os
import shutil
import threading
import time
from pathlib import Path
from typing import Optional

import cv2
import numpy as np

log = logging.getLogger("Q10.ml.collector")

# Motor spin threshold — only record frames where pilot is actually flying
THROTTLE_THRESHOLD = 0xA0

# Collection rate
SAMPLE_HZ = 10
SAMPLE_INTERVAL = 1.0 / SAMPLE_HZ

# JPEG quality (balance size vs quality)
JPEG_QUALITY = 70

# Base path for session data
BASE_PATH = Path(__file__).resolve().parent.parent / "data" / "sessions"


class DataCollector:
    """Records video frames + joystick state during manual flight."""

    def __init__(self, video_decoder, drone_controller):
        """
        Args:
            video_decoder: VideoDecoder instance with get_frame() -> np.ndarray|None
            drone_controller: Q10Controller with .roll, .pitch, .throttle, .yaw attrs
        """
        self._video = video_decoder
        self._drone = drone_controller

        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        self._session_name: Optional[str] = None
        self._session_path: Optional[Path] = None
        self._csv_file = None
        self._csv_writer = None
        self._frame_count = 0
        self._start_time = 0.0
        self._lock = threading.Lock()

    @property
    def is_recording(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def frame_count(self) -> int:
        return self._frame_count

    def start_session(self, name: str):
        """Start recording a new session."""
        if self.is_recording:
            raise RuntimeError("Already recording a session")

        self._session_name = name
        self._session_path = BASE_PATH / name
        frames_dir = self._session_path / "frames"
        frames_dir.mkdir(parents=True, exist_ok=True)

        # Open CSV
        csv_path = self._session_path / "joystick.csv"
        self._csv_file = open(csv_path, "w", newline="")
        self._csv_writer = csv.writer(self._csv_file)
        self._csv_writer.writerow(["frame_idx", "timestamp", "roll", "pitch", "throttle", "yaw"])

        self._frame_count = 0
        self._start_time = time.time()
        self._stop_event.clear()

        self._thread = threading.Thread(target=self._collect_loop, daemon=True,
                                        name="data-collector")
        self._thread.start()
        log.info("Recording session '%s' started", name)

    def stop_session(self):
        """Stop the current recording session and save metadata."""
        if not self.is_recording:
            return

        self._stop_event.set()
        self._thread.join(timeout=5)
        self._thread = None

        # Close CSV
        if self._csv_file:
            self._csv_file.close()
            self._csv_file = None
            self._csv_writer = None

        # Write metadata
        duration = time.time() - self._start_time
        meta = {
            "session_name": self._session_name,
            "start_time": self._start_time,
            "frame_count": self._frame_count,
            "duration": round(duration, 2),
            "sample_hz": SAMPLE_HZ,
        }
        meta_path = self._session_path / "meta.json"
        with open(meta_path, "w") as f:
            json.dump(meta, f, indent=2)

        log.info("Session '%s' stopped: %d frames, %.1fs",
                 self._session_name, self._frame_count, duration)
        self._session_name = None
        self._session_path = None

    def get_state(self) -> dict:
        """Return current collector state for API."""
        return {
            "is_recording": self.is_recording,
            "session_name": self._session_name,
            "frame_count": self._frame_count,
            "duration": round(time.time() - self._start_time, 1) if self.is_recording else 0,
        }

    @classmethod
    def list_sessions(cls) -> list:
        """List all saved sessions with metadata."""
        sessions = []
        if not BASE_PATH.exists():
            return sessions
        for entry in sorted(BASE_PATH.iterdir()):
            meta_path = entry / "meta.json"
            if entry.is_dir() and meta_path.exists():
                with open(meta_path) as f:
                    meta = json.load(f)
                sessions.append(meta)
        return sessions

    @classmethod
    def delete_session(cls, name: str):
        """Delete a saved session by name."""
        session_path = BASE_PATH / name
        if session_path.exists():
            shutil.rmtree(session_path)
            log.info("Deleted session '%s'", name)

    def _collect_loop(self):
        """Background thread: sample frames + joystick at SAMPLE_HZ."""
        log.info("Collector loop started at %d Hz", SAMPLE_HZ)
        while not self._stop_event.is_set():
            t0 = time.time()

            try:
                # Check throttle threshold
                throttle = self._drone.throttle
                if throttle < THROTTLE_THRESHOLD:
                    # Not flying — skip this sample
                    elapsed = time.time() - t0
                    if elapsed < SAMPLE_INTERVAL:
                        self._stop_event.wait(SAMPLE_INTERVAL - elapsed)
                    continue

                # Get frame
                frame = self._video.get_frame()
                if frame is None:
                    elapsed = time.time() - t0
                    if elapsed < SAMPLE_INTERVAL:
                        self._stop_event.wait(SAMPLE_INTERVAL - elapsed)
                    continue

                # Save frame as JPEG
                idx = self._frame_count
                frame_path = self._session_path / "frames" / f"{idx:06d}.jpg"
                encode_params = [cv2.IMWRITE_JPEG_QUALITY, JPEG_QUALITY]
                cv2.imwrite(str(frame_path), frame, encode_params)

                # Record joystick
                timestamp = round(time.time() - self._start_time, 3)
                roll = self._drone.roll
                pitch = self._drone.pitch
                yaw = self._drone.yaw

                self._csv_writer.writerow([idx, timestamp, roll, pitch, throttle, yaw])
                self._csv_file.flush()

                self._frame_count += 1

            except Exception as e:
                log.error("Collector error: %s", e)

            elapsed = time.time() - t0
            if elapsed < SAMPLE_INTERVAL:
                self._stop_event.wait(SAMPLE_INTERVAL - elapsed)

        log.info("Collector loop ended")
