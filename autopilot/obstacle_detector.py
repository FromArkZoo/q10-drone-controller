"""
Obstacle Detector — analyze video frames to detect walls and obstacles.

Uses lightweight computer vision (edge density + frame differencing) to
estimate obstacle proximity in three frame regions: left, center, right.

Each region gets a threat level from 0.0 (clear) to 1.0 (imminent collision).
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Optional

import cv2
import numpy as np

log = logging.getLogger("Q10.obstacle")


@dataclass
class ObstacleMap:
    """Obstacle detection result for a single frame."""
    timestamp: float = 0.0
    left_threat: float = 0.0
    center_threat: float = 0.0
    right_threat: float = 0.0
    annotated_frame: Optional[np.ndarray] = field(default=None, repr=False)

    @property
    def max_threat(self) -> float:
        return max(self.left_threat, self.center_threat, self.right_threat)

    @property
    def safest_direction(self) -> str:
        """Returns 'left', 'center', or 'right' — whichever has lowest threat."""
        threats = {"left": self.left_threat, "center": self.center_threat,
                   "right": self.right_threat}
        return min(threats, key=threats.get)

    def to_dict(self) -> dict:
        return {
            "left_threat": round(self.left_threat, 3),
            "center_threat": round(self.center_threat, 3),
            "right_threat": round(self.right_threat, 3),
            "max_threat": round(self.max_threat, 3),
            "safest_direction": self.safest_direction,
        }


class ObstacleDetector:
    """Detects obstacles using edge density and frame differencing."""

    def __init__(self, sensitivity: int = 5):
        """
        Args:
            sensitivity: 1-10, higher = more sensitive to obstacles.
        """
        self.sensitivity = max(1, min(10, sensitivity))
        self._prev_gray: Optional[np.ndarray] = None
        self._prev_time: float = 0.0

        # Region split ratios (left 30%, center 40%, right 30%)
        self._left_ratio = 0.30
        self._center_ratio = 0.40
        # right is remainder

        # Tunable weights for threat fusion
        self._edge_weight = 0.6
        self._motion_weight = 0.4

        # Edge density normalization — calibrated so that
        # a wall filling the frame ≈ 0.8-1.0 threat
        self._edge_max = 0.35  # ~35% edge pixels = max threat

        # Motion normalization — pixel change magnitude
        self._motion_max = 40.0  # Mean absolute diff per pixel

        self._frame_count = 0

    def set_sensitivity(self, level: int):
        """Adjust sensitivity (1=least sensitive, 10=most)."""
        self.sensitivity = max(1, min(10, level))
        # Scale the "max" thresholds — lower max = more sensitive
        scale = 1.5 - (self.sensitivity / 10.0)  # 1.4 at sens=1, 0.5 at sens=10
        self._edge_max = 0.35 * scale
        self._motion_max = 40.0 * scale
        log.info("Sensitivity set to %d (edge_max=%.3f, motion_max=%.1f)",
                 level, self._edge_max, self._motion_max)

    def analyze(self, frame: np.ndarray) -> ObstacleMap:
        """Analyze a BGR frame and return an ObstacleMap.

        Args:
            frame: BGR image as numpy array (any size, will be processed as-is)

        Returns:
            ObstacleMap with threat levels for left/center/right regions
        """
        now = time.time()
        h, w = frame.shape[:2]

        # Convert to grayscale for analysis
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

        # Apply slight blur to reduce noise
        gray = cv2.GaussianBlur(gray, (5, 5), 0)

        # Split into regions
        left_bound = int(w * self._left_ratio)
        right_bound = int(w * (self._left_ratio + self._center_ratio))

        regions = {
            "left": gray[:, :left_bound],
            "center": gray[:, left_bound:right_bound],
            "right": gray[:, right_bound:],
        }

        # Compute edge density per region
        edge_threats = {}
        for name, region in regions.items():
            edge_threats[name] = self._edge_density(region)

        # Compute motion (frame differencing) per region
        motion_threats = {"left": 0.0, "center": 0.0, "right": 0.0}
        if self._prev_gray is not None and self._prev_gray.shape == gray.shape:
            prev_regions = {
                "left": self._prev_gray[:, :left_bound],
                "center": self._prev_gray[:, left_bound:right_bound],
                "right": self._prev_gray[:, right_bound:],
            }
            for name, region in regions.items():
                motion_threats[name] = self._motion_delta(region, prev_regions[name])

        self._prev_gray = gray.copy()
        self._prev_time = now

        # Fuse threats (weighted combination)
        fused = {}
        for name in ("left", "center", "right"):
            raw = (self._edge_weight * edge_threats[name] +
                   self._motion_weight * motion_threats[name])
            fused[name] = max(0.0, min(1.0, raw))

        # Build annotated frame for the web UI
        annotated = self._annotate_frame(frame, fused, left_bound, right_bound)

        self._frame_count += 1
        if self._frame_count % 150 == 0:
            log.info("Obstacles: L=%.2f C=%.2f R=%.2f (edge L=%.2f C=%.2f R=%.2f)",
                     fused["left"], fused["center"], fused["right"],
                     edge_threats["left"], edge_threats["center"], edge_threats["right"])

        return ObstacleMap(
            timestamp=now,
            left_threat=fused["left"],
            center_threat=fused["center"],
            right_threat=fused["right"],
            annotated_frame=annotated,
        )

    def _edge_density(self, gray_region: np.ndarray) -> float:
        """Compute edge density as fraction of edge pixels, normalized to 0-1."""
        edges = cv2.Canny(gray_region, 50, 150)
        density = np.count_nonzero(edges) / max(1, edges.size)
        return min(1.0, density / self._edge_max)

    def _motion_delta(self, current: np.ndarray, previous: np.ndarray) -> float:
        """Compute mean absolute pixel difference, normalized to 0-1."""
        diff = cv2.absdiff(current, previous)
        mean_diff = np.mean(diff)
        return min(1.0, mean_diff / self._motion_max)

    def _annotate_frame(self, frame: np.ndarray, threats: dict,
                        left_bound: int, right_bound: int) -> np.ndarray:
        """Draw threat overlays on the frame for the web UI."""
        annotated = frame.copy()
        h, w = annotated.shape[:2]

        # Draw region boundaries
        cv2.line(annotated, (left_bound, 0), (left_bound, h), (100, 100, 100), 1)
        cv2.line(annotated, (right_bound, 0), (right_bound, h), (100, 100, 100), 1)

        # Threat bars at bottom of each region
        bar_h = 20
        regions_bounds = [
            ("left", 0, left_bound),
            ("center", left_bound, right_bound),
            ("right", right_bound, w),
        ]

        for name, x1, x2 in regions_bounds:
            t = threats[name]
            # Color: green (safe) → yellow → red (danger)
            if t < 0.3:
                color = (0, 200, 0)
            elif t < 0.6:
                color = (0, 200, 200)
            else:
                color = (0, 0, 220)

            bar_width = int((x2 - x1) * t)
            cv2.rectangle(annotated, (x1, h - bar_h), (x1 + bar_width, h), color, -1)
            cv2.rectangle(annotated, (x1, h - bar_h), (x2, h), (80, 80, 80), 1)

            # Threat text
            label = f"{t:.0%}"
            cv2.putText(annotated, label, (x1 + 4, h - 5),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.4, (255, 255, 255), 1)

        return annotated
