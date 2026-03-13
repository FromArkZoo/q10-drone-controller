"""
PyTorch Dataset for behavioral cloning — loads recorded flight sessions.
"""

import csv
import random
from pathlib import Path
from typing import List, Optional

import numpy as np
import torch
from torch.utils.data import Dataset
from PIL import Image
import torchvision.transforms as T
import torchvision.transforms.functional as TF


# Default session storage base
BASE_PATH = Path(__file__).resolve().parent.parent / "data" / "sessions"

# Target image dimensions
IMG_W = 320
IMG_H = 240


class DroneDataset(Dataset):
    """Loads one or more flight sessions for training/validation."""

    def __init__(self, session_names: List[str], base_path: str = str(BASE_PATH),
                 split: str = "train", val_ratio: float = 0.2, augment: bool = True):
        """
        Args:
            session_names: List of session directory names to load.
            base_path: Root directory containing session folders.
            split: 'train' or 'val'.
            val_ratio: Fraction of frames to hold out for validation.
            augment: Whether to apply data augmentation (train only).
        """
        self.base_path = Path(base_path)
        self.split = split
        self.augment = augment and (split == "train")

        # Load all frame paths and joystick labels
        self._frames: List[Path] = []
        self._labels: List[np.ndarray] = []

        for session_name in session_names:
            session_dir = self.base_path / session_name
            frames_dir = session_dir / "frames"
            csv_path = session_dir / "joystick.csv"

            if not csv_path.exists():
                continue

            # Read CSV into a dict keyed by frame_idx
            joystick_data = {}
            with open(csv_path) as f:
                reader = csv.DictReader(f)
                for row in reader:
                    idx = int(row["frame_idx"])
                    joystick_data[idx] = np.array([
                        int(row["roll"]),
                        int(row["pitch"]),
                        int(row["throttle"]),
                        int(row["yaw"]),
                    ], dtype=np.float32)

            # Match frames to labels
            for idx in sorted(joystick_data.keys()):
                frame_path = frames_dir / f"{idx:06d}.jpg"
                if frame_path.exists():
                    self._frames.append(frame_path)
                    self._labels.append(joystick_data[idx])

        # Deterministic train/val split based on frame indices
        n = len(self._frames)
        n_val = int(n * val_ratio)
        # Use every 5th frame for val (deterministic, spread across session)
        val_indices = set(range(0, n, max(1, int(1.0 / val_ratio))))
        # Trim to exact count
        val_indices = set(list(sorted(val_indices))[:n_val])
        train_indices = [i for i in range(n) if i not in val_indices]
        val_indices = sorted(val_indices)

        if split == "val":
            indices = val_indices
        else:
            indices = train_indices

        self._frames = [self._frames[i] for i in indices]
        self._labels = [self._labels[i] for i in indices]

        # Image transforms (no augmentation)
        self._to_tensor = T.Compose([
            T.Resize((IMG_H, IMG_W)),
            T.ToTensor(),  # [0,1] float, C,H,W
        ])

    def __len__(self) -> int:
        return len(self._frames)

    def __getitem__(self, idx: int):
        # Load image
        img = Image.open(self._frames[idx]).convert("RGB")

        # Normalize joystick values from [0,255] to [0,1]
        label = self._labels[idx] / 255.0

        # Augmentation (train only)
        if self.augment:
            # Random horizontal flip
            if random.random() > 0.5:
                img = TF.hflip(img)
                # Invert roll and yaw axes
                label[0] = 1.0 - label[0]  # roll
                label[3] = 1.0 - label[3]  # yaw

            # Random brightness/contrast jitter
            img = TF.adjust_brightness(img, 0.8 + random.random() * 0.4)  # [0.8, 1.2]
            img = TF.adjust_contrast(img, 0.8 + random.random() * 0.4)

        img_tensor = self._to_tensor(img)
        label_tensor = torch.tensor(label, dtype=torch.float32)

        return img_tensor, label_tensor
