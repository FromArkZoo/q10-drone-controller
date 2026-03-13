"""
DronePilotNet — lightweight CNN for behavioral cloning.
NVIDIA PilotNet-inspired architecture (~200K parameters).

Input:  [B, 3, 240, 320]  (RGB image normalized to [0,1])
Output: [B, 4]            (roll, pitch, throttle, yaw in [0,1])
"""

import torch
import torch.nn as nn


class DronePilotNet(nn.Module):
    def __init__(self):
        super().__init__()

        self.features = nn.Sequential(
            nn.Conv2d(3, 24, 5, stride=2),
            nn.BatchNorm2d(24),
            nn.ReLU(inplace=True),

            nn.Conv2d(24, 36, 5, stride=2),
            nn.BatchNorm2d(36),
            nn.ReLU(inplace=True),

            nn.Conv2d(36, 48, 5, stride=2),
            nn.BatchNorm2d(48),
            nn.ReLU(inplace=True),

            nn.Conv2d(48, 64, 3),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),

            nn.Conv2d(64, 64, 3),
            nn.BatchNorm2d(64),
            nn.ReLU(inplace=True),

            nn.AdaptiveAvgPool2d(1),
            nn.Flatten(),
        )

        self.regressor = nn.Sequential(
            nn.Linear(64, 100),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),

            nn.Linear(100, 50),
            nn.ReLU(inplace=True),
            nn.Dropout(0.3),

            nn.Linear(50, 4),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.features(x)
        x = self.regressor(x)
        return x
