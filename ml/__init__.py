"""ML behavioral cloning package for Q10 drone autopilot."""

from ml.data_collector import DataCollector

# Lazy imports for torch-dependent modules (torch may not be installed)
def __getattr__(name):
    if name == "DroneDataset":
        from ml.dataset import DroneDataset
        return DroneDataset
    elif name == "DronePilotNet":
        from ml.model import DronePilotNet
        return DronePilotNet
    elif name == "Trainer":
        from ml.trainer import Trainer
        return Trainer
    elif name == "Predictor":
        from ml.predictor import Predictor
        return Predictor
    raise AttributeError(f"module 'ml' has no attribute {name!r}")

__all__ = ["DataCollector", "DroneDataset", "DronePilotNet", "Trainer", "Predictor"]
