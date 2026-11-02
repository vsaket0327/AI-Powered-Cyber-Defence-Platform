from pathlib import Path

import joblib


# Directory for saved ML models
MODEL_DIRECTORY = Path(__file__).resolve().parent.parent / "ml_models"

# Saved anomaly detection model
MODEL_PATH = MODEL_DIRECTORY / "network_anomaly_detector.joblib"


def save_model(detector) -> str:
    """Save the trained anomaly detector to disk."""

    if not detector.is_trained:
        raise ValueError("Cannot save an untrained model.")

    MODEL_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(detector, MODEL_PATH)

    return str(MODEL_PATH)


def load_model():
    """Load a previously trained anomaly detector."""

    if not MODEL_PATH.exists():
        return None

    detector = joblib.load(MODEL_PATH)

    if not detector.is_trained:
        raise ValueError("Saved anomaly detector is not trained.")

    return detector


def model_exists() -> bool:
    """Check whether a saved model exists."""

    return MODEL_PATH.exists()