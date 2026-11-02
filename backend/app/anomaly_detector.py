import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler


# Numerical features used by the model
NUMERIC_FEATURES = [
    "packet_count",
    "byte_count",
    "duration_seconds",
    "bytes_per_packet",
    "packets_per_second",
    "bytes_per_second",
]


class NetworkAnomalyDetector:
    def __init__(
        self,
        contamination: float = 0.05,
        random_state: int = 42,
    ):
        self.contamination = contamination

        self.scaler = StandardScaler()

        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=random_state,
        )

        self.is_trained = False

    def prepare_features(self, flows: list[dict]) -> pd.DataFrame:
        if not flows:
            raise ValueError("No network flows provided.")

        dataframe = pd.DataFrame(flows)

        required_columns = [
            "packet_count",
            "byte_count",
            "duration_seconds",
        ]

        for column in required_columns:
            if column not in dataframe.columns:
                raise ValueError(
                    f"Missing required feature: {column}"
                )

            dataframe[column] = pd.to_numeric(
                dataframe[column],
                errors="coerce",
            )

        dataframe[required_columns] = (
            dataframe[required_columns]
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0)
        )

        # Prevent division by zero.
        safe_packets = dataframe["packet_count"].clip(lower=1)
        safe_duration = dataframe["duration_seconds"].clip(lower=0.001)

        # Feature engineering.
        dataframe["bytes_per_packet"] = (
            dataframe["byte_count"] / safe_packets
        )

        dataframe["packets_per_second"] = (
            dataframe["packet_count"] / safe_duration
        )

        dataframe["bytes_per_second"] = (
            dataframe["byte_count"] / safe_duration
        )

        dataframe[NUMERIC_FEATURES] = (
            dataframe[NUMERIC_FEATURES]
            .replace([np.inf, -np.inf], np.nan)
            .fillna(0)
        )

        return dataframe[NUMERIC_FEATURES]

    def train(self, flows: list[dict]) -> dict:
        if len(flows) < 10:
            raise ValueError(
                "At least 10 network flows are required for training."
            )

        features = self.prepare_features(flows)

        scaled_features = self.scaler.fit_transform(features)

        self.model.fit(scaled_features)

        self.is_trained = True

        return {
            "message": "Anomaly detection model trained successfully.",
            "training_samples": len(flows),
            "features_used": NUMERIC_FEATURES,
        }

    def predict(self, flows: list[dict]) -> list[dict]:
        if not self.is_trained:
            raise RuntimeError(
                "The anomaly detection model has not been trained."
            )

        features = self.prepare_features(flows)

        scaled_features = self.scaler.transform(features)

        predictions = self.model.predict(scaled_features)

        anomaly_scores = self.model.decision_function(
            scaled_features
        )

        results = []

        for flow, prediction, score in zip(
            flows,
            predictions,
            anomaly_scores,
        ):
            is_anomaly = prediction == -1

            results.append({
                "flow_id": flow.get("id"),
                "source_ip": flow.get("source_ip"),
                "destination_ip": flow.get("destination_ip"),
                "protocol": flow.get("protocol"),
                "is_anomaly": bool(is_anomaly),
                "anomaly_score": round(float(score), 6),
                "status": (
                    "anomaly" if is_anomaly else "normal"
                ),
            })

        return results