from sqlalchemy import select

from app.database import SessionLocal
from app.models import NetworkFlow
from app.anomaly_detector import NetworkAnomalyDetector
from app.model_storage import save_model


def train_network_anomaly_model():
    db = SessionLocal()

    try:
        statement = select(NetworkFlow).order_by(
            NetworkFlow.created_at.asc()
        )

        network_flows = db.execute(statement).scalars().all()

        if len(network_flows) < 10:
            raise ValueError(
                f"Training requires at least 10 flows. "
                f"Currently available: {len(network_flows)}."
            )

        # Convert SQLAlchemy records into dictionaries.
        flow_data = [
            {
                "id": flow.id,
                "source_ip": flow.source_ip,
                "destination_ip": flow.destination_ip,
                "protocol": flow.protocol,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "duration_seconds": flow.duration_seconds,
                "source_port": flow.source_port,
                "destination_port": flow.destination_port,
            }
            for flow in network_flows
        ]

        detector = NetworkAnomalyDetector()

        training_result = detector.train(flow_data)

        model_path = save_model(detector)

        print("\nMODEL TRAINING SUCCESSFUL")
        print("-------------------------")
        print("Training samples:", len(flow_data))
        print("Features:", training_result["features_used"])
        print("Saved model:", model_path)

    finally:
        db.close()


if __name__ == "__main__":
    train_network_anomaly_model()