from sqlalchemy.orm import Session

from app.models import NetworkAnomaly


def save_anomaly_results(
    db: Session,
    predictions: list[dict],
) -> int:
    """
    Save anomalous network-flow predictions.

    The caller is responsible for committing or rolling back
    the database transaction.
    """

    anomaly_records = []

    for prediction in predictions:
        if not prediction.get("is_anomaly", False):
            continue

        source_ip = prediction.get("source_ip")
        destination_ip = prediction.get("destination_ip")
        protocol = prediction.get("protocol")
        anomaly_score = prediction.get("anomaly_score")
        flow_id = prediction.get("flow_id")

        if not source_ip or not destination_ip or not protocol:
            raise ValueError(
                "Anomaly prediction is missing required network information."
            )

        if anomaly_score is None:
            raise ValueError(
                "Anomaly prediction is missing its anomaly score."
            )

        anomaly_records.append(
            NetworkAnomaly(
                flow_id=flow_id,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                anomaly_score=float(anomaly_score),
                status="anomaly",
                model_name="IsolationForest",
            )
        )

    if anomaly_records:
        db.add_all(anomaly_records)
        db.flush()

    return len(anomaly_records)