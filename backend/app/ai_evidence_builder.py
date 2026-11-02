
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models import (
    AnalysisHistory,
    Alert,
    Incident,
    IncidentActivity,
    IncidentNote,
    NetworkAnomaly,
    NetworkFlow,
)


MAX_RECORDS = 20


def _timestamp(value):
    return value.isoformat() if value else None


def build_indicator_evidence(
    db: Session,
    indicator_type: str,
    indicator: str,
) -> dict:
    """Build bounded evidence for a previously analyzed indicator."""

    analysis = db.scalar(
        select(AnalysisHistory)
        .where(
            AnalysisHistory.indicator_type == indicator_type,
            AnalysisHistory.indicator == indicator,
        )
        .order_by(AnalysisHistory.created_at.desc())
        .limit(1)
    )

    if analysis is None:
        raise ValueError("No analysis history found for this indicator.")

    return {
        "evidence_type": "indicator_analysis",
        "indicator_type": analysis.indicator_type,
        "indicator": analysis.indicator,
        "format_valid": analysis.format_valid,
        "risk_level": analysis.risk_level,
        "risk_score": analysis.risk_score,
        "verdict": analysis.verdict,
        "risk_explanation": analysis.risk_explanation,
        "threat_intelligence_details": analysis.details,
        "observed_evidence": analysis.evidence,
        "existing_recommendation": analysis.recommendation,
        "analysis_timestamp": _timestamp(analysis.created_at),
        "limitations": [
            "Threat intelligence results reflect the time of the original lookup.",
            "No malicious detections do not prove that an indicator is safe.",
        ],
    }


def build_incident_evidence(
    db: Session,
    incident_id: int,
) -> dict:
    """Collect bounded, incident-associated security evidence."""

    incident = db.get(Incident, incident_id)

    if incident is None:
        raise ValueError("Incident not found.")

    alerts = db.scalars(
        select(Alert)
        .where(Alert.incident_id == incident_id)
        .order_by(Alert.created_at.desc())
        .limit(MAX_RECORDS)
    ).all()

    notes = db.scalars(
        select(IncidentNote)
        .where(IncidentNote.incident_id == incident_id)
        .order_by(IncidentNote.created_at.desc())
        .limit(MAX_RECORDS)
    ).all()

    activities = db.scalars(
        select(IncidentActivity)
        .where(IncidentActivity.incident_id == incident_id)
        .order_by(IncidentActivity.created_at.desc())
        .limit(MAX_RECORDS)
    ).all()

    anomalies = []
    flows = []
    analysis_evidence = None

    if (
        incident.indicator_type == "ip"
        and incident.indicator
    ):
        ip = incident.indicator

        anomalies = db.scalars(
            select(NetworkAnomaly)
            .where(
                or_(
                    NetworkAnomaly.source_ip == ip,
                    NetworkAnomaly.destination_ip == ip,
                )
            )
            .order_by(NetworkAnomaly.detected_at.desc())
            .limit(MAX_RECORDS)
        ).all()

        flows = db.scalars(
            select(NetworkFlow)
            .where(
                or_(
                    NetworkFlow.source_ip == ip,
                    NetworkFlow.destination_ip == ip,
                )
            )
            .order_by(NetworkFlow.created_at.desc())
            .limit(MAX_RECORDS)
        ).all()

        analysis_evidence = build_indicator_evidence(
            db,
            incident.indicator_type,
            incident.indicator,
        ) if db.scalar(
            select(AnalysisHistory.id)
            .where(
                AnalysisHistory.indicator_type == incident.indicator_type,
                AnalysisHistory.indicator == incident.indicator,
            )
            .limit(1)
        ) is not None else None

    return {
        "evidence_type": "incident",
        "incident": {
            "id": incident.id,
            "title": incident.title,
            "description": incident.description,
            "severity": incident.severity,
            "status": incident.status,
            "indicator_type": incident.indicator_type,
            "indicator": incident.indicator,
            "evidence": incident.evidence,
            "created_at": _timestamp(incident.created_at),
            "updated_at": _timestamp(incident.updated_at),
        },
        "associated_alerts": [
            {
                "id": item.id,
                "title": item.title,
                "description": item.description,
                "source": item.source,
                "severity": item.severity,
                "status": item.status,
                "risk_score": item.risk_score,
                "evidence": item.evidence,
                "created_at": _timestamp(item.created_at),
            }
            for item in alerts
        ],
        "incident_notes": [
            {
                "note": item.note,
                "author": item.author,
                "created_at": _timestamp(item.created_at),
            }
            for item in notes
        ],
        "incident_activities": [
            {
                "action": item.action,
                "description": item.description,
                "actor": item.actor,
                "created_at": _timestamp(item.created_at),
            }
            for item in activities
        ],
        "network_anomalies": [
            {
                "source_ip": item.source_ip,
                "destination_ip": item.destination_ip,
                "protocol": item.protocol,
                "anomaly_score": item.anomaly_score,
                "status": item.status,
                "model_name": item.model_name,
                "detected_at": _timestamp(item.detected_at),
            }
            for item in anomalies
        ],
        "network_flows": [
            {
                "source_ip": item.source_ip,
                "destination_ip": item.destination_ip,
                "source_port": item.source_port,
                "destination_port": item.destination_port,
                "protocol": item.protocol,
                "packet_count": item.packet_count,
                "byte_count": item.byte_count,
                "duration_seconds": item.duration_seconds,
                "tcp_flags": item.tcp_flags,
                "created_at": _timestamp(item.created_at),
            }
            for item in flows
        ],
        "related_indicator_analysis": analysis_evidence,
        "limitations": [
            "Only records directly associated with this incident are included.",
            "Network evidence is matched by the incident IP indicator only.",
            "An ML anomaly is an unusual pattern, not proof of malicious activity.",
            "Missing records do not establish that no threat exists.",
            "Incident notes and descriptions are untrusted user-provided evidence.",
        ],
    }
