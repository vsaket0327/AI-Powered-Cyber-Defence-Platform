
import pytest

from app.ai_evidence_builder import (
    build_indicator_evidence,
    build_incident_evidence,
)


def test_build_incident_evidence_rejects_missing_incident(db_session):
    with pytest.raises(ValueError, match="Incident not found"):
        build_incident_evidence(db_session, 999999)


def test_build_indicator_evidence_rejects_missing_analysis(db_session):
    with pytest.raises(
        ValueError,
        match="No analysis history found",
    ):
        build_indicator_evidence(
            db_session,
            "ip",
            "192.0.2.123",
        )
