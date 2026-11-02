
from datetime import datetime

from sqlalchemy import DateTime, Integer, JSON, String, func
from sqlalchemy import ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import Boolean, UniqueConstraint

from app.database import Base


class AnalysisHistory(Base):
    __tablename__ = "analysis_history"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )
    indicator_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )
    indicator: Mapped[str] = mapped_column(
        String(2048), nullable=False
    )
    format_valid: Mapped[bool] = mapped_column(
        nullable=False
    )
    risk_level: Mapped[str] = mapped_column(
        String(30), nullable=False
    )
    verdict: Mapped[str] = mapped_column(
        String(30), nullable=False
    )
    risk_score: Mapped[int | None] = mapped_column(Integer, nullable=True)
    risk_explanation: Mapped[str | None] = mapped_column(String(2000), nullable=True)

    details: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )
    evidence: Mapped[dict] = mapped_column(
    JSON, nullable=False, default=dict
    )
    recommendation: Mapped[str] = mapped_column(
        String(2000), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    title: Mapped[str] = mapped_column(
        String(200), nullable=False
    )

    description: Mapped[str] = mapped_column(
        String(2000), nullable=False, default=""
    )

    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium", index=True
    )

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="open", index=True
    )

    indicator_type: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )

    indicator: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )
    evidence: Mapped[dict] = mapped_column(
    JSON, nullable=False, default=dict
    )
    assigned_to = mapped_column(String(100), nullable=True)

    resolution_summary = mapped_column(Text, nullable=True)

    root_cause = mapped_column(Text, nullable=True)

    resolved_at = mapped_column(DateTime(timezone=True), nullable=True)

    closed_at = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

class IncidentActivity(Base):
    __tablename__ = "incident_activities"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    action: Mapped[str] = mapped_column(
        String(50), nullable=False
    )

    description: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    actor: Mapped[str] = mapped_column(
        String(100), nullable=False, default="System"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    note: Mapped[str] = mapped_column(
        Text, nullable=False
    )

    author: Mapped[str] = mapped_column(
        String(100), nullable=False, default="Analyst"
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    username: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )

    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )

    hashed_password: Mapped[str] = mapped_column(
        String(255), nullable=False
    )

    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="analyst"
    )

    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    username: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )

    action: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )

    resource_type: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    resource_id: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    details: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict
    )

    ip_address: Mapped[str | None] = mapped_column(
        String(45), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    title: Mapped[str] = mapped_column(
        String(200), nullable=False
    )

    description: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )

    source: Mapped[str] = mapped_column(
        String(100), nullable=False, index=True
    )

    severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="medium", index=True
    )

    status: Mapped[str] = mapped_column(
        String(20), nullable=False, default="new", index=True
    )

    indicator_type: Mapped[str | None] = mapped_column(
        String(20), nullable=True
    )

    indicator: Mapped[str | None] = mapped_column(
        String(2048), nullable=True
    )

    risk_score: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    evidence: Mapped[dict] = mapped_column(
        JSON, nullable=False, default=dict
    )

    assigned_to: Mapped[str | None] = mapped_column(
        String(100), nullable=True
    )

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
class ThreatIntelCache(Base):
    __tablename__ = "threat_intel_cache"

    __table_args__ = (
        UniqueConstraint(
            "indicator_type",
            "indicator",
            name="uq_threat_intel_indicator",
        ),
    )

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    indicator_type: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )

    indicator: Mapped[str] = mapped_column(
        String(2048), nullable=False
    )

    source: Mapped[str] = mapped_column(
        String(50), nullable=False, default="VirusTotal"
    )

    result: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

class NetworkFlow(Base):
    __tablename__ = "network_flows"

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True
    )

    source_ip: Mapped[str] = mapped_column(
        String(45), nullable=False, index=True
    )

    destination_ip: Mapped[str] = mapped_column(
        String(45), nullable=False, index=True
    )

    source_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    destination_port: Mapped[int | None] = mapped_column(
        Integer, nullable=True
    )

    protocol: Mapped[str] = mapped_column(
        String(20), nullable=False, index=True
    )

    packet_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    byte_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    start_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, index=True
    )

    end_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    duration_seconds: Mapped[float] = mapped_column(
        nullable=False, default=0.0
    )

    tcp_flags: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True
    )
class NetworkAnomaly(Base):
    __tablename__ = "network_anomalies"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    flow_id: Mapped[int | None] = mapped_column(
        ForeignKey("network_flows.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    source_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )

    destination_ip: Mapped[str] = mapped_column(
        String(45),
        nullable=False,
        index=True,
    )

    protocol: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
    )

    anomaly_score: Mapped[float] = mapped_column(
        nullable=False,
    )

    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="normal",
        index=True,
    )

    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="IsolationForest",
    )

    detected_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )
class AIAnalysisReport(Base):
    __tablename__ = "ai_analysis_reports"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        index=True,
    )

    user_id: Mapped[int | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    alert_id: Mapped[int | None] = mapped_column(
        ForeignKey("alerts.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    model_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
    )

    evidence_snapshot: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        default=dict,
    )

    report: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
        index=True,
    )