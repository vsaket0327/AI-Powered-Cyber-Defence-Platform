import hashlib
import ipaddress
import re
from app.threat_intel import (
    lookup_ip_reputation,
    lookup_domain_reputation,
    lookup_hash_reputation,
    lookup_url_reputation,
    get_cache_stats,
)
from sqlalchemy.orm import Session
from app.audit import log_audit_event
from app.database import SessionLocal
from app.models import (
    AnalysisHistory,
    Incident,
    IncidentActivity,
    IncidentNote,
    User,
    AuditLog,
    Alert,
    NetworkFlow,
    AIAnalysisReport,
    NetworkAnomaly,
)
from app.security import (
    hash_password,
    verify_password,
    create_access_token,
)

from app.dependencies import (
    get_db,
    get_current_user,
    require_role,
)
from urllib.parse import urlsplit

from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    Depends,
    status,
    UploadFile,
    File,
)
from fastapi.requests import Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from datetime import datetime, timezone
from sqlalchemy import select, func
from app.network_analyzer import analyze_pcap
from app.anomaly_detector import NetworkAnomalyDetector
from app.anomaly_storage import save_anomaly_results
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from app.model_storage import load_model, model_exists
from app.pcap_validation import (
    validate_pcap,
    MAX_PCAP_SIZE,
)
from app.risk_engine import calculate_risk
import logging
from typing import Literal
logger = logging.getLogger(__name__)
from app.ai_security_analyzer import AISecurityAnalyzer
from app.ai_evidence_builder import build_incident_evidence


class Settings(BaseSettings):
    app_name: str = "AI-Powered Cyber Defence Platform"
    environment: str = "development"
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()

app = FastAPI(
    title=settings.app_name,
    description="Defensive, read-only security analysis platform starter.",
    version="0.2.0",
)
limiter = Limiter(key_func=get_remote_address)

app.state.limiter = limiter
app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["*"],
)


class IndicatorRequest(BaseModel):
    indicator_type: str = Field(
        description="One of: ip, domain, url, hash"
    )
    value: str = Field(min_length=1, max_length=2048)



class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] = "medium"
    status: Literal[
        "open", "investigating", "resolved", "closed"
    ] = "open"
    indicator_type: Literal["ip", "domain", "url", "hash"] | None = None
    indicator: str | None = Field(default=None, max_length=2048)
    evidence: dict = Field(default_factory=dict)

class IncidentUpdate(BaseModel):
    title: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    severity: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "investigating", "resolved", "closed"] | None = None

    assigned_to: str | None = Field(default=None, max_length=100)
    resolution_summary: str | None = Field(default=None, max_length=10000)
    root_cause: str | None = Field(default=None, max_length=10000)
class IncidentNoteCreate(BaseModel):
    note: str = Field(min_length=1, max_length=10000)
    author: str = Field(default="Analyst", max_length=100)
class AlertCreate(BaseModel):
    title: str = Field(min_length=3, max_length=200)
    description: str = Field(default="", max_length=2000)

    source: str = Field(min_length=2, max_length=100)

    severity: Literal[
        "low", "medium", "high", "critical"
    ] = "medium"

    indicator_type: Literal[
        "ip", "domain", "url", "hash"
    ] | None = None

    indicator: str | None = Field(
        default=None, max_length=2048
    )

    risk_score: int | None = Field(
        default=None, ge=0, le=100
    )

    evidence: dict = Field(default_factory=dict)


class AlertUpdate(BaseModel):
    severity: Literal[
        "low", "medium", "high", "critical"
    ] | None = None

    status: Literal[
        "new", "acknowledged", "investigating", "resolved"
    ] | None = None

    assigned_to: str | None = Field(
        default=None, max_length=100
    )

class IncidentActivityCreate(BaseModel):
    action: str = Field(min_length=1, max_length=50)
    description: str = Field(min_length=1, max_length=2000)
    actor: str = Field(default="Analyst", max_length=100)
class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)


class UserLogin(BaseModel):
    username_or_email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=8, max_length=128)
class AdminUserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=100)
    email: str = Field(min_length=5, max_length=255)
    password: str = Field(min_length=8, max_length=128)
    role: Literal["admin", "analyst", "viewer"] = "analyst"
class AdminUserUpdate(BaseModel):
    role: Literal["admin", "analyst", "viewer"] | None = None
    is_active: bool | None = None
def validate_indicator(indicator_type: str, value: str) -> dict:
    value = value.strip()
    indicator_type = indicator_type.lower()

    if not value:
        raise HTTPException(status_code=422, detail="Indicator cannot be empty.")

    if indicator_type == "ip":
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid IP address.")

        return {
            "normalized_value": str(parsed),
            "format_valid": True,
            "details": {
                "version": parsed.version,
                "is_private": parsed.is_private,
                "is_global": parsed.is_global,
                "is_loopback": parsed.is_loopback,
            },
        }

    if indicator_type == "domain":
        domain = value.rstrip(".").lower()

        try:
            domain = domain.encode("idna").decode("ascii")
        except UnicodeError:
            raise HTTPException(status_code=422, detail="Invalid domain name.")

        if len(domain) > 253:
            raise HTTPException(status_code=422, detail="Domain name is too long.")

        labels = domain.split(".")
        label_pattern = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

        if (
            len(labels) < 2
            or any(not label_pattern.fullmatch(label) for label in labels)
        ):
            raise HTTPException(status_code=422, detail="Invalid domain name.")

        return {
            "normalized_value": domain,
            "format_valid": True,
            "details": {"label_count": len(labels)},
        }

    if indicator_type == "url":
        try:
            parsed = urlsplit(value)
            hostname = parsed.hostname
            # Accessing .port also validates malformed port numbers.
            _ = parsed.port
        except ValueError:
            raise HTTPException(status_code=422, detail="Invalid URL.")

        if (
            parsed.scheme.lower() not in {"http", "https"}
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise HTTPException(
                status_code=422,
                detail="Provide an HTTP or HTTPS URL with a hostname and no embedded credentials.",
            )

        return {
            "normalized_value": value,
            "format_valid": True,
            "details": {
                "scheme": parsed.scheme.lower(),
                "hostname": hostname.lower(),
            },
        }

    if indicator_type == "hash":
        hash_value = value.lower()
        hash_lengths = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}

        if len(hash_value) not in hash_lengths or not re.fullmatch(
            r"[0-9a-f]+", hash_value
        ):
            raise HTTPException(
                status_code=422,
                detail="Provide a 32-character MD5, 40-character SHA-1, or 64-character SHA-256 hash.",
            )

        return {
            "normalized_value": hash_value,
            "format_valid": True,
            "details": {"algorithm": hash_lengths[len(hash_value)]},
        }

    raise HTTPException(
        status_code=422,
        detail="Unsupported indicator type. Use ip, domain, url, or hash.",
    )


@app.get("/")
def root():
    return {
        "name": settings.app_name,
        "status": "running",
        "docs": "/docs",
    }


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "service": "api"}



@app.post("/api/v1/indicators/analyze", tags=["Indicator Analysis"])
async def analyze_indicator(request: IndicatorRequest,
                              current_user: User = Depends(
        require_role("admin", "analyst")
    ),):
    result = validate_indicator(
        request.indicator_type,
        request.value,
    )


    threat_intel = None

    if request.indicator_type == "ip":
        threat_intel = await lookup_ip_reputation(request.value)

    elif request.indicator_type == "domain":
        threat_intel = await lookup_domain_reputation(request.value)

    elif request.indicator_type == "hash":
        threat_intel = await lookup_hash_reputation(request.value)

    elif request.indicator_type == "url":
        threat_intel = await lookup_url_reputation(request.value)




    response = {
        "indicator_type": request.indicator_type.lower(),
        "indicator": result["normalized_value"],
        "format_valid": result["format_valid"],
        "risk_level": "unknown",
        "verdict": "unknown",
        "evidence": [
            {
                "source": "local_validation",
                "finding": (
                    "The indicator format was validated. "
                    "Indicator format validation completed successfully. "
                ),
            }
        ],
        "details": result["details"],
        "recommendation": (
            "Check trusted threat-intelligence sources "
            "before making a security decision."
        ),
    }



    if threat_intel is not None:
        response["threat_intelligence"] = threat_intel

        if threat_intel.get("available"):
            response["verdict"] = threat_intel["verdict"]
            response["risk_level"] = threat_intel["risk_level"]

            stats = threat_intel.get("analysis_stats", {})

            response["evidence"].append({
                "source": "VirusTotal",
                "finding": (
                    f"VirusTotal {request.indicator_type} "
                    "reputation lookup completed."
                ),
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
            })



        response["recommendation"] = (
            "Review the number of malicious and suspicious detections, "
            "the reporting vendors, and other available context. "
            "A single detection is not conclusive proof of malicious "
            "activity, and zero detections do not guarantee safety."
        )




    db: Session = SessionLocal()

    try:
        # Calculate risk BEFORE creating the database record.
        risk_result = calculate_risk(threat_intel)

        response["risk_score"] = risk_result["score"]
        response["risk_level"] = risk_result["risk_level"]
        response["verdict"] = risk_result["verdict"]
        response["risk_explanation"] = risk_result["explanation"]

        # Create the record only after all response fields are ready.
        record = AnalysisHistory(
            indicator_type=response["indicator_type"],
            indicator=response["indicator"],
            format_valid=response["format_valid"],
            risk_level=response["risk_level"],
            verdict=response["verdict"],
            risk_score=response["risk_score"],
            risk_explanation=response["risk_explanation"],
            evidence=response["evidence"],
            details=response["details"],
            recommendation=response["recommendation"],
        )

        db.add(record)
        db.commit()
        db.refresh(record)

    except Exception as exc:
        db.rollback()
        logger.exception("Failed to save analysis history")
        raise HTTPException(
            status_code=503,
            detail=f"Database save failed: {type(exc).__name__}: {exc}",
        ) from exc
    finally:
        db.close()

    return response


@app.get("/api/v1/indicators/history", tags=["Indicator Analysis"])
def get_analysis_history(
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(
    require_role("admin", "analyst", "viewer")
),
):
    db = SessionLocal()

    try:
        statement = (
            select(AnalysisHistory)
            .order_by(
                AnalysisHistory.created_at.desc(),
                AnalysisHistory.id.desc(),
            )
            .limit(limit)
        )

        records = db.scalars(statement).all()

        items = []
        for record in records:
            items.append({
                "id": record.id,
                "indicator_type": record.indicator_type,
                "indicator": record.indicator,
                "format_valid": record.format_valid,
                "risk_level": record.risk_level,
                "verdict": record.verdict,
                "details": record.details,
                "recommendation": record.recommendation,
                "created_at": (
                    record.created_at.isoformat()
                    if record.created_at is not None
                    else None
                ),
            })

        return {
            "count": len(items),
            "items": items,
        }

    except Exception:
        logger.exception("Failed to retrieve analysis history")
        raise HTTPException(
            status_code=503,
            detail="Unable to retrieve analysis history. Check backend logs.",
        )

    finally:
        db.close()


def incident_to_dict(incident: Incident) -> dict:
    return {
        "id": incident.id,
        "title": incident.title,
        "description": incident.description,
        "severity": incident.severity,
        "status": incident.status,
        "indicator_type": incident.indicator_type,
        "indicator": incident.indicator,
        "created_at": incident.created_at,
        "updated_at": incident.updated_at,
        "assigned_to": incident.assigned_to,
        "resolution_summary": incident.resolution_summary,
        "root_cause": incident.root_cause,
        "resolved_at": incident.resolved_at.isoformat() if incident.resolved_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
    }




@app.get("/api/v1/incidents", tags=["Incident Management"])
def list_incidents(
    status: str | None = None,
    severity: str | None = None,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(
        require_role("admin", "analyst", "viewer")
    ),
):
    db = SessionLocal()

    try:
        statement = select(Incident)

        if status is not None:
            if status not in {"open", "investigating", "resolved", "closed"}:
                raise HTTPException(
                    status_code=422,
                    detail="Invalid incident status."
                )
            statement = statement.where(Incident.status == status)

        if severity is not None:
            if severity not in {"low", "medium", "high", "critical"}:
                raise HTTPException(
                    status_code=422,
                    detail="Invalid incident severity."
                )
            statement = statement.where(Incident.severity == severity)

        total = db.scalar(
            select(func.count()).select_from(statement.subquery())
        ) or 0

        incidents = db.scalars(
            statement
            .order_by(Incident.created_at.desc())
            .offset(skip)
            .limit(limit)
        ).all()

        return {
            "count": len(incidents),
            "total": total,
            "items": [incident_to_dict(i) for i in incidents],
        }

    finally:
        db.close()


@app.get("/api/v1/incidents/{incident_id}", tags=["Incident Management"])
def get_incident(incident_id: int,
                current_user: User = Depends(require_role("admin", "analyst", "viewer")
                ),):
    db = SessionLocal()
    try:
        incident = db.get(Incident, incident_id)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found.")
        return incident_to_dict(incident)
    finally:
        db.close()




@app.patch("/api/v1/incidents/{incident_id}", tags=["Incident Management"])
def update_incident(
    incident_id: int,
    payload: IncidentUpdate,
    current_user: User = Depends(
        require_role("admin", "analyst")
    ),
):
    updates = payload.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=422,
            detail="Provide at least one field to update.",
        )

    if any(value is None for value in updates.values()):
        raise HTTPException(
            status_code=422,
            detail="Update fields cannot be null.",
        )

    db = SessionLocal()

    try:
        incident = db.get(Incident, incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        previous_values = {
            field: getattr(incident, field)
            for field in updates
        }

        previous_status = incident.status
        previous_severity = incident.severity

        for field, value in updates.items():
            setattr(incident, field, value)

        if incident.status != previous_status:

            if incident.status == "resolved":
                incident.resolved_at = datetime.now(timezone.utc)
                incident.closed_at = None

            elif incident.status == "closed":
                incident.closed_at = datetime.now(timezone.utc)

                if incident.resolved_at is None:
                    incident.resolved_at = datetime.now(timezone.utc)

            elif incident.status in ["open", "investigating"]:
                incident.resolved_at = None
                incident.closed_at = None

        # Existing incident activity tracking
        if incident.status != previous_status:
            db.add(IncidentActivity(
                incident_id=incident.id,
                action="STATUS_CHANGED",
                description=(
                    f"Status changed from {previous_status} "
                    f"to {incident.status}."
                ),
                actor=current_user.username,
            ))

        if incident.severity != previous_severity:
            db.add(IncidentActivity(
                incident_id=incident.id,
                action="SEVERITY_CHANGED",
                description=(
                    f"Severity changed from {previous_severity} "
                    f"to {incident.severity}."
                ),
                actor=current_user.username,
            ))

        if (
            "assigned_to" in updates
            and updates["assigned_to"] != previous_values.get("assigned_to")
        ):
            db.add(IncidentActivity(
                incident_id=incident.id,
                action="ASSIGNED",
                description=f"Incident assigned to {incident.assigned_to}.",
                actor=current_user.username,
            ))

        if "resolution_summary" in updates or "root_cause" in updates:
            db.add(IncidentActivity(
                incident_id=incident.id,
                action="RESOLUTION_UPDATED",
                description="Incident resolution details updated.",
                actor=current_user.username,
            ))

        # Security audit logging
        changes = {
            field: {
                "old": previous_values[field],
                "new": updates[field],
            }
            for field in updates
            if previous_values[field] != updates[field]
        }

        if changes:
            log_audit_event(
                db=db,
                user=current_user,
                action="INCIDENT_UPDATED",
                resource_type="incident",
                resource_id=incident.id,
                details={"changes": changes},
            )

        db.commit()
        db.refresh(incident)

        return incident_to_dict(incident)

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Failed to update incident")

        raise HTTPException(
            status_code=500,
            detail="Unable to update incident.",
        )

    finally:
        db.close()


@app.delete(
    "/api/v1/incidents/{incident_id}",
    tags=["Incident Management"],
    status_code=204,
)
def delete_incident(
    incident_id: int,
    current_user: User = Depends(
        require_role("admin")
    ),
):
    db = SessionLocal()

    try:
        incident = db.get(Incident, incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        # Capture details before deleting the incident
        incident_details = {
            "title": incident.title,
            "severity": incident.severity,
            "status": incident.status,
        }

        # Record the deletion in the audit log
        log_audit_event(
            db=db,
            user=current_user,
            action="INCIDENT_DELETED",
            resource_type="incident",
            resource_id=incident.id,
            details=incident_details,
        )

        db.delete(incident)
        db.commit()

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Failed to delete incident")
        raise HTTPException(
            status_code=500,
            detail="Unable to delete incident.",
        )

    finally:
        db.close()

@app.post("/api/v1/incidents", tags=["Incident Management"], status_code=201)
def create_incident(
    payload: IncidentCreate,
    current_user: User = Depends(
        require_role("admin", "analyst")
    ),
):
    db = SessionLocal()

    try:
        incident = Incident(**payload.model_dump())
        db.add(incident)
        db.flush()

        # Existing incident activity tracking
        activity = IncidentActivity(
            incident_id=incident.id,
            action="CREATED",
            description=f"Incident '{incident.title}' was created.",
            actor=current_user.username,
        )
        db.add(activity)

        # Security audit logging
        log_audit_event(
            db=db,
            user=current_user,
            action="INCIDENT_CREATED",
            resource_type="incident",
            resource_id=incident.id,
            details={
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
            },
        )

        db.commit()
        db.refresh(incident)

        return incident_to_dict(incident)

    except Exception:
        db.rollback()
        logger.exception("Failed to create incident")
        raise HTTPException(
            status_code=500,
            detail="Unable to create incident.",
        )

    finally:
        db.close()

@app.get(
    "/api/v1/incidents/{incident_id}/notes",
    tags=["Incident Investigation"],
)
def get_incident_notes(incident_id: int,
                       current_user: User = Depends(
    require_role("admin", "analyst", "viewer")
),):
    db = SessionLocal()
    try:
        incident = db.get(Incident, incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        notes = db.scalars(
            select(IncidentNote)
            .where(IncidentNote.incident_id == incident_id)
            .order_by(IncidentNote.created_at.desc())
        ).all()

        return {
            "count": len(notes),
            "items": [
                {
                    "id": item.id,
                    "incident_id": item.incident_id,
                    "note": item.note,
                    "author": item.author,
                    "created_at": item.created_at,
                }
                for item in notes
            ],
        }
    finally:
        db.close()


@app.post(
    "/api/v1/incidents/{incident_id}/notes",
    tags=["Incident Investigation"],
    status_code=201,
)
def create_incident_note(
    incident_id: int,
    payload: IncidentNoteCreate,
    current_user: User = Depends(
        require_role("admin", "analyst")
    ),
):
    db = SessionLocal()

    try:
        incident = db.get(Incident, incident_id)

        if incident is None:
            raise HTTPException(
                status_code=404,
                detail="Incident not found.",
            )

        note = IncidentNote(
            incident_id=incident_id,
            note=payload.note,
            author=current_user.username,
        )

        db.add(note)
        db.flush()

        # Security audit logging
        log_audit_event(
            db=db,
            user=current_user,
            action="INCIDENT_NOTE_CREATED",
            resource_type="incident",
            resource_id=incident_id,
            details={
                "note_id": note.id,
            },
        )

        db.commit()
        db.refresh(note)

        return {
            "id": note.id,
            "incident_id": note.incident_id,
            "note": note.note,
            "author": note.author,
            "created_at": note.created_at,
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Failed to create incident note")
        raise HTTPException(
            status_code=500,
            detail="Unable to create incident note.",
        )

    finally:
        db.close()

# ==============================
# Authentication
# ==============================

@app.post(
    "/api/v1/auth/register",
    tags=["Authentication"],
    status_code=201,
)
def register_user(payload: UserRegister):
    db = SessionLocal()

    try:
        username = payload.username.strip().lower()
        email = payload.email.strip().lower()

        if "@" not in email:
            raise HTTPException(
                status_code=400,
                detail="Invalid email address.",
            )

        existing_user = db.query(User).filter(
            (User.username == username) |
            (User.email == email)
        ).first()

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail="Username or email already registered.",
            )

        user = User(
            username=username,
            email=email,
            hashed_password=hash_password(payload.password),
            role="analyst",
            is_active=True,
        )

        db.add(user)
        db.commit()
        db.refresh(user)

        return {
            "message": "User registered successfully.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
            },
        }

    except HTTPException:
        raise

    except Exception:
        db.rollback()
        logger.exception("User registration failed")
        raise HTTPException(
            status_code=500,
            detail="Unable to register user.",
        )

    finally:
        db.close()


@app.post(
    "/api/v1/auth/login",
    tags=["Authentication"],
)
@limiter.limit("5/minute")
def login_user(payload: UserLogin, request: Request):
    db = SessionLocal()

    try:
        identifier = payload.username_or_email.strip().lower()

        user = db.query(User).filter(
            (User.username == identifier) |
            (User.email == identifier)
        ).first()

        client_ip = (
            request.client.host
            if request.client
            else None
        )

        # Failed login: invalid username or password
        if (
            user is None
            or not verify_password(
                payload.password,
                user.hashed_password,
            )
        ):
            log_audit_event(
                db=db,
                action="LOGIN_FAILED",
                username=identifier,
                resource_type="authentication",
                details={"reason": "invalid_credentials"},
                ip_address=client_ip,
            )
            db.commit()

            raise HTTPException(
                status_code=401,
                detail="Incorrect username/email or password.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Login blocked: inactive account
        if not user.is_active:
            log_audit_event(
                db=db,
                action="LOGIN_BLOCKED",
                user=user,
                resource_type="authentication",
                details={"reason": "inactive_account"},
                ip_address=client_ip,
            )
            db.commit()

            raise HTTPException(
                status_code=403,
                detail="This account is inactive.",
            )

        access_token = create_access_token(
            user_id=user.id,
            role=user.role,
        )

        # Successful login
        log_audit_event(
            db=db,
            action="LOGIN_SUCCESS",
            user=user,
            resource_type="authentication",
            details={"role": user.role},
            ip_address=client_ip,
        )
        db.commit()

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
            },
        }

    finally:
        db.close()

@app.get(
    "/api/v1/auth/me",
    tags=["Authentication"],
)
def get_my_account(
    current_user: User = Depends(get_current_user),
):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "role": current_user.role,
        "is_active": current_user.is_active,
    }
@app.get(
    "/api/v1/admin/users",
    tags=["Admin User Management"],
)
def get_all_users(
    current_user: User = Depends(
        require_role("admin")
    ),
):
    db = SessionLocal()

    try:
        users = db.scalars(
            select(User).order_by(User.id.asc())
        ).all()

        return {
            "count": len(users),
            "items": [
                {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role,
                    "is_active": user.is_active,
                    "created_at": (
                        user.created_at.isoformat()
                        if user.created_at
                        else None
                    ),
                }
                for user in users
            ],
        }

    finally:
        db.close()
@app.post(
    "/api/v1/admin/users",
    status_code=201,
    tags=["Admin User Management"],
)
def create_admin_user(
    payload: AdminUserCreate,
    current_user: User = Depends(
        require_role("admin")
    ),
):
    db = SessionLocal()

    try:
        username = payload.username.strip().lower()
        email = payload.email.strip().lower()

        existing_user = db.scalar(
            select(User).where(
                (User.username == username)
                | (User.email == email)
            )
        )

        if existing_user:
            raise HTTPException(
                status_code=409,
                detail="Username or email already exists.",
            )

        new_user = User(
            username=username,
            email=email,
            hashed_password=hash_password(payload.password),
            role=payload.role,
            is_active=True,
        )

        db.add(new_user)
        db.flush()

        log_audit_event(
            db,
            user=current_user,
            action="ADMIN_USER_CREATED",
            resource_type="user",
            resource_id=new_user.id,
            details={
                "username": new_user.username,
                "role": new_user.role,
            },
        )

        db.commit()
        db.refresh(new_user)

        return {
            "message": "User created successfully.",
            "user": {
                "id": new_user.id,
                "username": new_user.username,
                "email": new_user.email,
                "role": new_user.role,
                "is_active": new_user.is_active,
                "created_at": (
                    new_user.created_at.isoformat()
                    if new_user.created_at
                    else None
                ),
            },
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Admin user creation failed.")
        raise HTTPException(
            status_code=500,
            detail="Unable to create user.",
        )

    finally:
        db.close()
@app.patch(
    "/api/v1/admin/users/{user_id}",
    tags=["Admin User Management"],
)
def update_admin_user(
    user_id: int,
    payload: AdminUserUpdate,
    current_user: User = Depends(
        require_role("admin")
    ),
):
    db = SessionLocal()

    try:
        updates = payload.model_dump(exclude_unset=True)

        if not updates:
            raise HTTPException(
                status_code=400,
                detail="At least one field must be provided.",
            )

        user = db.scalar(
            select(User).where(User.id == user_id)
        )

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found.",
            )

        if any(value is None for value in updates.values()):
            raise HTTPException(
                status_code=422,
                detail="Update values cannot be null.",
            )

        # Prevent an administrator from locking themselves out.
        if user.id == current_user.id:
            if updates.get("is_active") is False:
                raise HTTPException(
                    status_code=400,
                    detail="You cannot deactivate your own account.",
                )

            if updates.get("role") not in (None, "admin"):
                raise HTTPException(
                    status_code=400,
                    detail="You cannot remove your own admin role.",
                )

        previous_values = {
            field: getattr(user, field)
            for field in updates
        }

        # Protect the last active administrator.
        removing_admin_access = (
            user.role == "admin"
            and user.is_active
            and (
                updates.get("role", user.role) != "admin"
                or updates.get("is_active", user.is_active) is False
            )
        )

        if removing_admin_access:
            active_admin_count = db.scalar(
                select(func.count(User.id)).where(
                    User.role == "admin",
                    User.is_active.is_(True),
                )
            )

            if active_admin_count <= 1:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot remove the last active administrator.",
                )

        for field, value in updates.items():
            setattr(user, field, value)

        changes = {
            field: {
                "old": previous_values[field],
                "new": getattr(user, field),
            }
            for field in updates
            if previous_values[field] != getattr(user, field)
        }

        if changes:
            log_audit_event(
                db,
                user=current_user,
                action="ADMIN_USER_UPDATED",
                resource_type="user",
                resource_id=user.id,
                details={
                    "target_username": user.username,
                    "changes": changes,
                },
            )

        db.commit()
        db.refresh(user)

        return {
            "message": "User updated successfully.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role,
                "is_active": user.is_active,
                "created_at": (
                    user.created_at.isoformat()
                    if user.created_at
                    else None
                ),
            },
        }

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Admin user update failed.")
        raise HTTPException(
            status_code=500,
            detail="Unable to update user.",
        )

    finally:
        db.close()
@app.delete(
    "/api/v1/admin/users/{user_id}",
    status_code=204,
    tags=["Admin User Management"],
)
def delete_admin_user(
    user_id: int,
    current_user: User = Depends(
        require_role("admin")
    ),
):
    db = SessionLocal()

    try:
        user = db.scalar(
            select(User).where(User.id == user_id)
        )

        if not user:
            raise HTTPException(
                status_code=404,
                detail="User not found.",
            )

        # Prevent self-deletion.
        if user.id == current_user.id:
            raise HTTPException(
                status_code=400,
                detail="You cannot delete your own account.",
            )

        # Protect the last active administrator.
        if user.role == "admin" and user.is_active:
            active_admin_count = db.scalar(
                select(func.count(User.id)).where(
                    User.role == "admin",
                    User.is_active.is_(True),
                )
            )

            if active_admin_count <= 1:
                raise HTTPException(
                    status_code=400,
                    detail="Cannot delete the last active administrator.",
                )

        deleted_user_details = {
            "username": user.username,
            "email": user.email,
            "role": user.role,
        }

        log_audit_event(
            db,
            user=current_user,
            action="ADMIN_USER_DELETED",
            resource_type="user",
            resource_id=user.id,
            details=deleted_user_details,
        )

        db.delete(user)
        db.commit()

        return None

    except HTTPException:
        db.rollback()
        raise

    except Exception:
        db.rollback()
        logger.exception("Admin user deletion failed.")
        raise HTTPException(
            status_code=500,
            detail="Unable to delete user.",
        )

    finally:
        db.close()
# ==============================
# Threat Intelligence Cache Stats
# ==============================

@app.get(
    "/api/v1/admin/cache-stats",
    tags=["Threat Intelligence Cache"],
)
def get_threat_intelligence_cache_stats(
    current_user: User = Depends(
        require_role("admin")
    ),
):
    return {
        "message": "Cache statistics retrieved successfully.",
        "statistics": get_cache_stats(),
    }
# ==============================
# Security Audit Logs
# ==============================

@app.get(
    "/api/v1/audit-logs",
    tags=["Security Audit"],
)
def get_audit_logs(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=200),
    action: str | None = None,
    current_user: User = Depends(
        require_role("admin")
    ),
):
    db = SessionLocal()

    try:
        statement = select(AuditLog)

        if action:
            statement = statement.where(
                AuditLog.action == action
            )

        total = db.scalar(
            select(func.count()).select_from(statement.subquery())
        ) or 0

        logs = db.scalars(
            statement
            .order_by(
                AuditLog.created_at.desc(),
                AuditLog.id.desc(),
            )
            .offset(skip)
            .limit(limit)
        ).all()

        return {
            "count": len(logs),
            "total": total,
            "items": [
                {
                    "id": log.id,
                    "user_id": log.user_id,
                    "username": log.username,
                    "action": log.action,
                    "resource_type": log.resource_type,
                    "resource_id": log.resource_id,
                    "details": log.details,
                    "ip_address": log.ip_address,
                    "created_at": (
                        log.created_at.isoformat()
                        if log.created_at
                        else None
                    ),
                }
                for log in logs
            ],
        }

    finally:
        db.close()
@app.get("/api/v1/alerts")
def get_alerts(
    severity: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    search: str | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):

    query = select(Alert)

    if severity:
        query = query.where(Alert.severity == severity)

    if status_filter:
        query = query.where(Alert.status == status_filter)

    if search:
        search_term = f"%{search}%"
        query = query.where(
            Alert.title.ilike(search_term)
            | Alert.description.ilike(search_term)
            | Alert.indicator.ilike(search_term)
        )

    total = db.scalar(
        select(func.count()).select_from(query.subquery())
    )

    alerts = db.scalars(
        query
        .order_by(Alert.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()

    return {
        "count": total,
        "items": [
            {
                "id": alert.id,
                "title": alert.title,
                "description": alert.description,
                "source": alert.source,
                "severity": alert.severity,
                "status": alert.status,
                "indicator_type": alert.indicator_type,
                "indicator": alert.indicator,
                "risk_score": alert.risk_score,
                "evidence": alert.evidence,
                "assigned_to": alert.assigned_to,
                "incident_id": alert.incident_id,
                "created_at": alert.created_at,
                "updated_at": alert.updated_at,
            }
            for alert in alerts
        ],
    }
@app.post("/api/v1/alerts", status_code=201)
def create_alert(
    payload: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "analyst")
    ),
):
    alert = Alert(
        title=payload.title,
        description=payload.description,
        source=payload.source,
        severity=payload.severity,
        status="new",
        indicator_type=payload.indicator_type,
        indicator=payload.indicator,
        risk_score=payload.risk_score,
        evidence=payload.evidence,
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    log_audit_event(
        db=db,
        user=current_user,
        action="ALERT_CREATED",
        resource_type="alert",
        resource_id=str(alert.id),
        details={
            "title": alert.title,
            "severity": alert.severity,
            "source": alert.source,
        },
    )

    db.commit()

    return {
        "message": "Alert created successfully.",
        "alert_id": alert.id,
        "severity": alert.severity,
        "status": alert.status,
    }
@app.patch("/api/v1/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    payload: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "analyst")
    ),
):
    alert = db.get(Alert, alert_id)

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found.",
        )

    updates = payload.model_dump(exclude_unset=True)

    if not updates:
        raise HTTPException(
            status_code=400,
            detail="No update fields provided.",
        )

    for field, value in updates.items():
        setattr(alert, field, value)

    db.commit()
    db.refresh(alert)

    log_audit_event(
        db=db,
        user=current_user,
        action="ALERT_UPDATED",
        resource_type="alert",
        resource_id=str(alert.id),
        details=updates,
    )

    db.commit()

    return {
        "message": "Alert updated successfully.",
        "alert_id": alert.id,
        "severity": alert.severity,
        "status": alert.status,
        "assigned_to": alert.assigned_to,
    }
@app.post("/api/v1/alerts/{alert_id}/convert-to-incident", status_code=201)
def convert_alert_to_incident(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "analyst")
    ),
):
    alert = db.get(Alert, alert_id)

    if not alert:
        raise HTTPException(
            status_code=404,
            detail="Alert not found.",
        )

    if alert.incident_id is not None:
        raise HTTPException(
            status_code=409,
            detail="Alert is already linked to an incident.",
        )

    incident = Incident(
        title=alert.title,
        description=alert.description,
        severity=alert.severity,
        status="open",
        indicator_type=alert.indicator_type,
        indicator=alert.indicator,
        evidence=alert.evidence,
        assigned_to=alert.assigned_to,
    )

    db.add(incident)
    db.flush()

    alert.incident_id = incident.id
    alert.status = "investigating"

    db.add(
        IncidentActivity(
            incident_id=incident.id,
            action="created_from_alert",
            description=f"Incident created from alert #{alert.id}.",
            actor=current_user.username,
        )
    )

    log_audit_event(
        db=db,
        user=current_user,
        action="ALERT_CONVERTED_TO_INCIDENT",
        resource_type="alert",
        resource_id=str(alert.id),
        details={"incident_id": incident.id},
    )

    db.commit()
    db.refresh(incident)

    return {
        "message": "Alert converted to incident successfully.",
        "alert_id": alert.id,
        "incident_id": incident.id,
    }

@app.post(
    "/api/v1/network/analyze-pcap",
    status_code=201,
    tags=["Network Traffic Analysis"],
)
@app.get("/api/v1/network/anomalies")
def get_network_anomalies(
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "analyst", "viewer")
    ),
):
    if limit < 1 or limit > 500:
        raise HTTPException(
            status_code=400,
            detail="Limit must be between 1 and 500.",
        )

    if offset < 0:
        raise HTTPException(
            status_code=400,
            detail="Offset cannot be negative.",
        )
    total = db.scalar(
    select(func.count()).select_from(NetworkAnomaly)
) or 0
    anomalies = db.scalars(
        select(NetworkAnomaly)
        .order_by(NetworkAnomaly.detected_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()

    return {
    "total": total,
    "anomalies": [
            {
                "id": anomaly.id,
                "flow_id": anomaly.flow_id,
                "source_ip": anomaly.source_ip,
                "destination_ip": anomaly.destination_ip,
                "protocol": anomaly.protocol,
                "anomaly_score": anomaly.anomaly_score,
                "status": anomaly.status,
                "model_name": anomaly.model_name,
                "detected_at": anomaly.detected_at,
            }
            for anomaly in anomalies
        ],
    }
@app.post("/api/v1/network/detect-anomalies")
def detect_network_anomalies(
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
):
    if not model_exists():
        raise HTTPException(
            status_code=503,
            detail="Anomaly detection model is not available.",
        )

    detector = load_model()

    if detector is None:
        raise HTTPException(
            status_code=503,
            detail="Unable to load anomaly detection model.",
        )

    flows = db.scalars(
        select(NetworkFlow).order_by(NetworkFlow.id.asc())
    ).all()

    if not flows:
        raise HTTPException(
            status_code=404,
            detail="No network flows available for analysis.",
        )

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
        for flow in flows
    ]

    try:
        predictions = detector.predict(flow_data)

        saved_count = save_anomaly_results(db, predictions)

        db.commit()

        anomaly_results = [
            prediction
            for prediction in predictions
            if prediction.get("is_anomaly", False)
        ]

        log_audit_event(
            db=db,
            action="NETWORK_ANOMALIES_DETECTED",
            user=current_user,
            username=current_user.username,
            resource_type="network_analysis",
            resource_id="anomaly_detection",
            details={
                "total_flows": len(flows),
                "anomalies_detected": len(anomaly_results),
                "anomalies_saved": saved_count,
            },
            ip_address=None,
        )

        db.commit()

        return {
            "message": "Network anomaly detection completed.",
            "total_flows_analyzed": len(flows),
            "anomalies_detected": len(anomaly_results),
            "anomalies_saved": saved_count,
            "anomalies": anomaly_results,
        }

    except Exception:
        db.rollback()
        raise HTTPException(
            status_code=500,
            detail="Failed to complete network anomaly detection.",
        )
async def analyze_network_pcap(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "analyst")
    ),
):
    # Read at most 10 MB + 1 byte to enforce the upload limit.
    try:
        file_content = await file.read(MAX_PCAP_SIZE + 1)
    finally:
        await file.close()

    if len(file_content) > MAX_PCAP_SIZE:
        raise HTTPException(
            status_code=413,
            detail="PCAP file exceeds the 10 MB upload limit.",
        )

    # Validate the uploaded PCAP.
    try:
        validation = validate_pcap(file_content)
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        )

    # Extract network-flow metadata.
    try:
        flows = analyze_pcap(file_content)
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="Unable to analyze the uploaded PCAP file.",
        )

    # Prepare database records.
    network_flow_records = [
        NetworkFlow(**flow)
        for flow in flows
    ]

    try:
        db.add_all(network_flow_records)
        db.flush()

        # Record the upload in the security audit log.
        log_audit_event(
            db=db,
            user=current_user,
            action="PCAP_ANALYZED",
            resource_type="network_capture",
            resource_id="pcap_upload",
            details={
                "file_size_bytes": validation["file_size_bytes"],
                "packet_count": validation["packet_count"],
                "flow_count": len(flows),
            },
        )

        # Commit flow records and audit event together.
        db.commit()

    except Exception:
        db.rollback()
        logger.exception("Failed to save PCAP analysis results.")

        raise HTTPException(
            status_code=500,
            detail="Failed to save network analysis results.",
        )

    return {
        "message": "PCAP analysis completed successfully.",
        "file_size_bytes": validation["file_size_bytes"],
        "packet_count": validation["packet_count"],
        "flow_count": len(flows),
        "flows": [
            {
                "id": flow.id,
                "source_ip": flow.source_ip,
                "destination_ip": flow.destination_ip,
                "source_port": flow.source_port,
                "destination_port": flow.destination_port,
                "protocol": flow.protocol,
                "packet_count": flow.packet_count,
                "byte_count": flow.byte_count,
                "start_time": flow.start_time,
                "end_time": flow.end_time,
                "duration_seconds": flow.duration_seconds,
                "tcp_flags": flow.tcp_flags,
            }
            for flow in network_flow_records
        ],
    }

@app.post(
    "/api/v1/ai-analysis/incidents/{incident_id}",
    tags=["AI Security Analysis"],
    status_code=201,
)
def generate_incident_ai_report(
    incident_id: int,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_role("admin", "analyst")),
):
    # 1. Build evidence for the requested incident.
    try:
        evidence = build_incident_evidence(db, incident_id)
    except ValueError:
        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        )

    # 2. Generate the AI report.
    try:
        analyzer = AISecurityAnalyzer()
        report_data = analyzer.analyze(evidence)
    except Exception:
        logger.exception("AI incident analysis failed.")
        raise HTTPException(
            status_code=502,
            detail="AI analysis service is currently unavailable.",
        )

    # 3. Save the report and audit event in one transaction.
    try:
        report_record = AIAnalysisReport(
            user_id=current_user.id,
            incident_id=incident_id,
            alert_id=None,
            model_name=analyzer.model,
            evidence_snapshot=evidence,
            report=report_data,
        )

        db.add(report_record)
        db.flush()

        log_audit_event(
            db=db,
            user=current_user,
            action="AI_ANALYSIS_REPORT_GENERATED",
            resource_type="ai_analysis_report",
            resource_id=report_record.id,
            details={
                "incident_id": incident_id,
                "model_name": analyzer.model,
            },
            ip_address=request.client.host if request.client else None,
        )

        db.commit()
        db.refresh(report_record)

        return {
            "message": "AI security analysis report generated successfully.",
            "report_id": report_record.id,
            "incident_id": report_record.incident_id,
            "model_name": report_record.model_name,
            "created_at": report_record.created_at,
            "evidence_snapshot": report_record.evidence_snapshot,
            "report": report_record.report,
        }

    except Exception:
        db.rollback()
        logger.exception("Failed to save AI analysis report.")
        raise HTTPException(
            status_code=500,
            detail="Failed to save AI analysis report.",
        )

@app.get(
    "/api/v1/ai-analysis/reports/{report_id}",
    tags=["AI Security Analysis"],
)
def get_ai_analysis_report(
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "analyst", "viewer")
    ),
):
    report_record = db.get(AIAnalysisReport, report_id)

    if report_record is None:
        raise HTTPException(
            status_code=404,
            detail="AI analysis report not found.",
        )

    return {
        "report_id": report_record.id,
        "user_id": report_record.user_id,
        "incident_id": report_record.incident_id,
        "alert_id": report_record.alert_id,
        "model_name": report_record.model_name,
        "created_at": report_record.created_at,
        "evidence_snapshot": report_record.evidence_snapshot,
        "report": report_record.report,
    }

@app.get(
    "/api/v1/ai-analysis/reports",
    tags=["AI Security Analysis"],
)
def list_ai_analysis_reports(
    incident_id: int | None = Query(default=None, ge=1),
    report_user_id: int | None = Query(default=None, ge=1),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(
        require_role("admin", "analyst", "viewer")
    ),
):
    query = select(AIAnalysisReport)

    if incident_id is not None:
        query = query.where(
            AIAnalysisReport.incident_id == incident_id
        )

    # Only administrators can filter reports by another user's ID.
    if report_user_id is not None:
        if current_user.role != "admin":
            raise HTTPException(
                status_code=403,
                detail="Only administrators can filter by report user.",
            )

        query = query.where(
            AIAnalysisReport.user_id == report_user_id
        )

    total = db.scalar(
        select(func.count()).select_from(query.subquery())
    )

    reports = db.scalars(
        query
        .order_by(AIAnalysisReport.created_at.desc())
        .offset(skip)
        .limit(limit)
    ).all()

    return {
        "total": total or 0,
        "skip": skip,
        "limit": limit,
        "items": [
            {
                "report_id": item.id,
                "user_id": item.user_id,
                "incident_id": item.incident_id,
                "alert_id": item.alert_id,
                "model_name": item.model_name,
                "created_at": item.created_at,
                "severity": item.report.get("severity", "unknown"),
                "threat_category": item.report.get(
                    "threat_category", "unknown"
                ),
                "executive_summary": item.report.get(
                    "executive_summary", ""
                ),
            }
            for item in reports
        ],
    }
