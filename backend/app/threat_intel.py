import os
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv
from sqlalchemy import select

from app.database import SessionLocal
from app.models import ThreatIntelCache



load_dotenv()


VIRUSTOTAL_API_URL = "https://www.virustotal.com/api/v3"
# Threat intelligence cache configuration
THREAT_INTEL_CACHE_TTL_HOURS = int(
    os.getenv("THREAT_INTEL_CACHE_TTL_HOURS", "24")
)
# ==============================
# Cache Performance Metrics
# ==============================

from threading import Lock

_cache_stats = {
    "hits": 0,
    "misses": 0,
    "writes": 0,
    "expired": 0,
}

_cache_stats_lock = Lock()


def record_cache_event(event: str) -> None:
    """Safely increment a cache performance counter."""

    if event not in _cache_stats:
        return

    with _cache_stats_lock:
        _cache_stats[event] += 1


def get_cache_stats() -> dict:
    """Return a snapshot of cache performance metrics."""

    with _cache_stats_lock:
        stats = dict(_cache_stats)

    total = stats["hits"] + stats["misses"]

    stats["total_lookups"] = total
    stats["hit_rate_percent"] = (
        round(stats["hits"] / total * 100, 2)
        if total else 0
    )

    return stats

def get_cached_reputation(
    indicator_type: str,
    indicator: str,
) -> dict | None:
    """Return an unexpired cached reputation result."""

    db = SessionLocal()

    try:
        statement = select(ThreatIntelCache).where(
            ThreatIntelCache.indicator_type == indicator_type,
            ThreatIntelCache.indicator == indicator,
        )

        cached_entry = db.execute(statement).scalar_one_or_none()

        if cached_entry is None:
            record_cache_event("misses")
            return None

        now = datetime.now(timezone.utc)

        # Handle timezone-aware and timezone-naive database values.
        expires_at = cached_entry.expires_at

        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if expires_at <= now:
            record_cache_event("expired")
            record_cache_event("misses")
            return None

        record_cache_event("hits")
        return cached_entry.result

    finally:
        db.close()

def save_cached_reputation(
    indicator_type: str,
    indicator: str,
    result: dict,
) -> None:
    """Save or update a successful reputation result."""

    db = SessionLocal()

    try:
        statement = select(ThreatIntelCache).where(
            ThreatIntelCache.indicator_type == indicator_type,
            ThreatIntelCache.indicator == indicator,
        )

        cached_entry = db.execute(statement).scalar_one_or_none()

        expires_at = datetime.now(timezone.utc) + timedelta(
            hours=THREAT_INTEL_CACHE_TTL_HOURS
        )

        if cached_entry:
            cached_entry.result = result
            cached_entry.expires_at = expires_at
            cached_entry.source = "VirusTotal"
        else:
            cached_entry = ThreatIntelCache(
                indicator_type=indicator_type,
                indicator=indicator,
                source="VirusTotal",
                result=result,
                expires_at=expires_at,
            )

            db.add(cached_entry)

        db.commit()
        record_cache_event("writes")
    except Exception:
        db.rollback()
        raise

    finally:
        db.close()


async def lookup_ip_reputation(ip_address: str) -> dict:
    return await _lookup_reputation(
        f"ip_addresses/{ip_address}",
        "ip",
        ip_address,
    )




async def lookup_domain_reputation(domain: str) -> dict:
    return await _lookup_reputation(
        f"domains/{domain}",
        "domain",
        domain,
    )

async def lookup_hash_reputation(file_hash: str) -> dict:
    return await _lookup_reputation(
        f"files/{file_hash}",
        "hash",
        file_hash,
    )


async def _lookup_reputation(
    resource_path: str,
    indicator_type: str,
    indicator: str,
) -> dict:
    """Fetch reputation data with PostgreSQL caching."""

    # 1. Check PostgreSQL cache first.
    try:
        cached_result = get_cached_reputation(
            indicator_type,
            indicator,
        )

        if cached_result is not None:
            return cached_result

    except Exception:
        # Cache failure should not prevent a live lookup.
        pass

    # 2. Check API configuration.
    api_key = os.getenv("VIRUSTOTAL_API_KEY")

    if not api_key:
        return {
            "available": False,
            "source": "VirusTotal",
            "error": "API key is not configured.",
        }

    headers = {"x-apikey": api_key}
    url = f"{VIRUSTOTAL_API_URL}/{resource_path}"

    # 3. Query VirusTotal.
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.get(url, headers=headers)

        if response.status_code == 404:
            return {
                "available": False,
                "source": "VirusTotal",
                "error": "No report was found for this indicator.",
            }

        if response.status_code == 401:
            message = "VirusTotal rejected the API key."
        elif response.status_code == 429:
            message = "VirusTotal API rate limit reached."
        elif response.status_code != 200:
            message = (
                f"VirusTotal request failed with status "
                f"{response.status_code}."
            )
        else:
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = max(0, int(stats.get("malicious", 0)))
            suspicious = max(0, int(stats.get("suspicious", 0)))

            total = sum(
                max(0, int(stats.get(key, 0)))
                for key in (
                    "malicious",
                    "suspicious",
                    "harmless",
                    "undetected",
                    "timeout",
                    "confirmed-timeout",
                )
            )

            if total == 0:
                verdict, risk_level = "unknown", "unknown"
            elif malicious >= 5:
                verdict, risk_level = "malicious", "high"
            elif malicious >= 2:
                verdict, risk_level = "suspicious", "medium"
            elif malicious == 1 or suspicious > 0:
                verdict, risk_level = "needs_review", "medium"
            else:
                verdict, risk_level = (
                    "no_malicious_detections",
                    "low",
                )

            result = {
                "available": True,
                "source": "VirusTotal",
                "verdict": verdict,
                "risk_level": risk_level,
                "reputation": attributes.get("reputation", 0),
                "analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "timeout": stats.get("timeout", 0),
                    "confirmed-timeout": stats.get(
                        "confirmed-timeout", 0
                    ),
                },
                "last_analysis_date": attributes.get(
                    "last_analysis_date"
                ),
            }

            # 4. Cache only successful reports.
            try:
                save_cached_reputation(
                    indicator_type,
                    indicator,
                    result,
                )
            except Exception:
                # A cache write failure must not discard
                # a successful VirusTotal response.
                pass

            return result

        return {
            "available": False,
            "source": "VirusTotal",
            "error": message,
        }

    except httpx.TimeoutException:
        return {
            "available": False,
            "source": "VirusTotal",
            "error": "VirusTotal request timed out.",
        }

    except (httpx.HTTPError, ValueError, TypeError):
        return {
            "available": False,
            "source": "VirusTotal",
            "error": "Unable to retrieve a valid VirusTotal report.",
        }
async def lookup_url_reputation(url_value: str) -> dict:
    import base64

    url_id = base64.urlsafe_b64encode(
        url_value.encode("utf-8")
    ).decode("ascii").rstrip("=")

    return await _lookup_reputation(
        f"urls/{url_id}",
        "url",
        url_value,
    )
