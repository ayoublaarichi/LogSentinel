"""
Threat intelligence enrichment service.

Uses the free ip-api.com (no API key required, 45 req/min limit) plus
a local DB cache to avoid hammering the upstream.

Fields returned:
    country, city, asn, isp, reputation_score, is_tor
"""

import json
from datetime import datetime, timedelta
from typing import Optional

import httpx
from sqlalchemy.orm import Session

from app.config import THREAT_INTEL_CACHE_TTL
from app.models import ThreatIntelCache


def _is_private_ip(ip: str) -> bool:
    """Quick check for RFC-1918 and loopback."""
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return True
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


def enrich_ip(db: Session, ip: str) -> dict:
    """
    Return threat intel for *ip*.  Checks the local cache first;
    if stale or missing, fetches from ip-api.com and caches the result.
    """
    if _is_private_ip(ip):
        return {
            "ip": ip,
            "country": "Private",
            "city": "—",
            "asn": "—",
            "isp": "Private Network",
            "reputation_score": None,
            "is_tor": False,
            "source": "local",
        }

    # Check cache
    cached = db.query(ThreatIntelCache).filter(ThreatIntelCache.ip_address == ip).first()
    ttl = timedelta(seconds=THREAT_INTEL_CACHE_TTL)
    if cached and (datetime.utcnow() - cached.fetched_at) < ttl:
        return _cache_to_dict(cached)

    # Fetch from ip-api.com
    try:
        resp = httpx.get(
            f"http://ip-api.com/json/{ip}?fields=status,message,country,city,"
            f"isp,org,as,proxy,hosting,query",
            timeout=5,
        )
        data = resp.json() if resp.status_code == 200 else {}
    except Exception:
        data = {}

    if data.get("status") == "success":
        entry = _upsert_cache(db, ip, data)
        return _cache_to_dict(entry)

    # Return empty if API fails
    return {
        "ip": ip,
        "country": "Unknown",
        "city": "—",
        "asn": "—",
        "isp": "—",
        "reputation_score": None,
        "is_tor": False,
        "source": "error",
    }


def _upsert_cache(db: Session, ip: str, data: dict) -> ThreatIntelCache:
    """Insert or update the threat intel cache row."""
    existing = db.query(ThreatIntelCache).filter(ThreatIntelCache.ip_address == ip).first()

    # Heuristic reputation: proxy + hosting → suspicious
    rep = 0.0
    if data.get("proxy"):
        rep += 50.0
    if data.get("hosting"):
        rep += 30.0

    vals = dict(
        country=data.get("country", "Unknown"),
        city=data.get("city", ""),
        asn=data.get("as", ""),
        isp=data.get("isp", ""),
        reputation_score=rep,
        is_tor=1 if data.get("proxy") else 0,
        raw_json=json.dumps(data),
        fetched_at=datetime.utcnow(),
    )

    if existing:
        for k, v in vals.items():
            setattr(existing, k, v)
        db.commit()
        db.refresh(existing)
        return existing

    entry = ThreatIntelCache(ip_address=ip, **vals)
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def _cache_to_dict(c: ThreatIntelCache) -> dict:
    return {
        "ip": c.ip_address,
        "country": c.country or "Unknown",
        "city": c.city or "—",
        "asn": c.asn or "—",
        "isp": c.isp or "—",
        "reputation_score": c.reputation_score,
        "is_tor": bool(c.is_tor),
        "source": "cached",
    }
