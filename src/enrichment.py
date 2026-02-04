"""
Enrichment functions for IP and file hash IOCs.

Uses AbuseIPDB for IP reputation and VirusTotal for hash reputation.
"""

from __future__ import annotations

import os
from typing import Dict, Any

import requests

DEFAULT_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "10"))


def enrich_ip(ip: str) -> Dict[str, Any]:
    """
    Enrich an IP address using AbuseIPDB.

    Returns a dict with country, isp, abuse_confidence, and a raw fallback.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    base_url = os.getenv("ABUSEIPDB_BASE_URL", "https://api.abuseipdb.com/api/v2/check")
    headers = {"Key": api_key, "Accept": "application/json"}
    params = {"ipAddress": ip, "maxAgeInDays": 90}

    if not api_key:
        raise ValueError("ABUSEIPDB_API_KEY is not set")

    try:
        resp = requests.get(base_url, headers=headers, params=params, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        data = resp.json().get("data", {})
    except Exception as exc:
        return {
            "country": "unknown",
            "isp": "unknown",
            "abuse_confidence": -1,
            "error": str(exc),
        }

    return {
        "country": data.get("countryCode", "unknown"),
        "isp": data.get("isp", "unknown"),
        "abuse_confidence": data.get("abuseConfidenceScore", -1),
    }


def enrich_hash(file_hash: str) -> Dict[str, Any]:
    """
    Enrich a file hash using VirusTotal.

    Returns a dict with malicious, suspicious, undetected counts, and a raw fallback.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    base_url = os.getenv("VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3/files")
    headers = {"x-apikey": api_key}

    if not api_key:
        raise ValueError("VIRUSTOTAL_API_KEY is not set")

    url = f"{base_url}/{file_hash}"

    try:
        resp = requests.get(url, headers=headers, timeout=DEFAULT_TIMEOUT)
        resp.raise_for_status()
        attributes = resp.json().get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
    except Exception as exc:
        return {
            "malicious": -1,
            "suspicious": -1,
            "undetected": -1,
            "error": str(exc),
        }

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
    }
