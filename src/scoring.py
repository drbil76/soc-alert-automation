"""
Severity scoring logic combining IP and hash reputation
"""

from __future__ import annotations

from typing import Dict


def calculate_severity(ip_data: Dict, hash_data: Dict) -> str:
    """
    Determine severity as Low, Medium, or High.

    Rules (highest match wins):
    - High if abuse_confidence >= 70 OR malicious detections >= 5
    - Medium if abuse_confidence between 30-69 OR malicious between 1-4 OR suspicious >= 3
    - Low otherwise
    Errors (-1 values) default to Medium to avoid under-triage
    """
    abuse = ip_data.get("abuse_confidence", -1)
    malicious = hash_data.get("malicious", -1)
    suspicious = hash_data.get("suspicious", -1)

    # Handle missing/errored data conservatively
    if abuse == -1 or malicious == -1 or suspicious == -1:
        return "Medium"

    if abuse >= 70 or malicious >= 5:
        return "High"

    if 30 <= abuse < 70 or 1 <= malicious <= 4 or suspicious >= 3:
        return "Medium"

    return "Low"
