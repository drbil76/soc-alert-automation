"""
Report generation for SOC investigation in Markdown
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, Any


def generate_report(alert: Dict[str, Any], ip_data: Dict[str, Any], hash_data: Dict[str, Any], severity: str) -> str:
    """
    Build a Markdown investigation report string
    """
    timestamp = datetime.utcnow().isoformat() + "Z"

    return f"""# SOC Investigation Report

**Generated:** {timestamp}
**Alert Name:** {alert.get('alert_name')}
**Source:** {alert.get('source')}
**Host:** {alert.get('host')}
**User:** {alert.get('user')}

## Indicator Enrichment

### Destination IP
- Address: {alert.get('destination_ip')}
- Country: {ip_data.get('country')}
- ISP: {ip_data.get('isp')}
- Abuse Confidence Score: {ip_data.get('abuse_confidence')}

### File Hash
- Hash: {alert.get('file_hash')}
- Malicious Detections: {hash_data.get('malicious')}
- Suspicious Detections: {hash_data.get('suspicious')}
- Undetected: {hash_data.get('undetected')}

## Severity Assessment
- Calculated Severity: **{severity}**

## Analyst Notes
- If severity is High: isolate host, block IP, and submit sample to sandbox
- If severity is Medium: monitor connections, review EDR timeline, and consider containment if activity persists
- If severity is Low: document findings and continue monitoring

## Appendix
- Enrichment errors (if any):
  - IP enrichment error: {ip_data.get('error', 'none')}
  - Hash enrichment error: {hash_data.get('error', 'none')}
"""
