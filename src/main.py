"""
Entry point for SOC alert automation.

Loads configuration, enriches IOCs, scores severity, and writes report.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

from dotenv import load_dotenv

from .enrichment import enrich_ip, enrich_hash
from .scoring import calculate_severity
from .report import generate_report


def load_alert(path: Path) -> dict:
    """
    Load alert JSON from disk.
    """
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_report(content: str, path: Path) -> None:
    """
    Write the Markdown report to disk.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        f.write(content)


def main() -> None:
    """
    Run the alert automation workflow.
    """
    load_dotenv()

    base_dir = Path(__file__).resolve().parent.parent
    alert_path = base_dir / "alert_input.json"
    output_path = base_dir / "output" / "investigation_report.md"

    alert = load_alert(alert_path)

    ip_data = enrich_ip(alert.get("destination_ip"))
    hash_data = enrich_hash(alert.get("file_hash"))
    severity = calculate_severity(ip_data, hash_data)
    report_md = generate_report(alert, ip_data, hash_data, severity)

    write_report(report_md, output_path)
    print(f"Report generated at {output_path}")


if __name__ == "__main__":
    main()
