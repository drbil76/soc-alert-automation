# SOC Investigation Report

**Generated:** (example) 2026-02-04T00:00:00Z
**Alert Name:** Suspicious File Execution
**Source:** EDR
**Host:** host-23.corp.example.com
**User:** jdoe

## Indicator Enrichment

### Destination IP
- Address: 8.8.8.8
- Country: unknown
- ISP: unknown
- Abuse Confidence Score: -1

### File Hash
- Hash: 44d88612fea8a8f36de82e1278abb02f
- Malicious Detections: -1
- Suspicious Detections: -1
- Undetected: -1

## Severity Assessment
- Calculated Severity: **Medium**

## Analyst Notes
- If severity is High: isolate host, block IP, and submit sample to sandbox.
- If severity is Medium: monitor connections, review EDR timeline, and consider containment if activity persists.
- If severity is Low: document findings and continue monitoring.

## Appendix
- Enrichment errors (if any):
  - IP enrichment error: none
  - Hash enrichment error: none
