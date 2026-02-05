# soc-alert-automation

Automation of SOC alerts triage by enriching indicators of compromise (IOCs), computing a reputation-driven severity, and producing a SOC-ready investigation report.

## Features
- IP enrichment via AbuseIPDB (country, ISP, abuse confidence score)
- File hash enrichment via VirusTotal (malicious, suspicious, undetected counts)
- Deterministic severity calculation (Low/Medium/High) combining IP and hash reputation
- Markdown investigation report with alert context, enrichment details, and final assessment
- Environment-based API keys, request timeouts, and defensive response handling

## Why It Matters for SOC
Reduces analyst time on repetitive triage, improves consistency in severity assignments, and produces standardized reports that can be attached to cases or tickets.

## Installation
1. Ensure Python 3.10+ is installed
2. Clone or download this repository
3. Create and activate a virtual environment
4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
5. Copy `.env.example` to `.env` and populate your API keys

## Usage
1. Edit `alert_input.json` with the alert details to triage.
2. Run:
   ```bash
   python -m src.main
   ```
3. The enriched Markdown report is written to `output/investigation_report.md`

## Output
- `output/investigation_report.md` contains:
  - Alert metadata and context
  - IP and hash enrichment summaries
  - Severity justification and recommended next actions
