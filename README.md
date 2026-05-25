# Threat Intelligence IOC Enrichment Tool

A Python-based threat intelligence enrichment tool that uses the VirusTotal API to analyse and classify Indicators of Compromise (IOCs), including IP addresses, domains, URLs, and file hashes.

The tool supports IOC type detection, bulk IOC processing, threat scoring, JSON/CSV report generation, and analyst-style recommendations based on malicious and suspicious verdict counts from VirusTotal security vendors. It is designed as a practical blue-team utility for SOC triage, threat intelligence enrichment, malware investigation support, and incident response workflows.

---

## Project Summary

**Project:** Threat Intelligence IOC Enrichment Tool  
**Tools:** Python, VirusTotal API  
**Focus Area:** Threat Intelligence, IOC Analysis, SOC Automation, Malware Analysis Support  
**Status:** Working portfolio project  

Developed a Python-based threat intelligence enrichment tool using the VirusTotal API to analyse IPs, domains, URLs, and file hashes. Implemented support for 4 IOC types, bulk IOC processing, threat scoring, and JSON/CSV report generation with analyst-style recommendations based on malicious verdict counts from 60+ security vendors. Validated the tool using known malicious malware hashes to generate structured threat intelligence reports for SOC workflows.

---

## Key Features

- Analyses multiple IOC types:
  - IP addresses
  - Domains
  - URLs
  - File hashes: MD5, SHA1, SHA256
- Uses VirusTotal API v3 for enrichment
- Detects IOC type automatically
- Supports single IOC analysis
- Supports bulk IOC processing from a text file
- Assigns threat levels based on malicious and suspicious verdict counts
- Generates analyst-style recommendations
- Exports structured reports in JSON and CSV formats
- Handles common API conditions, including:
  - IOC not found
  - API rate limiting
  - API request errors
- Keeps the VirusTotal API key outside the source code using environment variables

---

## Technologies Used

- Python 3
- VirusTotal API v3
- requests
- argparse
- csv
- json
- base64
- regex

---

## Repository Structure

```text
ioc-threat-intel-enricher/
|
├── threat_intel_enricher.py
├── requirements.txt
├── iocs.txt
├── threat_intel_report.json
├── threat_intel_report.csv
├── README.md
└── screenshots/
    ├── terminal_output.png
    └── sample_report.png
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/ioc-threat-intel-enricher.git
cd ioc-threat-intel-enricher
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

## requirements.txt

```text
requests
```

---

## VirusTotal API Setup

This tool requires a VirusTotal API key.

1. Create or log in to a VirusTotal account.
2. Go to your API key page.
3. Copy your API key.
4. Set it as an environment variable.

### Windows PowerShell

```powershell
$env:VT_API_KEY="YOUR_API_KEY_HERE"
```

### Linux/macOS

```bash
export VT_API_KEY="YOUR_API_KEY_HERE"
```

The API key should not be hardcoded into the Python script or uploaded to GitHub.

---

## Usage

### Analyse a Single IOC

```bash
python threat_intel_enricher.py -i 8.8.8.8
```

### Analyse a Domain

```bash
python threat_intel_enricher.py -i google.com
```

### Analyse a URL

```bash
python threat_intel_enricher.py -i https://example.com
```

### Analyse a File Hash

```bash
python threat_intel_enricher.py -i 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

---

## Bulk IOC Processing

Create a file named `iocs.txt` with one IOC per line:

```text
8.8.8.8
google.com
https://example.com
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
```

Run the tool in bulk mode:

```bash
python threat_intel_enricher.py -f iocs.txt
```

---

## Output Files

The tool generates two structured output files by default:

```text
threat_intel_report.json
threat_intel_report.csv
```

You can also specify custom output names:

```bash
python threat_intel_enricher.py -f iocs.txt --json results.json --csv results.csv
```

---

## Example Terminal Output

```text
Threat Intelligence Report
==================================================
ioc: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
ioc_type: file_hash
status: success
malicious: 66
suspicious: 0
harmless: 0
undetected: 2
reputation: 3742
threat_level: HIGH
recommendation: Block immediately and investigate related activity.
generated_at: 2026-05-22T17:06:58.451962
```

---

## Threat Scoring Logic

The tool assigns a threat level based on VirusTotal malicious and suspicious verdict counts.

| Threat Level | Logic | Analyst Meaning |
|---|---|---|
| HIGH | 20+ malicious detections | Strong malicious consensus. Block and investigate. |
| MEDIUM | 5+ malicious or suspicious detections | Potential threat. Review logs and related activity. |
| LOW | 1-4 malicious/suspicious detections | Weak signal. Manual review recommended. |
| INFO | No detections but negative reputation | No confirmed detection, but context should be reviewed. |
| CLEAN/UNKNOWN | No malicious/suspicious detections | No immediate malicious indicator found. |

---

## Analyst Recommendations

The tool generates practical recommendations based on the IOC risk level, such as:

- Block immediately and investigate related endpoint, network, and user activity.
- Investigate the IOC and check related logs.
- Review manually before taking action.
- Review context before trusting negatively reputed indicators.
- No immediate malicious indicators detected.

These recommendations are intended to support SOC triage and should be validated against internal logs, asset context, and business impact.

---

## SOC Use Cases

This project can support entry-level SOC and blue-team workflows such as:

- IOC triage
- Malware hash reputation checking
- Threat intelligence enrichment
- Incident response investigations
- Phishing investigation support
- Threat hunting preparation
- Enriching indicators before blocking or escalation
- Generating structured evidence for analyst notes

---

## Security Considerations

- Do not upload your VirusTotal API key to GitHub.
- Use environment variables for secrets.
- Validate results with internal telemetry before taking action.
- Treat third-party reputation data as supporting evidence, not as the only decision point.
- Be aware of API rate limits when running bulk IOC checks.

---

## Limitations

- The tool depends on VirusTotal API availability and rate limits.
- It does not submit new files or detonate malware samples.
- It does not replace full malware analysis or sandboxing.
- Vendor detection counts can change over time.
- A clean result does not guarantee an IOC is safe.

---

## Future Improvements

- ANY.RUN sandbox integration
- AbuseIPDB integration
- MITRE ATT&CK mapping
- HTML/PDF report generation
- YARA rule support
- Email alerting
- SIEM integration
- IOC allowlist and blocklist comparison
- Confidence scoring based on IOC type and vendor consensus
