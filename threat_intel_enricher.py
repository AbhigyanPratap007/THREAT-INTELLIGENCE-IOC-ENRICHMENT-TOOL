import os, re, csv, json, base64, argparse, requests
from datetime import datetime

API_KEY = os.getenv("VT_API_KEY")
if not API_KEY:
    raise SystemExit("Set VT_API_KEY first.")

HEADERS = {"x-apikey": API_KEY}


def ioc_type(ioc):
    if re.fullmatch(r"[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}", ioc):
        return "file_hash"
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ioc):
        return "ip"
    if ioc.startswith(("http://", "https://")):
        return "url"
    return "domain"


def vt_url(ioc, typ):
    paths = {
        "file_hash": f"files/{ioc}",
        "ip": f"ip_addresses/{ioc}",
        "domain": f"domains/{ioc}",
        "url": f"urls/{base64.urlsafe_b64encode(ioc.encode()).decode().rstrip('=')}"
    }
    return f"https://www.virustotal.com/api/v3/{paths[typ]}"


def verdict(mal, sus, rep):
    if mal >= 20:
        return "HIGH", "Block immediately and investigate related activity."
    if mal >= 5 or sus >= 5:
        return "MEDIUM", "Investigate the IOC and check related logs."
    if mal > 0 or sus > 0:
        return "LOW", "Review manually before taking action."
    if isinstance(rep, int) and rep < 0:
        return "INFO", "Negative reputation. Review context before trusting."
    return "CLEAN/UNKNOWN", "No immediate malicious indicators detected."


def empty_report(ioc, typ, status, level, rec):
    return {
        "ioc": ioc,
        "ioc_type": typ,
        "status": status,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "reputation": "N/A",
        "threat_level": level,
        "recommendation": rec,
        "generated_at": datetime.now().isoformat()
    }


def enrich(ioc):
    ioc = ioc.strip()
    typ = ioc_type(ioc)

    try:
        r = requests.get(vt_url(ioc, typ), headers=HEADERS, timeout=20)

        if r.status_code == 404:
            return empty_report(ioc, typ, "not_found", "UNKNOWN", "IOC was not found in VirusTotal.")
        if r.status_code == 429:
            return empty_report(ioc, typ, "rate_limited", "UNKNOWN", "VirusTotal API rate limit reached.")

        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})

        mal, sus = stats.get("malicious", 0), stats.get("suspicious", 0)
        rep = attrs.get("reputation", "N/A")
        level, rec = verdict(mal, sus, rep)

        return {
            "ioc": ioc,
            "ioc_type": typ,
            "status": "success",
            "malicious": mal,
            "suspicious": sus,
            "harmless": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation": rep,
            "threat_level": level,
            "recommendation": rec,
            "generated_at": datetime.now().isoformat()
        }

    except requests.RequestException as e:
        return empty_report(ioc, typ, "error", "UNKNOWN", f"API request failed: {e}")


def save_reports(reports, json_file, csv_file):
    with open(json_file, "w", encoding="utf-8") as f:
        json.dump(reports, f, indent=4)

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=reports[0].keys())
        writer.writeheader()
        writer.writerows(reports)


def load_iocs(path):
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def show(report):
    print("\nThreat Intelligence Report")
    print("=" * 50)
    for k, v in report.items():
        print(f"{k}: {v}")


def main():
    p = argparse.ArgumentParser(description="VirusTotal IOC Threat Intel Enricher")
    p.add_argument("-i", "--ioc", help="Single IOC to analyse")
    p.add_argument("-f", "--file", help="Text file with one IOC per line")
    p.add_argument("--json", default="threat_intel_report.json")
    p.add_argument("--csv", default="threat_intel_report.csv")
    args = p.parse_args()

    iocs = [args.ioc] if args.ioc else load_iocs(args.file) if args.file else [input("Enter IOC: ")]
    reports = [enrich(ioc) for ioc in iocs]

    for report in reports:
        show(report)

    save_reports(reports, args.json, args.csv)
    print(f"\nSaved: {args.json} and {args.csv}")


if __name__ == "__main__":
    main()
