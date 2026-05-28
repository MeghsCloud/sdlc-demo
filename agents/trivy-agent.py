"""
Trivy Agent - Analyzes Trivy scan results and makes go/no-go decisions.

Usage in CI:
  python agents/trivy-agent.py [trivy-container.json] [trivy-fs.json] [trivy-deps.json]

Decision logic:
  - BLOCK: Any CRITICAL vulnerability found
  - WARN: HIGH vulnerabilities exceed threshold (default: 5)
  - PASS: No critical issues
"""

import json
import sys


def load_json(file_path):
    """Load a JSON file safely."""
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def analyze_trivy_report(report, source_name):
    """Analyze a single Trivy JSON report."""
    findings = {
        "source": source_name,
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
    }

    results = report.get("Results", [])
    for result in results:
        target = result.get("Target", "unknown")
        vulns = result.get("Vulnerabilities") or []

        for vuln in vulns:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            entry = {
                "id": vuln.get("VulnerabilityID", "N/A"),
                "package": vuln.get("PkgName", "N/A"),
                "installed_version": vuln.get("InstalledVersion", "N/A"),
                "fixed_version": vuln.get("FixedVersion", "N/A"),
                "target": target,
                "title": vuln.get("Title", ""),
            }

            if severity == "CRITICAL":
                findings["critical"].append(entry)
            elif severity == "HIGH":
                findings["high"].append(entry)
            elif severity == "MEDIUM":
                findings["medium"].append(entry)
            else:
                findings["low"].append(entry)

    return findings


def make_decision(all_findings, high_threshold=5):
    """Make a go/no-go decision based on all scan findings."""
    total_critical = 0
    total_high = 0
    total_medium = 0
    total_low = 0
    details = []

    for finding in all_findings:
        total_critical += len(finding["critical"])
        total_high += len(finding["high"])
        total_medium += len(finding["medium"])
        total_low += len(finding["low"])
        details.append({
            "source": finding["source"],
            "critical": len(finding["critical"]),
            "high": len(finding["high"]),
            "medium": len(finding["medium"]),
            "low": len(finding["low"]),
        })

    # Decision logic
    if total_critical > 0:
        decision = "BLOCK"
        action = f"Fix {total_critical} CRITICAL vulnerabilities before proceeding"
        # List the critical CVEs for visibility
        critical_cves = []
        for finding in all_findings:
            for vuln in finding["critical"]:
                critical_cves.append(f"{vuln['id']} ({vuln['package']})")
    elif total_high > high_threshold:
        decision = "WARN"
        action = f"{total_high} HIGH vulnerabilities exceed threshold ({high_threshold}). Review required."
        critical_cves = []
    else:
        decision = "PASS"
        action = "Vulnerability scan passed"
        critical_cves = []

    return {
        "decision": decision,
        "action": action,
        "summary": {
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
            "total": total_critical + total_high + total_medium + total_low,
        },
        "critical_cves": critical_cves[:10],  # Cap at 10 for readability
        "scan_details": details,
    }


if __name__ == "__main__":
    # Accept multiple Trivy report files
    report_files = sys.argv[1:] if len(sys.argv) > 1 else ["trivy-container.json"]

    all_findings = []
    for report_file in report_files:
        report = load_json(report_file)
        if report:
            findings = analyze_trivy_report(report, report_file)
            all_findings.append(findings)
        else:
            print(f"Warning: Could not load {report_file}")

    result = make_decision(all_findings)

    print("\n===== TRIVY AGENT =====")
    print(json.dumps(result, indent=2))

    # Exit non-zero if blocked
    if result["decision"] == "BLOCK":
        sys.exit(1)
