import json

def analyze_results(results):
    findings = results.get("findings", [])

    critical = [f for f in findings if f["severity"] == "CRITICAL"]

    if critical:
        return {
            "status": "BLOCK",
            "reason": "Critical vulnerabilities detected",
            "summary": critical
        }

    return {
        "status": "PASS",
        "reason": "No critical issues",
        "summary": findings
    }


if __name__ == "__main__":
    sample = {
        "findings": [
            {"id": "CVE-123", "severity": "HIGH"},
            {"id": "CVE-999", "severity": "CRITICAL"}
        ]
    }

    print(json.dumps(analyze_results(sample), indent=2))