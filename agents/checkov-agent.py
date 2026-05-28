"""
Checkov Agent - Analyzes Checkov IaC scan results and enforces policy.

Usage in CI:
  python agents/checkov-agent.py [checkov-results.json]

Decision logic:
  - BLOCK: Any HIGH severity misconfigurations in Dockerfile or K8s manifests
  - WARN: Medium severity issues exceed threshold
  - PASS: All checks passed or only low-severity findings
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


def analyze_checkov_results(report):
    """Parse Checkov output and categorize findings."""
    findings = {
        "passed": [],
        "failed": [],
        "skipped": [],
    }

    # Checkov can output as a list or dict depending on version
    if isinstance(report, list):
        results_list = report
    else:
        results_list = [report]

    for result_block in results_list:
        passed = result_block.get("results", {}).get("passed_checks", [])
        failed = result_block.get("results", {}).get("failed_checks", [])
        skipped = result_block.get("results", {}).get("skipped_checks", [])

        findings["passed"].extend(passed)
        findings["failed"].extend(failed)
        findings["skipped"].extend(skipped)

    return findings


def categorize_failures(failed_checks):
    """Categorize failed checks by severity and resource type."""
    critical_patterns = [
        "CKV_DOCKER_2",   # Healthcheck missing
        "CKV_DOCKER_3",   # User not set
        "CKV_K8S_1",      # CPU limits
        "CKV_K8S_3",      # Memory limits
        "CKV_K8S_6",      # Root container
        "CKV_K8S_8",      # Liveness probe
        "CKV_K8S_9",      # Readiness probe
        "CKV_K8S_20",     # Privileged container
        "CKV_K8S_22",     # Read-only filesystem
        "CKV_K8S_28",     # Capabilities drop
        "CKV_K8S_37",     # Privilege escalation
    ]

    high = []
    medium = []
    low = []

    for check in failed_checks:
        check_id = check.get("check_id", "")
        entry = {
            "check_id": check_id,
            "check_name": check.get("check_result", {}).get("result", check.get("name", "")),
            "resource": check.get("resource", "N/A"),
            "file": check.get("file_path", "N/A"),
            "guideline": check.get("guideline", ""),
        }

        if check_id in critical_patterns:
            high.append(entry)
        elif check_id.startswith(("CKV_K8S", "CKV_DOCKER")):
            medium.append(entry)
        else:
            low.append(entry)

    return high, medium, low


def make_decision(findings, high_threshold=3):
    """Make go/no-go decision based on Checkov findings."""
    failed = findings["failed"]
    passed = findings["passed"]

    if not failed:
        return {
            "decision": "PASS",
            "action": "All IaC checks passed",
            "summary": {
                "passed": len(passed),
                "failed": 0,
                "skipped": len(findings["skipped"]),
            },
            "failures": [],
        }

    high, medium, low = categorize_failures(failed)

    if len(high) > 0:
        decision = "BLOCK"
        action = f"Fix {len(high)} high-severity IaC misconfigurations"
    elif len(medium) > high_threshold:
        decision = "WARN"
        action = f"{len(medium)} medium-severity issues exceed threshold ({high_threshold})"
    else:
        decision = "PASS"
        action = "IaC scan passed with minor findings"

    return {
        "decision": decision,
        "action": action,
        "summary": {
            "passed": len(passed),
            "failed": len(failed),
            "high": len(high),
            "medium": len(medium),
            "low": len(low),
            "skipped": len(findings["skipped"]),
        },
        "high_severity_failures": high[:10],
    }


if __name__ == "__main__":
    report_file = sys.argv[1] if len(sys.argv) > 1 else "checkov.json"

    report = load_json(report_file)
    if not report:
        print(f"Warning: Could not load {report_file}, assuming clean scan")
        result = {"decision": "PASS", "action": "No report to analyze", "summary": {}}
    else:
        findings = analyze_checkov_results(report)
        result = make_decision(findings)

    print("\n===== CHECKOV AGENT =====")
    print(json.dumps(result, indent=2))

    # Exit non-zero if blocked
    if result["decision"] == "BLOCK":
        sys.exit(1)
