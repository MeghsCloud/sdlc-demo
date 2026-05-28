import json
import sys

def load_json(file_path):
    try:
        with open(file_path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def calculate_risk(trivy, checkov, opa):
    risk_score = 0
    reasons = []

    # -------------------------
    # Trivy vulnerabilities
    # -------------------------
    vulns = trivy.get("Results", [])
    for v in vulns:
        for vuln in v.get("Vulnerabilities", []) or []:
            severity = vuln.get("Severity", "")

            if severity == "CRITICAL":
                risk_score += 50
                reasons.append("Critical vulnerability found")
            elif severity == "HIGH":
                risk_score += 20
            elif severity == "MEDIUM":
                risk_score += 10

    # -------------------------
    # Checkov failures
    # -------------------------
    failed = checkov.get("results", {}).get("failed_checks", [])
    if failed:
        risk_score += len(failed) * 15
        reasons.append(f"{len(failed)} infrastructure misconfigurations")

    # -------------------------
    # OPA violations
    # -------------------------
    if opa and "deny" in str(opa).lower():
        risk_score += 40
        reasons.append("OPA policy violation detected")

    return risk_score, reasons


def make_decision(score, reasons):
    if score >= 70:
        return {
            "decision": "BLOCK",
            "risk_score": score,
            "reason": reasons,
            "action": "Fix issues before deployment"
        }

    elif score >= 30:
        return {
            "decision": "MANUAL_APPROVAL_REQUIRED",
            "risk_score": score,
            "reason": reasons,
            "action": "Requires human approval"
        }

    else:
        return {
            "decision": "DEPLOY",
            "risk_score": score,
            "reason": reasons,
            "action": "Safe to deploy"
        }


if __name__ == "__main__":

    # Expect file inputs from CI pipeline
    trivy_file = sys.argv[1] if len(sys.argv) > 1 else "trivy.json"
    checkov_file = sys.argv[2] if len(sys.argv) > 2 else "checkov.json"
    opa_file = sys.argv[3] if len(sys.argv) > 3 else "opa.json"

    trivy = load_json(trivy_file)
    checkov = load_json(checkov_file)
    opa = load_json(opa_file)

    score, reasons = calculate_risk(trivy, checkov, opa)
    result = make_decision(score, reasons)

    print("\n===== RELEASE DECISION =====")
    print(json.dumps(result, indent=2))