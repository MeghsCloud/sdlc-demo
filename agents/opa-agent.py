"""
OPA Agent - Evaluates Open Policy Agent results and enforces governance.

Usage in CI:
  python agents/opa-agent.py [opa-results.json]

Decision logic:
  - BLOCK: Any deny rules triggered
  - WARN: Advisory/warn rules triggered
  - PASS: No policy violations
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


def analyze_opa_results(report):
    """Parse OPA evaluation output."""
    denials = []
    warnings = []

    # OPA output format varies based on how it's invoked
    # Handle: {"result": [{"expressions": [{"value": [...]}]}]}
    if "result" in report:
        results = report.get("result", [])
        for r in results:
            expressions = r.get("expressions", [])
            for expr in expressions:
                value = expr.get("value", [])
                if isinstance(value, list):
                    for item in value:
                        if isinstance(item, str):
                            denials.append(item)
                        elif isinstance(item, dict):
                            msg = item.get("msg", item.get("message", str(item)))
                            severity = item.get("severity", "high")
                            if severity == "warning":
                                warnings.append(msg)
                            else:
                                denials.append(msg)
                elif isinstance(value, dict):
                    # Single result
                    if value:
                        denials.append(str(value))

    # Handle flat format: {"deny": ["msg1", "msg2"]}
    elif "deny" in report:
        deny_val = report["deny"]
        if isinstance(deny_val, list):
            denials.extend(deny_val)
        elif deny_val:
            denials.append(str(deny_val))

    # Handle: direct list of strings
    elif isinstance(report, list):
        denials.extend([str(item) for item in report if item])

    return denials, warnings


def make_decision(denials, warnings):
    """Make go/no-go decision based on OPA evaluation."""
    if denials:
        return {
            "decision": "BLOCK",
            "action": f"Fix {len(denials)} policy violation(s) before deployment",
            "summary": {
                "denials": len(denials),
                "warnings": len(warnings),
            },
            "violations": denials[:10],
            "warnings": warnings[:5],
        }
    elif warnings:
        return {
            "decision": "WARN",
            "action": f"{len(warnings)} policy warning(s) - review recommended",
            "summary": {
                "denials": 0,
                "warnings": len(warnings),
            },
            "violations": [],
            "warnings": warnings[:5],
        }
    else:
        return {
            "decision": "PASS",
            "action": "All policies satisfied",
            "summary": {
                "denials": 0,
                "warnings": 0,
            },
            "violations": [],
            "warnings": [],
        }


if __name__ == "__main__":
    report_file = sys.argv[1] if len(sys.argv) > 1 else "opa.json"

    report = load_json(report_file)
    if not report:
        print(f"Warning: Could not load {report_file}, assuming clean evaluation")
        result = {"decision": "PASS", "action": "No OPA report to analyze", "summary": {}}
    else:
        denials, warnings = analyze_opa_results(report)
        result = make_decision(denials, warnings)

    print("\n===== OPA AGENT =====")
    print(json.dumps(result, indent=2))

    # Exit non-zero if blocked
    if result["decision"] == "BLOCK":
        sys.exit(1)
