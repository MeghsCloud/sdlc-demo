"""
Peer Review Agent - Automated code review for pull requests.

Usage in CI:
  python agents/peer-review-agent.py [--diff-file <path>]

What it checks:
  - Code complexity (large files, long functions)
  - Security anti-patterns (hardcoded secrets, eval, exec)
  - Best practices (missing error handling, TODO/FIXME counts)
  - Dockerfile best practices
  - Kubernetes manifest hygiene
"""

import json
import os
import re
import subprocess
import sys


def run_cmd(cmd):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1


def get_changed_files(diff_file=None):
    """Get list of changed files from git diff or a diff file."""
    if diff_file and os.path.exists(diff_file):
        with open(diff_file, "r") as f:
            content = f.read()
        files = re.findall(r"^\+\+\+ b/(.+)$", content, re.MULTILINE)
        return files

    output, rc = run_cmd("git diff --name-only HEAD~1 HEAD")
    if rc == 0 and output:
        return output.split("\n")
    return []


def check_security_patterns(file_path):
    """Scan a file for security anti-patterns."""
    issues = []
    if not os.path.exists(file_path):
        return issues

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return issues

    patterns = [
        (r"(password|secret|api_key|token)\s*=\s*['\"][^'\"]+['\"]", "Possible hardcoded secret"),
        (r"\beval\s*\(", "Use of eval() - potential code injection"),
        (r"\bexec\s*\(", "Use of exec() - potential code injection"),
        (r"subprocess\.call\(.+shell\s*=\s*True", "Shell injection risk with subprocess"),
        (r"# ?TODO|# ?FIXME|# ?HACK", "Unresolved TODO/FIXME/HACK"),
    ]

    for i, line in enumerate(lines, 1):
        for pattern, message in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    "file": file_path,
                    "line": i,
                    "severity": "HIGH" if "secret" in message.lower() or "injection" in message.lower() else "LOW",
                    "message": message,
                })

    return issues


def check_complexity(file_path):
    """Check for overly complex files."""
    issues = []
    if not os.path.exists(file_path):
        return issues

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return issues

    # File too long
    if len(lines) > 500:
        issues.append({
            "file": file_path,
            "severity": "MEDIUM",
            "message": f"File has {len(lines)} lines - consider splitting",
        })

    # Long functions (Python)
    if file_path.endswith(".py"):
        func_start = None
        func_name = ""
        for i, line in enumerate(lines, 1):
            match = re.match(r"^(def|async def)\s+(\w+)", line)
            if match:
                if func_start and (i - func_start) > 50:
                    issues.append({
                        "file": file_path,
                        "line": func_start,
                        "severity": "MEDIUM",
                        "message": f"Function '{func_name}' is {i - func_start} lines - consider refactoring",
                    })
                func_start = i
                func_name = match.group(2)

    return issues


def check_dockerfile(file_path):
    """Check Dockerfile best practices."""
    issues = []
    if not os.path.exists(file_path):
        return issues

    with open(file_path, "r") as f:
        content = f.read()
        lines = content.split("\n")

    # Running as root
    if "USER" not in content:
        issues.append({
            "file": file_path,
            "severity": "MEDIUM",
            "message": "No USER instruction - container runs as root",
        })

    # Using latest tag
    for i, line in enumerate(lines, 1):
        if re.match(r"^FROM\s+\S+:latest", line):
            issues.append({
                "file": file_path,
                "line": i,
                "severity": "MEDIUM",
                "message": "Using :latest tag - pin to specific version",
            })

    # No HEALTHCHECK
    if "HEALTHCHECK" not in content:
        issues.append({
            "file": file_path,
            "severity": "LOW",
            "message": "No HEALTHCHECK instruction",
        })

    return issues


def check_k8s_manifest(file_path):
    """Check Kubernetes manifest best practices."""
    issues = []
    if not os.path.exists(file_path):
        return issues

    with open(file_path, "r") as f:
        content = f.read()

    if "resources:" not in content:
        issues.append({
            "file": file_path,
            "severity": "HIGH",
            "message": "No resource limits/requests defined",
        })

    if "livenessProbe:" not in content and "readinessProbe:" not in content:
        issues.append({
            "file": file_path,
            "severity": "MEDIUM",
            "message": "No health probes (liveness/readiness) defined",
        })

    if "securityContext:" not in content:
        issues.append({
            "file": file_path,
            "severity": "MEDIUM",
            "message": "No securityContext defined",
        })

    return issues


def review_files(files):
    """Run all review checks on changed files."""
    all_issues = []

    for file_path in files:
        if not os.path.exists(file_path):
            continue

        # Security patterns for all text files
        all_issues.extend(check_security_patterns(file_path))

        # Complexity for code files
        if file_path.endswith((".py", ".ts", ".js", ".go")):
            all_issues.extend(check_complexity(file_path))

        # Dockerfile checks
        if "Dockerfile" in file_path:
            all_issues.extend(check_dockerfile(file_path))

        # K8s manifest checks
        if file_path.endswith((".yml", ".yaml")) and ("k8s" in file_path or "deployment" in file_path):
            all_issues.extend(check_k8s_manifest(file_path))

    return all_issues


def make_decision(issues):
    """Decide review outcome based on findings."""
    high_count = sum(1 for i in issues if i.get("severity") == "HIGH")
    medium_count = sum(1 for i in issues if i.get("severity") == "MEDIUM")

    if high_count >= 3:
        decision = "REQUEST_CHANGES"
        summary = f"{high_count} high-severity issues must be fixed"
    elif high_count >= 1:
        decision = "REQUEST_CHANGES"
        summary = f"{high_count} high-severity issue(s) found"
    elif medium_count >= 5:
        decision = "COMMENT"
        summary = f"{medium_count} medium-severity suggestions"
    else:
        decision = "APPROVE"
        summary = "Code looks good"

    return {
        "decision": decision,
        "summary": summary,
        "total_issues": len(issues),
        "high": high_count,
        "medium": medium_count,
        "low": sum(1 for i in issues if i.get("severity") == "LOW"),
        "issues": issues[:20],  # Cap output at 20 issues
    }


if __name__ == "__main__":
    diff_file = None
    if "--diff-file" in sys.argv:
        idx = sys.argv.index("--diff-file")
        if idx + 1 < len(sys.argv):
            diff_file = sys.argv[idx + 1]

    changed_files = get_changed_files(diff_file)

    if not changed_files:
        print("No changed files detected.")
        result = {"decision": "APPROVE", "summary": "No files to review", "total_issues": 0}
    else:
        print(f"Reviewing {len(changed_files)} file(s)...")
        issues = review_files(changed_files)
        result = make_decision(issues)

    print("\n===== PEER REVIEW AGENT =====")
    print(json.dumps(result, indent=2))

    # Exit non-zero if changes requested
    if result["decision"] == "REQUEST_CHANGES":
        sys.exit(1)
