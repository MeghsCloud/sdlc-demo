"""
Pre-commit Agent - Runs locally before code is pushed to catch issues early.

Usage:
  python agents/precommit-agent.py [--fix]

Checks:
  - Secrets detection (API keys, tokens, passwords in code)
  - Large file detection (>1MB files being committed)
  - Syntax validation (Python, YAML, JSON)
  - Merge conflict markers
  - Debug statements left in code

Install as git hook:
  cp agents/precommit-agent.py .git/hooks/pre-commit
  chmod +x .git/hooks/pre-commit
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


def get_staged_files():
    """Get list of files staged for commit."""
    output, rc = run_cmd("git diff --cached --name-only --diff-filter=ACM")
    if rc == 0 and output:
        return output.split("\n")
    return []


def check_secrets(file_path):
    """Detect potential secrets in staged files."""
    issues = []
    if not os.path.exists(file_path):
        return issues

    secret_patterns = [
        (r"(?i)(aws_access_key_id|aws_secret_access_key)\s*=\s*['\"]?[A-Za-z0-9/+=]{20,}", "AWS credential"),
        (r"(?i)(github_token|gh_token|ghp_)[A-Za-z0-9_]{20,}", "GitHub token"),
        (r"(?i)(password|passwd|pwd)\s*=\s*['\"][^'\"]{8,}['\"]", "Hardcoded password"),
        (r"(?i)(api_key|apikey|api_secret)\s*=\s*['\"][^'\"]{10,}['\"]", "API key"),
        (r"(?i)(secret_key|private_key)\s*=\s*['\"][^'\"]{10,}['\"]", "Secret/private key"),
        (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private key file"),
    ]

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return issues

    for i, line in enumerate(lines, 1):
        for pattern, desc in secret_patterns:
            if re.search(pattern, line):
                issues.append({
                    "type": "SECRET",
                    "severity": "CRITICAL",
                    "file": file_path,
                    "line": i,
                    "message": f"Potential {desc} detected",
                })

    return issues


def check_large_files(file_path, max_size_mb=1):
    """Detect files that are too large."""
    issues = []
    if os.path.exists(file_path):
        size = os.path.getsize(file_path)
        if size > max_size_mb * 1024 * 1024:
            issues.append({
                "type": "LARGE_FILE",
                "severity": "HIGH",
                "file": file_path,
                "message": f"File is {size / (1024*1024):.1f}MB (max: {max_size_mb}MB)",
            })
    return issues


def check_debug_statements(file_path):
    """Detect debug statements left in code."""
    issues = []
    if not os.path.exists(file_path):
        return issues

    debug_patterns = {
        ".py": [r"^\s*(import pdb|pdb\.set_trace|breakpoint\(\))", r"^\s*print\(.*debug", r"^\s*import ipdb"],
        ".js": [r"^\s*console\.log\(", r"^\s*debugger"],
        ".ts": [r"^\s*console\.log\(", r"^\s*debugger"],
    }

    ext = os.path.splitext(file_path)[1]
    patterns = debug_patterns.get(ext, [])
    if not patterns:
        return issues

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return issues

    for i, line in enumerate(lines, 1):
        for pattern in patterns:
            if re.search(pattern, line, re.IGNORECASE):
                issues.append({
                    "type": "DEBUG",
                    "severity": "LOW",
                    "file": file_path,
                    "line": i,
                    "message": f"Debug statement: {line.strip()[:60]}",
                })

    return issues


def check_merge_conflicts(file_path):
    """Detect unresolved merge conflict markers."""
    issues = []
    if not os.path.exists(file_path):
        return issues

    try:
        with open(file_path, "r", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return issues

    for i, line in enumerate(lines, 1):
        if re.match(r"^(<{7}|>{7}|={7})\s", line):
            issues.append({
                "type": "MERGE_CONFLICT",
                "severity": "CRITICAL",
                "file": file_path,
                "line": i,
                "message": "Unresolved merge conflict marker",
            })

    return issues


def check_syntax(file_path):
    """Validate syntax for known file types."""
    issues = []
    ext = os.path.splitext(file_path)[1]

    if ext == ".py":
        output, rc = run_cmd(f"python3 -c \"import ast; ast.parse(open('{file_path}').read())\"")
        if rc != 0:
            issues.append({
                "type": "SYNTAX",
                "severity": "HIGH",
                "file": file_path,
                "message": f"Python syntax error: {output[:100]}",
            })

    elif ext in (".yml", ".yaml"):
        try:
            import yaml
            with open(file_path, "r") as f:
                yaml.safe_load(f)
        except Exception as e:
            issues.append({
                "type": "SYNTAX",
                "severity": "HIGH",
                "file": file_path,
                "message": f"YAML syntax error: {str(e)[:100]}",
            })

    elif ext == ".json":
        try:
            with open(file_path, "r") as f:
                json.load(f)
        except Exception as e:
            issues.append({
                "type": "SYNTAX",
                "severity": "HIGH",
                "file": file_path,
                "message": f"JSON syntax error: {str(e)[:100]}",
            })

    return issues


def run_all_checks(files):
    """Run all pre-commit checks on staged files."""
    all_issues = []

    for file_path in files:
        all_issues.extend(check_secrets(file_path))
        all_issues.extend(check_large_files(file_path))
        all_issues.extend(check_debug_statements(file_path))
        all_issues.extend(check_merge_conflicts(file_path))
        all_issues.extend(check_syntax(file_path))

    return all_issues


def make_decision(issues):
    """Decide whether to allow the commit."""
    critical = [i for i in issues if i["severity"] == "CRITICAL"]
    high = [i for i in issues if i["severity"] == "HIGH"]

    if critical:
        return {
            "decision": "BLOCK",
            "action": "Commit blocked - fix critical issues",
            "summary": {
                "critical": len(critical),
                "high": len(high),
                "low": len([i for i in issues if i["severity"] == "LOW"]),
                "total": len(issues),
            },
            "issues": issues[:15],
        }
    elif high:
        return {
            "decision": "WARN",
            "action": "Commit allowed with warnings - review high-severity issues",
            "summary": {
                "critical": 0,
                "high": len(high),
                "low": len([i for i in issues if i["severity"] == "LOW"]),
                "total": len(issues),
            },
            "issues": issues[:15],
        }
    else:
        return {
            "decision": "PASS",
            "action": "All pre-commit checks passed",
            "summary": {"total": len(issues)},
            "issues": issues[:5],
        }


if __name__ == "__main__":
    staged_files = get_staged_files()

    if not staged_files:
        # If not in git context, scan all Python/YAML files
        staged_files = []
        for root, dirs, files in os.walk("."):
            dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "__pycache__", "cdk.out")]
            for f in files:
                if f.endswith((".py", ".yml", ".yaml", ".json", ".ts", ".js")):
                    staged_files.append(os.path.join(root, f))

    print(f"Pre-commit agent scanning {len(staged_files)} file(s)...")
    issues = run_all_checks(staged_files)
    result = make_decision(issues)

    print("\n===== PRE-COMMIT AGENT =====")
    print(json.dumps(result, indent=2))

    if result["decision"] == "BLOCK":
        sys.exit(1)
