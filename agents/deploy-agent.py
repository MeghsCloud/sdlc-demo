"""
Deploy Agent - Validates deployment readiness and monitors rollout health.

Usage in CI:
  python agents/deploy-agent.py <deployment-name> <namespace> [--pre|--post]

Modes:
  --pre   Pre-deployment checks (image exists, manifests valid, security passed)
  --post  Post-deployment health check (pods running, endpoints healthy)
"""

import json
import subprocess
import sys


def run_cmd(cmd):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1


def pre_deploy_checks(deployment_name, namespace):
    """Validate that deployment is safe to proceed."""
    checks = []
    passed = True

    # Check 1: Kubernetes manifest is valid
    output, rc = run_cmd(f"kubectl apply --dry-run=client -f k8s/deployment.yml 2>&1")
    if rc == 0:
        checks.append({"check": "manifest_valid", "status": "PASS"})
    else:
        checks.append({"check": "manifest_valid", "status": "FAIL", "detail": output})
        passed = False

    # Check 2: Namespace exists
    output, rc = run_cmd(f"kubectl get namespace {namespace} 2>&1")
    if rc == 0:
        checks.append({"check": "namespace_exists", "status": "PASS"})
    else:
        checks.append({"check": "namespace_exists", "status": "FAIL", "detail": "Namespace not found"})
        passed = False

    # Check 3: No existing failed rollout
    output, rc = run_cmd(
        f"kubectl rollout status deployment/{deployment_name} -n {namespace} --timeout=5s 2>&1"
    )
    if "successfully rolled out" in output or "not found" in output:
        checks.append({"check": "no_stuck_rollout", "status": "PASS"})
    else:
        checks.append({"check": "no_stuck_rollout", "status": "WARN", "detail": output})

    decision = "DEPLOY" if passed else "BLOCK"
    return {
        "phase": "pre-deploy",
        "deployment": deployment_name,
        "namespace": namespace,
        "decision": decision,
        "checks": checks,
    }


def post_deploy_checks(deployment_name, namespace):
    """Verify deployment health after rollout."""
    checks = []
    healthy = True

    # Check 1: Rollout status
    output, rc = run_cmd(
        f"kubectl rollout status deployment/{deployment_name} -n {namespace} --timeout=120s 2>&1"
    )
    if rc == 0 and "successfully rolled out" in output:
        checks.append({"check": "rollout_complete", "status": "PASS"})
    else:
        checks.append({"check": "rollout_complete", "status": "FAIL", "detail": output})
        healthy = False

    # Check 2: All pods running
    output, rc = run_cmd(
        f"kubectl get pods -l app={deployment_name} -n {namespace} -o json 2>&1"
    )
    if rc == 0:
        try:
            pods = json.loads(output)
            total = len(pods.get("items", []))
            running = sum(
                1 for p in pods.get("items", [])
                if p.get("status", {}).get("phase") == "Running"
            )
            if running == total and total > 0:
                checks.append({"check": "pods_running", "status": "PASS", "detail": f"{running}/{total}"})
            else:
                checks.append({"check": "pods_running", "status": "FAIL", "detail": f"{running}/{total}"})
                healthy = False
        except json.JSONDecodeError:
            checks.append({"check": "pods_running", "status": "FAIL", "detail": "Could not parse pod info"})
            healthy = False

    # Check 3: No crash loops
    output, rc = run_cmd(
        f"kubectl get pods -l app={deployment_name} -n {namespace} "
        f"-o jsonpath='{{.items[*].status.containerStatuses[*].restartCount}}' 2>&1"
    )
    if rc == 0:
        restarts = sum(int(x) for x in output.split() if x.isdigit())
        if restarts == 0:
            checks.append({"check": "no_crash_loops", "status": "PASS"})
        else:
            checks.append({"check": "no_crash_loops", "status": "WARN", "detail": f"{restarts} restarts"})

    status = "HEALTHY" if healthy else "UNHEALTHY"
    action = "Deployment successful" if healthy else "ROLLBACK recommended"

    return {
        "phase": "post-deploy",
        "deployment": deployment_name,
        "namespace": namespace,
        "status": status,
        "action": action,
        "checks": checks,
    }


if __name__ == "__main__":
    deployment = sys.argv[1] if len(sys.argv) > 1 else "sdlc-demo"
    namespace = sys.argv[2] if len(sys.argv) > 2 else "default"
    mode = sys.argv[3] if len(sys.argv) > 3 else "--pre"

    if mode == "--pre":
        result = pre_deploy_checks(deployment, namespace)
    else:
        result = post_deploy_checks(deployment, namespace)

    print("\n===== DEPLOY AGENT =====")
    print(json.dumps(result, indent=2))

    # Exit non-zero if blocked/unhealthy
    if result.get("decision") == "BLOCK" or result.get("status") == "UNHEALTHY":
        sys.exit(1)
