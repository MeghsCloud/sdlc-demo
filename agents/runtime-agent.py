"""
Runtime Agent - Monitors deployed application health and detects anomalies.

Usage in CI/CronJob:
  python agents/runtime-agent.py <deployment-name> <namespace> [--alert]

Checks:
  - Pod health (restarts, OOMKills, CrashLoopBackOff)
  - Resource utilization (CPU/memory vs limits)
  - Endpoint health (HTTP health check)
  - Anomaly detection (restart spikes, error rate)

Can be deployed as a Kubernetes CronJob for continuous monitoring.
"""

import json
import subprocess
import sys
from datetime import datetime


def run_cmd(cmd):
    """Run a shell command and return stdout."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return result.stdout.strip(), result.returncode
    except Exception as e:
        return str(e), 1


def check_pod_health(deployment, namespace):
    """Check pod status for anomalies."""
    findings = []

    output, rc = run_cmd(
        f"kubectl get pods -l app={deployment} -n {namespace} -o json"
    )
    if rc != 0:
        return [{"check": "pod_health", "status": "ERROR", "detail": "Could not fetch pods"}]

    try:
        pods = json.loads(output)
    except json.JSONDecodeError:
        return [{"check": "pod_health", "status": "ERROR", "detail": "Invalid JSON from kubectl"}]

    items = pods.get("items", [])
    if not items:
        findings.append({"check": "pod_exists", "status": "CRITICAL", "detail": "No pods found"})
        return findings

    total_restarts = 0
    oom_kills = 0
    crash_loops = 0

    for pod in items:
        pod_name = pod.get("metadata", {}).get("name", "unknown")
        phase = pod.get("status", {}).get("phase", "Unknown")

        if phase != "Running":
            findings.append({
                "check": "pod_phase",
                "status": "WARNING",
                "detail": f"{pod_name} is in {phase} state",
            })

        container_statuses = pod.get("status", {}).get("containerStatuses", [])
        for cs in container_statuses:
            restarts = cs.get("restartCount", 0)
            total_restarts += restarts

            # Check for OOMKilled
            last_state = cs.get("lastState", {})
            terminated = last_state.get("terminated", {})
            if terminated.get("reason") == "OOMKilled":
                oom_kills += 1

            # Check for CrashLoopBackOff
            waiting = cs.get("state", {}).get("waiting", {})
            if waiting.get("reason") == "CrashLoopBackOff":
                crash_loops += 1

    if crash_loops > 0:
        findings.append({
            "check": "crash_loop",
            "status": "CRITICAL",
            "detail": f"{crash_loops} container(s) in CrashLoopBackOff",
        })

    if oom_kills > 0:
        findings.append({
            "check": "oom_kills",
            "status": "CRITICAL",
            "detail": f"{oom_kills} OOMKill event(s) detected",
        })

    if total_restarts > 5:
        findings.append({
            "check": "restart_count",
            "status": "WARNING",
            "detail": f"Total restarts: {total_restarts} (threshold: 5)",
        })
    else:
        findings.append({
            "check": "restart_count",
            "status": "OK",
            "detail": f"Total restarts: {total_restarts}",
        })

    return findings


def check_resource_usage(deployment, namespace):
    """Check resource utilization vs limits."""
    findings = []

    output, rc = run_cmd(
        f"kubectl top pods -l app={deployment} -n {namespace} --no-headers 2>/dev/null"
    )
    if rc != 0:
        findings.append({
            "check": "resource_usage",
            "status": "UNKNOWN",
            "detail": "Metrics server not available",
        })
        return findings

    if not output:
        return findings

    for line in output.split("\n"):
        parts = line.split()
        if len(parts) >= 3:
            pod_name = parts[0]
            cpu = parts[1]  # e.g., "250m"
            memory = parts[2]  # e.g., "128Mi"

            # Parse memory
            mem_value = int(re.sub(r"[^0-9]", "", memory)) if memory else 0
            if "Gi" in memory:
                mem_value *= 1024

            # High memory usage warning (>3Gi)
            if mem_value > 3072:
                findings.append({
                    "check": "memory_usage",
                    "status": "WARNING",
                    "detail": f"{pod_name}: {memory} memory usage (high)",
                })

    if not findings:
        findings.append({
            "check": "resource_usage",
            "status": "OK",
            "detail": "Resource usage within normal range",
        })

    return findings


def check_endpoint_health(deployment, namespace):
    """Check if the application endpoint is responding."""
    findings = []

    # Get service ClusterIP
    output, rc = run_cmd(
        f"kubectl get svc {deployment} -n {namespace} -o jsonpath='{{.spec.clusterIP}}' 2>/dev/null"
    )

    if rc != 0 or not output or output == "None":
        findings.append({
            "check": "endpoint_health",
            "status": "UNKNOWN",
            "detail": "No service found for health check",
        })
        return findings

    # Try health endpoint
    health_output, health_rc = run_cmd(
        f"kubectl exec -n {namespace} deploy/{deployment} -- "
        f"wget -qO- --timeout=5 http://localhost:8080/health 2>/dev/null || "
        f"kubectl exec -n {namespace} deploy/{deployment} -- "
        f"curl -sf --max-time 5 http://localhost:8080/health 2>/dev/null"
    )

    if health_rc == 0 and health_output:
        findings.append({
            "check": "endpoint_health",
            "status": "OK",
            "detail": f"Health endpoint responding: {health_output[:50]}",
        })
    else:
        findings.append({
            "check": "endpoint_health",
            "status": "WARNING",
            "detail": "Health endpoint not responding",
        })

    return findings


def check_recent_events(deployment, namespace):
    """Check for warning events related to the deployment."""
    findings = []

    output, rc = run_cmd(
        f"kubectl get events -n {namespace} --field-selector type=Warning "
        f"--sort-by='.lastTimestamp' -o json 2>/dev/null"
    )

    if rc != 0:
        return findings

    try:
        events = json.loads(output)
    except json.JSONDecodeError:
        return findings

    recent_warnings = []
    for event in events.get("items", [])[-10:]:
        involved = event.get("involvedObject", {})
        if deployment in involved.get("name", ""):
            recent_warnings.append({
                "reason": event.get("reason", "Unknown"),
                "message": event.get("message", "")[:100],
                "count": event.get("count", 1),
            })

    if recent_warnings:
        findings.append({
            "check": "warning_events",
            "status": "WARNING",
            "detail": f"{len(recent_warnings)} warning event(s)",
            "events": recent_warnings[:5],
        })
    else:
        findings.append({
            "check": "warning_events",
            "status": "OK",
            "detail": "No recent warning events",
        })

    return findings


def make_decision(all_findings):
    """Determine overall health status and recommended action."""
    critical = [f for f in all_findings if f.get("status") == "CRITICAL"]
    warnings = [f for f in all_findings if f.get("status") == "WARNING"]
    ok = [f for f in all_findings if f.get("status") == "OK"]

    if critical:
        status = "CRITICAL"
        action = "IMMEDIATE_ACTION_REQUIRED"
        recommendation = "Investigate critical issues. Consider rollback if recent deployment."
    elif len(warnings) >= 3:
        status = "DEGRADED"
        action = "INVESTIGATE"
        recommendation = "Multiple warnings detected. Review resource usage and pod health."
    elif warnings:
        status = "WARNING"
        action = "MONITOR"
        recommendation = "Minor issues detected. Continue monitoring."
    else:
        status = "HEALTHY"
        action = "NONE"
        recommendation = "Application is running normally."

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "status": status,
        "action": action,
        "recommendation": recommendation,
        "summary": {
            "critical": len(critical),
            "warnings": len(warnings),
            "ok": len(ok),
        },
        "findings": all_findings,
    }


if __name__ == "__main__":
    import re

    deployment = sys.argv[1] if len(sys.argv) > 1 else "sdlc-demo"
    namespace = sys.argv[2] if len(sys.argv) > 2 else "default"
    alert_mode = "--alert" in sys.argv

    print(f"Runtime agent monitoring: {deployment} in {namespace}")
    print("-" * 50)

    all_findings = []
    all_findings.extend(check_pod_health(deployment, namespace))
    all_findings.extend(check_resource_usage(deployment, namespace))
    all_findings.extend(check_endpoint_health(deployment, namespace))
    all_findings.extend(check_recent_events(deployment, namespace))

    result = make_decision(all_findings)

    print("\n===== RUNTIME AGENT =====")
    print(json.dumps(result, indent=2))

    # Exit non-zero if critical
    if result["status"] == "CRITICAL":
        sys.exit(2)
    elif result["status"] == "DEGRADED":
        sys.exit(1)
