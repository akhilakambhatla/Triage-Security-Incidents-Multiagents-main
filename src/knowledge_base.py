"""Security playbook knowledge base for RAG-powered remediation."""

from __future__ import annotations

PLAYBOOKS: dict[str, dict] = {
    "unauthorized_access": {
        "title": "Unauthorized Access Response",
        "immediate": [
            "Revoke compromised credentials immediately",
            "Enable MFA on affected accounts if not already enabled",
            "Block source IP at WAF/security group level",
            "Capture forensic snapshot of affected instance",
        ],
        "investigation": [
            "Check CloudTrail for lateral movement from same source",
            "Review IAM policy changes in last 24 hours",
            "Identify all resources accessed by compromised credential",
            "Check for persistence mechanisms (new IAM users, access keys)",
        ],
        "long_term": [
            "Implement least-privilege IAM policies",
            "Enable GuardDuty anomaly detection",
            "Set up automated credential rotation",
            "Deploy network segmentation for sensitive workloads",
        ],
    },
    "data_exfiltration": {
        "title": "Data Exfiltration Response",
        "immediate": [
            "Block outbound traffic to identified destination",
            "Isolate affected instance from network",
            "Preserve network flow logs for forensics",
            "Notify data protection officer if PII involved",
        ],
        "investigation": [
            "Quantify data volume transferred",
            "Identify data classification of exfiltrated content",
            "Trace exfiltration path (DNS tunneling, HTTPS, S3 copy)",
            "Check for staging activities prior to exfiltration",
        ],
        "long_term": [
            "Implement DLP policies on egress points",
            "Enable S3 bucket access logging and alerts",
            "Deploy network anomaly detection for volume spikes",
            "Review and restrict S3 cross-account access policies",
        ],
    },
    "malware": {
        "title": "Malware Incident Response",
        "immediate": [
            "Isolate infected instance (remove from security group)",
            "Capture memory dump before termination",
            "Block C2 domains/IPs at DNS and firewall level",
            "Scan adjacent instances for IOC presence",
        ],
        "investigation": [
            "Identify malware family and capabilities",
            "Determine initial infection vector",
            "Map lateral movement timeline",
            "Check for data staging or exfiltration activity",
        ],
        "long_term": [
            "Deploy endpoint detection and response (EDR)",
            "Implement application whitelisting",
            "Harden AMI base images",
            "Enable runtime threat detection (GuardDuty)",
        ],
    },
    "policy_violation": {
        "title": "Policy Violation Response",
        "immediate": [
            "Document the violation with evidence",
            "Revert non-compliant configuration change",
            "Notify resource owner and security team",
            "Apply compensating control if revert not possible",
        ],
        "investigation": [
            "Determine if violation was intentional or accidental",
            "Check if violation exposed sensitive data",
            "Review change approval workflow gaps",
            "Assess blast radius of non-compliant state",
        ],
        "long_term": [
            "Implement preventive SCPs/guardrails",
            "Deploy Config Rules for drift detection",
            "Automate compliance remediation",
            "Update security training for common violations",
        ],
    },
    "anomalous_behavior": {
        "title": "Anomalous Behavior Response",
        "immediate": [
            "Flag account for enhanced monitoring",
            "Capture baseline vs. anomaly metrics",
            "Validate if activity matches known business process",
            "Restrict permissions pending investigation",
        ],
        "investigation": [
            "Compare activity pattern to user/service baseline",
            "Check for credential compromise indicators",
            "Correlate with other alerts in same timeframe",
            "Interview resource owner about expected behavior",
        ],
        "long_term": [
            "Tune anomaly detection thresholds",
            "Implement UEBA (User Entity Behavior Analytics)",
            "Establish activity baselines per service account",
            "Automate anomaly-to-ticket workflow",
        ],
    },
    "configuration_drift": {
        "title": "Configuration Drift Response",
        "immediate": [
            "Identify who made the change and when",
            "Assess security impact of the drift",
            "Revert to last known good configuration",
            "Enable change detection alerting",
        ],
        "investigation": [
            "Determine root cause (manual change, failed deployment, tool)",
            "Check if drift exposed attack surface",
            "Review other resources in same account for similar drift",
            "Validate IaC state matches actual state",
        ],
        "long_term": [
            "Enforce infrastructure as code for all changes",
            "Implement drift detection (AWS Config, Terraform)",
            "Restrict console access for production accounts",
            "Set up automated remediation for critical configs",
        ],
    },
}


def get_playbook(category: str) -> dict:
    """Retrieve the relevant playbook for a given alert category."""
    return PLAYBOOKS.get(category, PLAYBOOKS["anomalous_behavior"])


def search_playbooks(query: str) -> list[dict]:
    """Simple keyword search across playbooks (simulates RAG retrieval)."""
    results = []
    query_lower = query.lower()
    for category, playbook in PLAYBOOKS.items():
        score = 0
        all_text = " ".join(
            playbook["immediate"] + playbook["investigation"] + playbook["long_term"]
        ).lower()
        for word in query_lower.split():
            if word in all_text:
                score += 1
            if word in category:
                score += 2
        if score > 0:
            results.append({"category": category, "playbook": playbook, "score": score})
    results.sort(key=lambda x: x["score"], reverse=True)
    return results[:3]
