from typing import Dict, Tuple

RULE_SCORES: Dict[str, Tuple[int, str, int]] = {
    "failed_login": (5, "LOW", 80),
    "repeated_failed_login": (20, "HIGH", 95),
    "sql_injection": (40, "CRITICAL", 97),
    "xss": (30, "HIGH", 94),
    "directory_traversal": (30, "HIGH", 93),
    "command_injection": (45, "CRITICAL", 95),
    "port_scan": (25, "MEDIUM", 88),
    "directory_reconnaissance": (20, "MEDIUM", 85),
    "malware_indicator": (50, "CRITICAL", 98),
    "suspicious_authentication": (35, "HIGH", 90),
    "privilege_escalation": (35, "HIGH", 90),
}


def score_detection(rule: str, indicator_count: int = 1) -> Dict[str, int | str]:
    score, severity, confidence = RULE_SCORES.get(rule, (10, "LOW", 70))
    total = min(100, score + max(0, indicator_count - 1) * 5)
    if total >= 80:
        severity = "CRITICAL"
    elif total >= 50 and severity == "MEDIUM":
        severity = "HIGH"
    return {"risk_score": total, "severity": severity, "confidence": confidence}