import re
from typing import Any, Dict, List
from urllib.parse import unquote

from backend.app.detection.correlation_engine import CorrelationEngine
from backend.app.detection.risk_scoring import score_detection


# ── Evasion-resistant matching ────────────────────────────────────────────
# Signatures are matched against a *normalized* view of each event so the usual
# WAF-bypass tricks don't defeat a plain substring test:
#   * multi-level URL-encoding (%252e%252e%252f)  -> recursive percent-decode
#   * inline SQL comments (union/**/select)        -> comment becomes one space
#   * padded whitespace (union    select, 1 = 1)   -> whitespace collapsed
#   * Windows separators / spaced tags (..\, <script >, onerror =)
# Whitespace that touches punctuation is dropped (so "<script >" -> "<script>"
# and "onerror =" -> "onerror="), while whitespace between two word characters
# is kept as a single space (so "union   select" -> "union select" and the
# "union select" signature still requires the two tokens to be adjacent — no new
# false positives). Both the haystack AND every indicator pass through the same
# normalizer, so existing multi-token signatures like "/bin/sh -c" keep matching.
_WHITESPACE_RE = re.compile(r"\s+")
_WHITESPACE_AROUND_PUNCT_RE = re.compile(r"\s*([^\w\s])\s*")


def _strip_sql_comments(text: str) -> str:
    """Remove complete block comments with a forward-only scan."""
    parts = []
    position = 0
    while True:
        start = text.find("/*", position)
        if start < 0:
            parts.append(text[position:])
            break
        end = text.find("*/", start + 2)
        if end < 0:
            parts.append(text[position:])
            break
        parts.extend((text[position:start], " "))
        position = end + 2
    return "".join(parts)


def _recursive_unquote(text: str, max_passes: int = 3) -> str:
    """Percent-decode repeatedly (bounded) so multi-level encoding collapses."""
    for _ in range(max_passes):
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    return text


def normalize_payload(text: str) -> str:
    text = _recursive_unquote(text).lower()
    text = _strip_sql_comments(text)
    text = text.replace("\\", "/")
    text = _WHITESPACE_RE.sub(" ", text)
    text = _WHITESPACE_AROUND_PUNCT_RE.sub(r"\1", text)
    return text.strip()


INDICATOR_RULES = {
    "sql_injection": ("SQL Injection", ["union select", "or 1=1", "drop table", "information_schema", "xp_cmdshell"], "T1190", "Block the source and inspect the affected application for injection exposure."),
    "xss": ("Cross Site Scripting (XSS)", ["<script>", "javascript:", "onerror=", "alert(", "document.cookie"], "T1189", "Block the request and apply output encoding and input validation."),
    "directory_traversal": ("Directory Traversal", ["../", "..%2f", "/etc/passwd", "boot.ini"], "T1190", "Block the source and restrict file access to an allowlisted directory."),
    # Deliberately specific: generic shell metacharacters and tool names (&&, ||,
    # wget, curl, powershell, sudo) appear in routine traffic and produce floods of
    # false positives. Only flag unambiguous command-execution payloads.
    "command_injection": ("Command Injection", [";cat /etc/passwd", "|cat /etc/passwd", ";whoami", "|whoami", "&&whoami", "||whoami", "$(whoami)", "`whoami`", "cmd.exe", "powershell -enc", "/bin/sh -c", "/bin/bash -c"], "T1059", "Isolate the source and remove shell execution from request handling."),
    "malware_indicator": ("Malware Indicator", ["mimikatz", "meterpreter", "cobalt strike", "powershell -enc", "encoded commands"], "T1059.001", "Isolate the host, preserve evidence, and begin malware triage."),
    "privilege_escalation": ("Privilege Escalation", ["session opened for user root", "root login", "privilege granted", "privileges assigned"], "T1548", "Verify the change with the owner and review privileged account activity."),
}


# Precompute the normalized form of every indicator once, keeping the original
# text alongside it so evidence stays human-readable.
_NORMALIZED_INDICATOR_RULES = {
    rule: (threat_type, [(indicator, normalize_payload(indicator)) for indicator in indicators], mitre, action)
    for rule, (threat_type, indicators, mitre, action) in INDICATOR_RULES.items()
}


class DetectionEngine:
    def __init__(self, correlation_engine: CorrelationEngine | None = None):
        self.correlation_engine = correlation_engine or CorrelationEngine()

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        for index, event in enumerate(events):
            haystack = normalize_payload(f'{event.get("message", "")} {event.get("path", "")}')
            for rule, (threat_type, indicators, mitre, action) in _NORMALIZED_INDICATOR_RULES.items():
                matches = [original for original, normalized in indicators if normalized in haystack]
                if matches:
                    detections.append(self._build_detection(rule, threat_type, event, index, matches, mitre, action))
            message = haystack
            if "failed password" in message or "login failed" in message or "authentication failure" in message:
                detections.append(self._build_detection("failed_login", "Authentication Failure", event, index, ["failed login"], "T1110", "Verify the user and source IP; apply MFA and rate limiting."))

        detections.extend(self._correlate(events))
        return detections

    def _correlate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        results = []
        for detection in self.correlation_engine.correlate(events):
            event = events[detection["event_index"]]
            results.append(self._build_detection(
                detection["rule"], detection["threat_type"], event, detection["event_index"],
                [detection["evidence"]], "T1110" if detection["rule"] == "repeated_failed_login" else "T1046",
                "Block the source, investigate the account, and preserve the correlated event evidence.", detection,
            ))
        return results

    @staticmethod
    def _build_detection(rule, threat_type, event, index, matches, mitre, action, extra=None):
        extra = extra or {}
        score = score_detection(rule, len(matches))
        evidence = extra.get("evidence") or ", ".join(matches)
        return {
            "rule": rule, "threat_type": threat_type, "event_index": index,
            "source_ip": extra.get("source_ip") or event.get("source_ip"),
            "destination_ip": event.get("destination_ip"), "username": extra.get("username") or event.get("username"),
            "evidence": evidence, "mitre_technique": mitre, "recommended_action": action,
            "description": f"{threat_type} detected: {evidence}",
            "ai_summary": f"This event was flagged because the {rule.replace('_', ' ')} rule matched {evidence}. Review the evidence and contain the source before remediation.",
            "incident_summary": f"{threat_type} involving {event.get('source_ip') or 'an unknown source'}.",
            **score,
        }
