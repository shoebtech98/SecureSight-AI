from collections import Counter, defaultdict
from datetime import timedelta
import os
from typing import Any, Dict, List


class CorrelationEngine:
    """Correlates normalized events into multi-event security detections."""

    def __init__(self, failed_login_threshold: int | None = None, failed_login_window_minutes: int | None = None,
                 port_scan_threshold: int | None = None, port_scan_window_minutes: int | None = None):
        self.failed_login_threshold = failed_login_threshold or int(os.getenv("SIEM_FAILED_LOGIN_THRESHOLD", "5"))
        self.failed_login_window = timedelta(minutes=failed_login_window_minutes or int(os.getenv("SIEM_FAILED_LOGIN_WINDOW_MINUTES", "5")))
        self.port_scan_threshold = port_scan_threshold or int(os.getenv("SIEM_PORT_SCAN_THRESHOLD", "5"))
        self.port_scan_window = timedelta(minutes=port_scan_window_minutes or int(os.getenv("SIEM_PORT_SCAN_WINDOW_MINUTES", "2")))

    @staticmethod
    def _burst_reached(events: List[Dict[str, Any]], threshold: int, window: timedelta) -> bool:
        """True when >= ``threshold`` of ``events`` fall inside any ``window``-sized span.

        This is a *sliding* window, not a total-span check. The previous
        ``max - min <= window`` test could be defeated by injecting a single
        stray early/late event from the same source: that one event blew out the
        span and suppressed an otherwise-obvious burst, so *adding* malicious
        events *reduced* detection. Here we find the densest window instead.

        Events whose timestamp could not be parsed (``parse_datetime`` returns
        ``None``) still count toward the burst but cannot be used to spread it
        out; and when *no* event in the group carries a timestamp we fall back to
        the raw count, so stripping/garbling timestamps is not itself an evasion.
        """
        timestamps = sorted(ts for ts in (e.get("timestamp") for e in events) if ts is not None)
        untimed = len(events) - len(timestamps)
        if not timestamps:
            return untimed >= threshold
        best = 0
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1
            best = max(best, right - left + 1)
        # Untimed events are assumed contemporaneous with the densest burst: they
        # can raise the count but never widen the window.
        return best + untimed >= threshold

    @staticmethod
    def _distinct_ports_in_window(events: List[Dict[str, Any]], window: timedelta) -> int:
        """Count the most distinct destination ports in one sliding window."""
        timed = sorted(
            ((event["timestamp"], event["destination_port"]) for event in events
             if event.get("timestamp") is not None),
            key=lambda item: item[0],
        )
        untimed_ports = {event["destination_port"] for event in events if event.get("timestamp") is None}
        if not timed:
            return len(untimed_ports)
        left = 0
        best = 0
        counts = Counter()
        distinct = len(untimed_ports)
        for right, (timestamp, port) in enumerate(timed):
            if counts[port] == 0 and port not in untimed_ports:
                distinct += 1
            counts[port] += 1
            while timestamp - timed[left][0] > window:
                expired_port = timed[left][1]
                counts[expired_port] -= 1
                if counts[expired_port] == 0:
                    del counts[expired_port]
                    if expired_port not in untimed_ports:
                        distinct -= 1
                left += 1
            best = max(best, distinct)
        return best

    def correlate(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        detections = []
        failed_by_ip = defaultdict(list)
        ports_by_ip = defaultdict(list)
        logins_by_user = defaultdict(list)

        web_scans_by_ip = defaultdict(list)

        for index, event in enumerate(events):
            message = event["message"].lower()
            source_ip = event.get("source_ip")
            username = event.get("username")
            if source_ip and ("failed password" in message or "login failed" in message or
                              "authentication failure" in message or event.get("event_type") == "windows_failed_login"):
                failed_by_ip[source_ip].append(index)
            if source_ip and event.get("destination_port"):
                ports_by_ip[source_ip].append(index)
            if source_ip and (event.get("status_code") == 404 or "404" in message):
                web_scans_by_ip[source_ip].append(index)
            if username and event.get("event_type") in {"login", "windows_login", "windows_failed_login"}:
                logins_by_user[username].append(index)

        for source_ip, indexes in failed_by_ip.items():
            candidates = [events[index] for index in indexes]
            if self._burst_reached(candidates, self.failed_login_threshold, self.failed_login_window):
                detections.append({
                    "rule": "repeated_failed_login", "threat_type": "Brute Force Attack",
                    "event_index": indexes[-1], "source_ip": source_ip,
                    "evidence": f"{len(indexes)} failed authentication attempts from {source_ip} within {self.failed_login_window.seconds // 60} minutes.",
                })

        for source_ip, indexes in ports_by_ip.items():
            candidates = [events[index] for index in indexes]
            distinct_ports = self._distinct_ports_in_window(candidates, self.port_scan_window)
            if distinct_ports >= self.port_scan_threshold:
                detections.append({
                    "rule": "port_scan", "threat_type": "Port Scan",
                    "event_index": indexes[-1], "source_ip": source_ip,
                    "evidence": f"{source_ip} attempted connections to {distinct_ports} distinct ports within {self.port_scan_window.seconds // 60} minutes.",
                })

        for source_ip, indexes in web_scans_by_ip.items():
            if len(indexes) >= 10:
                detections.append({
                    "rule": "directory_reconnaissance", "threat_type": "Directory Reconnaissance",
                    "event_index": indexes[-1], "source_ip": source_ip,
                    "evidence": f"{source_ip} executed {len(indexes)} scanning probes triggering 404 Not Found responses.",
                })

        for username, indexes in logins_by_user.items():
            distinct_ips = {events[index].get("source_ip") for index in indexes if events[index].get("source_ip")}
            candidates = [events[index] for index in indexes]
            if len(distinct_ips) >= 3 and self._burst_reached(candidates, 3, timedelta(minutes=10)):
                detections.append({
                    "rule": "suspicious_authentication", "threat_type": "Suspicious Authentication",
                    "event_index": indexes[-1], "source_ip": events[indexes[-1]].get("source_ip"),
                    "username": username,
                    "evidence": f"User {username} authenticated from {len(distinct_ips)} source IPs within 10 minutes.",
                })
        return detections
