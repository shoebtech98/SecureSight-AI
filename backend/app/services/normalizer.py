from typing import Any, Dict, Iterable, List


def normalize_events(events: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    normalized = []
    for event in events:
        source_ip = event.get("source_ip") or event.get("ip_address")
        event["source_ip"] = source_ip
        event["ip_address"] = source_ip
        event["destination_ip"] = event.get("destination_ip")
        event["username"] = event.get("username")
        event["event_type"] = event.get("event_type") or event.get("service") or "unknown"
        event["message"] = str(event.get("message") or "")
        event["service"] = event.get("service") or "system"
        event["level"] = str(event.get("level") or "INFO").upper()
        event["classification"] = event.get("classification") or "clean"
        normalized.append(event)
    return normalized