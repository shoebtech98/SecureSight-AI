import csv
import io
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.app.parsers.timeutil import utc_from_timestamp, utc_now

APACHE_PATTERN = re.compile(r'^([^\s]+) - ([^\s]+) \[([^\]]+)\] "([A-Z]+) ([^\s]+) HTTP/[0-9.]+\" ([0-9]{3}) ([0-9]+|-)(?: "([^"]*)" "([^"]*)")?')
SSH_PATTERN = re.compile(r'(Failed password|Accepted password) for (?:invalid user )?([^\s]+) from ([^\s]+) port (\d+)', re.I)
SYSLOG_PATTERN = re.compile(r'^([A-Za-z]{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+([a-zA-Z0-9.\-_]+)(?:\[(\d+)\])?:\s+(.*)')
APP_PATTERN = re.compile(r'^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+\[([A-Z]+)\]\s+(.*)')
WINDOWS_EVENT_PATTERN = re.compile(r'(?:EventID|Event ID|EventCode)[=:\s>]*(\d+)', re.I)
IP_PATTERN = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')

# Columns we recognize in a CSV header row. Recognized headers enable structured
# CSV parsing; anything else falls back to the generic line parser.
CSV_HEADER_TOKENS = {
    "timestamp", "time", "date", "datetime", "ts",
    "source_ip", "src_ip", "src", "source", "ip", "ip_address", "sourceip",
    "clientip", "client_ip",
    "destination_ip", "dest_ip", "dst_ip", "destination", "dest",
    "username", "user", "account", "targetusername", "user_name",
    "service", "process", "daemon", "host", "hostname", "computer",
    "status", "action", "result", "outcome",
    "port", "src_port", "source_port", "sport",
    "dest_port", "destination_port", "dport", "dst_port",
    "protocol", "proto",
    "event_type", "type", "level", "severity",
    "attempts", "count", "city", "region", "country",
}


def parse_datetime(value: Optional[str], format_type: str = "auto") -> Optional[datetime]:
    """Parse a timestamp into a naive UTC datetime, or None when it cannot be parsed."""
    if not value or not isinstance(value, str):
        return None
    value = value.strip()
    try:
        if format_type == "nginx":
            parsed = datetime.strptime(value, "%d/%b/%Y:%H:%M:%S %z")
            return parsed.astimezone(timezone.utc).replace(tzinfo=None)
        if format_type == "syslog":
            return datetime.strptime(f"{utc_now().year} {value}", "%Y %b %d %H:%M:%S")
        if format_type == "epoch":
            return utc_from_timestamp(float(value))
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    except Exception:
        return None


def _base_event(line: str) -> Dict[str, Any]:
    return {
        "timestamp": None,
        "service": "system",
        "level": "INFO",
        "message": line,
        "source_ip": None,
        "ip_address": None,
        "destination_ip": None,
        "destination_port": None,
        "hostname": None,
        "port": None,
        "protocol": None,
        "username": None,
        "method": None,
        "path": None,
        "status_code": None,
        "action": None,
        "event_status": None,
        "event_type": "unknown",
        "classification": "clean",
    }


def _extract_ips(value: str) -> List[str]:
    return IP_PATTERN.findall(value)


def _is_csv_header_line(line: str) -> bool:
    """True when the line looks like a CSV header (comma separated known columns)."""
    if "," not in line:
        return False
    columns = [c.strip().lower().replace("-", "_").replace(" ", "_") for c in line.split(",")]
    known = sum(1 for c in columns if c in CSV_HEADER_TOKENS)
    return known >= 2


def _parse_csv(content: str) -> Optional[List[Dict[str, Any]]]:
    """Parse comma-separated log files into the common event shape.

    The first non-empty line must be a recognizable header (e.g.
    timestamp,source_ip,username,service,status,port,protocol); the header row
    itself is not stored as an event.
    """
    reader = csv.reader(io.StringIO(content, newline=""))
    header_row = next(reader, None)
    while header_row is not None and not any(value.strip() for value in header_row):
        header_row = next(reader, None)
    if not header_row or not _is_csv_header_line(",".join(header_row)):
        return None

    header = [c.strip().lower().replace("-", "_").replace(" ", "_") for c in header_row]
    events: List[Dict[str, Any]] = []

    for row in reader:
        if not any(value.strip() for value in row):
            continue
        event = _base_event(",".join(row))
        event["service"] = "csv"
        event["event_type"] = "csv_event"
        for col, value in zip(header, row):
            value = (value or "").strip()
            if not value:
                continue
            if col in ("timestamp", "time", "date", "datetime", "ts"):
                event["timestamp"] = parse_datetime(value)
            elif col in ("source_ip", "src_ip", "source", "src", "ip", "ip_address", "sourceip", "clientip", "client_ip"):
                event["source_ip"] = event["ip_address"] = value
            elif col in ("destination_ip", "dest_ip", "dst_ip", "destination", "dest"):
                event["destination_ip"] = value
            elif col in ("username", "user", "account", "targetusername", "user_name"):
                event["username"] = value
            elif col in ("service", "process", "daemon"):
                event["service"] = value
            elif col in ("hostname", "host", "computer"):
                event["hostname"] = value
            elif col in ("status", "action", "result", "outcome"):
                lowered = value.lower()
                event["action"] = lowered
                event["event_status"] = lowered
            elif col in ("port", "src_port", "source_port", "sport"):
                if value.isdigit():
                    event["port"] = int(value)
            elif col in ("dest_port", "destination_port", "dport", "dst_port"):
                if value.isdigit():
                    event["destination_port"] = int(value)
            elif col in ("protocol", "proto"):
                event["protocol"] = value
            elif col in ("level", "severity"):
                event["level"] = value.upper()
            elif col in ("event_type", "type"):
                event["event_type"] = value
        events.append(event)

    return events


def parse_log_content(content: str) -> List[Dict[str, Any]]:
    """Parse supported log formats into unified SIEM events.

    Threat detection runs on the normalized output, not on this raw parse.
    """
    # CSV content is detected by its header row before the line-based parsers.
    csv_events = _parse_csv(content)
    if csv_events is not None:
        return csv_events

    events = []
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        event = _base_event(line)
        parsed = False

        # 1. Apache / Nginx Access Log
        apache = APACHE_PATTERN.match(line)
        if apache:
            ip, _, dt, method, path, status, _, _, _ = apache.groups()
            status_code = int(status)
            event.update(
                source_ip=ip,
                ip_address=ip,
                timestamp=parse_datetime(dt, "nginx"),
                service="web-server",
                event_type="http_request",
                method=method,
                path=path,
                protocol="http",
                status_code=status_code,
                action=method,
                event_status="success" if status_code < 400 else "failure",
                level="ERROR" if status_code >= 500 else "WARN" if status_code >= 400 else "INFO",
            )
            parsed = True

        # 2. Linux Auth / SSH Log
        if not parsed:
            ssh = SSH_PATTERN.search(line)
            if ssh:
                action, username, source_ip, source_port = ssh.groups()
                failed = action.lower().startswith("failed")
                event.update(
                    source_ip=source_ip,
                    ip_address=source_ip,
                    username=username,
                    service="sshd",
                    port=int(source_port),
                    protocol="ssh",
                    action="failed" if failed else "accepted",
                    event_status="failure" if failed else "success",
                    event_type="failed_login" if failed else "login",
                    level="WARN" if failed else "INFO",
                )
                syslog = SYSLOG_PATTERN.match(line)
                if syslog:
                    event["timestamp"] = parse_datetime(syslog.group(1), "syslog")
                    event["hostname"] = syslog.group(2)
                parsed = True

        # 3. Suricata / Structured JSON Log
        if not parsed and line.startswith("{"):
            try:
                record = json.loads(line)
                source_ip = record.get("src_ip") or record.get("source_ip") or record.get("src")
                destination_ip = record.get("dest_ip") or record.get("destination_ip") or record.get("dest")
                destination_port = record.get("dest_port") or record.get("destination_port")
                source_port = record.get("src_port") or record.get("source_port")
                ts = record.get("timestamp")
                if source_ip or destination_ip or record.get("event_type"):
                    event.update(
                        source_ip=source_ip,
                        ip_address=source_ip,
                        destination_ip=destination_ip,
                        hostname=record.get("hostname") or record.get("host") or record.get("computer"),
                        port=int(source_port) if source_port else None,
                        destination_port=int(destination_port) if destination_port else None,
                        service=record.get("app_proto") or record.get("service") or "suricata",
                        protocol=record.get("proto") or record.get("protocol"),
                        event_type=record.get("event_type") or "ids_alert",
                        level="WARN",
                        action="alert",
                        event_status="detected",
                        timestamp=parse_datetime(ts) if ts else None,
                    )
                    parsed = True
            except (TypeError, ValueError):
                pass

        # 4. Windows Event Logs (Event ID 4624, 4625, 4672, 1102)
        if not parsed and WINDOWS_EVENT_PATTERN.search(line):
            source_match = re.search(r'(?:IpAddress|SourceNetworkAddress|SourceIpAddress)(?:[=:]\s*|">)([^<\s,]+)', line, re.I)
            user_match = re.search(r'(?:TargetUserName|AccountName|User)(?:[=:]\s*|">)([^<\s,]+)', line, re.I)
            event_id = WINDOWS_EVENT_PATTERN.search(line)
            source_ip = source_match.group(1).strip('"') if source_match and source_match.group(1) not in {"-", "::1"} else None
            failed = bool(event_id and event_id.group(1) == "4625") or "failed" in line.lower()
            event.update(
                source_ip=source_ip,
                ip_address=source_ip,
                username=user_match.group(1).strip('"') if user_match and user_match.group(1) else None,
                service="windows",
                event_type="windows_failed_login" if failed else "windows_login",
                level="WARN" if failed else "INFO",
                action="failed" if failed else "accepted",
                event_status="failure" if failed else "success",
            )
            parsed = True

        # 5. Snort / Suricata Fast Log
        if not parsed and ("[**]" in line or "suricata" in line.lower() or "snort" in line.lower()):
            ips = _extract_ips(line)
            dst_port = re.search(r'(?:dest_port|dport|dpt)[=: ](\d+)', line, re.I)
            if not dst_port:
                arrow_port = re.search(r"->\s*[^:]+:(\d+)", line)
                dst_port = arrow_port
            event.update(
                source_ip=ips[0] if ips else None,
                ip_address=ips[0] if ips else None,
                destination_ip=ips[1] if len(ips) > 1 else None,
                destination_port=int(dst_port.group(1)) if dst_port else None,
                service="suricata" if "suricata" in line.lower() else "snort",
                protocol="tcp",
                event_type="ids_alert",
                level="WARN",
                action="alert",
                event_status="detected",
            )
            parsed = True

        # 6. Firewall Logs (iptables, UFW, Cisco, Fortinet)
        if not parsed and ("src=" in line.lower() or "src_ip" in line.lower() or "firewall" in line.lower() or "ufw" in line.lower()):
            src = re.search(r'(?:src|src_ip|source)[=: ]+([^\s,]+)', line, re.I)
            dst = re.search(r'(?:dst|dst_ip|destination)[=: ]+([^\s,]+)', line, re.I)
            dport = re.search(r'(?:dport|dpt|dst_port|destination_port)[=: ]+(\d+)', line, re.I)
            sport = re.search(r'(?:spt|src_port|source_port)[=: ]+(\d+)', line, re.I)
            proto = re.search(r'(?:proto|protocol)[=: ]+([^\s,]+)', line, re.I)
            ips = _extract_ips(line)
            source_ip = src.group(1) if src else (ips[0] if ips else None)
            destination_ip = dst.group(1) if dst else (ips[1] if len(ips) > 1 else None)
            event.update(
                source_ip=source_ip,
                ip_address=source_ip,
                destination_ip=destination_ip,
                port=int(sport.group(1)) if sport else None,
                destination_port=int(dport.group(1)) if dport else None,
                protocol=proto.group(1).lower() if proto else "tcp",
                service="firewall",
                event_type="network_connection",
                action="allow" if "allow" in line.lower() else "deny" if "deny" in line.lower() or "block" in line.lower() else None,
                event_status="blocked" if "deny" in line.lower() or "block" in line.lower() else "allowed",
            )
            parsed = True

        # 7. Zeek TSV Logs (conn.log, dns.log, http.log)
        if not parsed and "\t" in line and not line.startswith("#"):
            fields = line.split("\t")
            if len(fields) >= 5:
                ts_val = fields[0]
                src_candidate = fields[2] if len(fields) > 2 else ""
                if IP_PATTERN.fullmatch(src_candidate or ""):
                    source_port = int(fields[3]) if len(fields) > 3 and fields[3].isdigit() else None
                    dst_candidate = fields[4] if len(fields) > 4 else ""
                    destination_port = int(fields[5]) if len(fields) > 5 and fields[5].isdigit() else None
                    event.update(
                        timestamp=parse_datetime(ts_val, "epoch") if ts_val.replace('.', '', 1).isdigit() else parse_datetime(ts_val),
                        source_ip=src_candidate,
                        ip_address=src_candidate,
                        destination_ip=dst_candidate if IP_PATTERN.fullmatch(dst_candidate or "") else None,
                        port=source_port,
                        destination_port=destination_port,
                        service="zeek",
                        protocol=fields[6] if len(fields) > 6 else "conn",
                        event_type="zeek_connection",
                    )
                    parsed = True

        # 8. Standard Syslog Format
        if not parsed:
            syslog = SYSLOG_PATTERN.match(line)
            if syslog:
                dt, hostname, service, _, message = syslog.groups()
                ips = _extract_ips(message)
                lower = message.lower()
                event.update(
                    timestamp=parse_datetime(dt, "syslog"),
                    service=service,
                    message=message,
                    hostname=hostname,
                    source_ip=ips[0] if ips else None,
                    ip_address=ips[0] if ips else None,
                    event_type="syslog",
                    level="ERROR" if "error" in lower else "WARN" if "failed" in lower else "INFO",
                )
                parsed = True

        # 9. Generic Application Log Format
        if not parsed:
            app = APP_PATTERN.match(line)
            if app:
                dt, level, message = app.groups()
                event.update(
                    timestamp=parse_datetime(dt),
                    level=level,
                    message=message,
                    event_type="application",
                )
                parsed = True

        # Fallback IP extraction
        if not event["source_ip"]:
            ips = _extract_ips(line)
            if ips:
                event["source_ip"] = event["ip_address"] = ips[0]
                if len(ips) > 1:
                    event["destination_ip"] = ips[1]

        events.append(event)

    return events
