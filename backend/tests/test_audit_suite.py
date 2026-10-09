import sys
import os
import unittest
from unittest.mock import patch
from datetime import datetime, timedelta
from backend.app.parsers.timeutil import utc_now

# Add root directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from fastapi.testclient import TestClient
from backend.app.main import app
from backend.app.database import get_db, SessionLocal, Base, engine, ensure_schema
from backend.app.parsers.log_parser import parse_log_content, parse_datetime
from backend.app.services.normalizer import normalize_events
from backend.app.detection.detection_engine import DetectionEngine


class SecureSightAuditTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        ensure_schema()
        cls.client = TestClient(app)
        cls.test_email = f"audit_user_{int(utc_now().timestamp())}@securesight.ai"
        cls.test_password = "SecurePassword123!"

    def test_01_auth_flow(self):
        # 1. Registration
        reg_resp = self.client.post("/api/auth/register", json={
            "email": self.test_email,
            "password": self.test_password,
            "full_name": "Audit Analyst",
            "security_question": "What is your primary SIEM tool?",
            "security_answer": "SecureSight AI"
        })
        self.assertEqual(reg_resp.status_code, 201)
        self.assertIn("id", reg_resp.json())
        self.assertGreaterEqual(len(reg_resp.json()["recovery_code"]), 32)
        self.__class__.recovery_code = reg_resp.json()["recovery_code"]

        # 2. Login
        login_resp = self.client.post("/api/auth/login", json={
            "email": self.test_email,
            "password": self.test_password
        })
        self.assertEqual(login_resp.status_code, 200)
        token_data = login_resp.json()
        self.assertIn("access_token", token_data)
        self.__class__.token = token_data["access_token"]
        self.__class__.headers = {"Authorization": f"Bearer {self.token}"}

        # 3. Protected /me route
        me_resp = self.client.get("/api/auth/me", headers=self.headers)
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["email"], self.test_email)

        # 4. Token Refresh
        refresh_resp = self.client.post("/api/auth/refresh", headers=self.headers)
        self.assertEqual(refresh_resp.status_code, 200)
        self.assertIn("access_token", refresh_resp.json())

        # 5. Invalid credentials rejected
        bad_login = self.client.post("/api/auth/login", json={
            "email": self.test_email, "password": "wrong-password"
        })
        self.assertEqual(bad_login.status_code, 401)

        # 6. Unauthorized request rejected
        unauth = self.client.get("/api/logs/events")
        self.assertEqual(unauth.status_code, 401)

        # 7. Weak password rejected on register
        weak = self.client.post("/api/auth/register", json={
            "email": "weak@securesight.ai",
            "password": "short",
            "full_name": "Weak",
            "security_question": "q",
            "security_answer": "a"
        })
        self.assertEqual(weak.status_code, 422)

        # 8. Password missing uppercase + special character rejected by policy
        weak_policy = self.client.post("/api/auth/register", json={
            "email": "weakpolicy@securesight.ai",
            "password": "password123",
            "full_name": "Weak Policy",
            "security_question": "q",
            "security_answer": "a"
        })
        self.assertEqual(weak_policy.status_code, 422)

        # 9. Reset endpoint rejects a policy-violating new password
        weak_reset = self.client.post("/api/auth/reset-password", json={
            "email": self.test_email,
            "recovery_code": self.recovery_code,
            "new_password": "newpass1"
        })
        self.assertEqual(weak_reset.status_code, 422)

    def test_01b_protected_routes_require_authentication(self):
        cases = [
            ("GET", "/api/auth/me", None),
            ("POST", "/api/auth/refresh", None),
            ("PUT", "/api/auth/me", {"full_name": "Nobody"}),
            ("GET", "/api/logs/files", None),
            ("GET", "/api/logs/events", None),
            ("DELETE", "/api/logs/files/1", None),
            ("GET", "/api/threats", None),
            ("GET", "/api/threats/stats", None),
            ("PUT", "/api/threats/1", {"status": "resolved"}),
            ("GET", "/api/dashboard/stats", None),
            ("POST", "/api/assistant/query", {"message": "Hello"}),
            ("GET", "/api/assistant/conversations", None),
            ("DELETE", "/api/assistant/conversations", None),
            ("GET", "/api/reports/alerts.csv", None),
            ("GET", "/api/reports/pdf", None),
        ]
        for method, path, payload in cases:
            with self.subTest(route=f"{method} {path}"):
                response = self.client.request(method, path, json=payload)
                self.assertEqual(response.status_code, 401)

    def test_02_parser_matrix_all_8_formats(self):
        # 1. Apache / Nginx
        apache_sample = '192.168.1.55 - - [20/Jul/2026:10:05:00 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users HTTP/1.1" 500 128 "-" "Mozilla/5.0"'
        p1 = parse_log_content(apache_sample)[0]
        self.assertEqual(p1["source_ip"], "192.168.1.55")
        self.assertEqual(p1["service"], "web-server")

        # 2. Linux SSH
        ssh_sample = 'Jul 20 10:15:01 server-01 sshd[25123]: Failed password for invalid user admin from 192.168.2.110 port 54321 ssh2'
        p2 = parse_log_content(ssh_sample)[0]
        self.assertEqual(p2["source_ip"], "192.168.2.110")
        self.assertEqual(p2["username"], "admin")
        self.assertEqual(p2["port"], 54321)

        # 3. Windows Event Log
        win_sample = '2026-07-20 10:00:00 server-01 EventID=4625 IpAddress="10.0.0.45" TargetUserName="Administrator"'
        p3 = parse_log_content(win_sample)[0]
        self.assertEqual(p3["source_ip"], "10.0.0.45")
        self.assertEqual(p3["username"], "Administrator")
        self.assertEqual(p3["service"], "windows")

        # 4. Syslog
        sys_sample = 'Jul 20 10:00:00 webhost nginx: 192.168.1.99 - Connection failed error'
        p4 = parse_log_content(sys_sample)[0]
        self.assertEqual(p4["hostname"], "webhost")

        # 5. Firewall
        fw_sample = 'Jul 20 10:00:00 ufw: [1234.56] [UFW BLOCK] IN=eth0 OUT= SRC=10.1.1.200 DST=192.168.1.1 PROTO=TCP SPT=4123 DPT=80'
        p5 = parse_log_content(fw_sample)[0]
        self.assertEqual(p5["source_ip"], "10.1.1.200")
        self.assertEqual(p5["destination_ip"], "192.168.1.1")
        self.assertEqual(p5["destination_port"], 80)

        # 6. Snort Fast Log
        snort_sample = '[**] [1:1000001:1] SQL Injection Attempt [**] [Priority: 1] {TCP} 172.16.0.5:4321 -> 192.168.1.10:80'
        p6 = parse_log_content(snort_sample)[0]
        self.assertEqual(p6["source_ip"], "172.16.0.5")
        self.assertEqual(p6["destination_ip"], "192.168.1.10")

        # 7. Suricata JSON
        suricata_sample = '{"timestamp":"2026-07-20T10:00:00.000Z","event_type":"alert","src_ip":"192.168.3.10","dest_ip":"10.0.0.1","src_port":51234,"dest_port":443,"proto":"TCP"}'
        p7 = parse_log_content(suricata_sample)[0]
        self.assertEqual(p7["source_ip"], "192.168.3.10")
        self.assertEqual(p7["destination_port"], 443)

        # 8. Zeek Connection Log
        zeek_sample = '1721469600.00\tC12345\t192.168.10.5\t53123\t10.0.0.5\t80\ttcp\thttp\t1.2\t100\t200\tSF'
        p8 = parse_log_content(zeek_sample)[0]
        self.assertEqual(p8["source_ip"], "192.168.10.5")
        self.assertEqual(p8["destination_ip"], "10.0.0.5")
        self.assertEqual(p8["timestamp"], datetime(2024, 7, 20, 10, 0))
        self.assertIsNone(p8["timestamp"].tzinfo)

    def test_02b_csv_parsing(self):
        csv_sample = (
            "timestamp,source_ip,city,username,service,attempts,status,port,protocol\n"
            "2024-01-09T23:45:07.484945,45.250.247.54,Berlin,nginx,cron,1,Success,22,TELNET\n"
            "2024-01-09T23:46:07.484945,45.250.247.54,Berlin,nginx,cron,4,Failed,22,SSH2\n"
        )
        events = parse_log_content(csv_sample)
        self.assertEqual(len(events), 2)
        # Header row must not be stored as an event
        self.assertNotIn("timestamp,source_ip", events[0]["message"])
        self.assertEqual(events[0]["source_ip"], "45.250.247.54")
        self.assertEqual(events[0]["username"], "nginx")
        self.assertEqual(events[0]["service"], "cron")
        self.assertEqual(events[0]["port"], 22)
        self.assertEqual(events[0]["protocol"], "TELNET")
        self.assertEqual(events[0]["event_status"], "success")
        self.assertEqual(events[1]["event_status"], "failed")

    def test_02c_timestamp_offsets_and_multiline_csv(self):
        self.assertEqual(parse_datetime("2026-01-01T10:00:00+05:30"), datetime(2026, 1, 1, 4, 30))
        self.assertEqual(parse_datetime("01/Jan/2026:10:00:00 +0530", "nginx"), datetime(2026, 1, 1, 4, 30))
        self.assertEqual(parse_datetime("2026-01-01T10:00:00.123456Z"), datetime(2026, 1, 1, 10, 0, 0, 123456))
        events = parse_log_content(
            'timestamp,source_ip,service\n'
            '"2026-01-01T10:00:00Z",198.51.100.5,"web\nserver"\n'
        )
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["source_ip"], "198.51.100.5")
        self.assertEqual(events[0]["service"], "web\nserver")
        self.assertEqual(parse_log_content("timestamp,source_ip,service\n"), [])

    def test_03_detection_engine_threat_rules(self):
        test_events = normalize_events([
            # SQLi
            {"message": "GET /search?q=1 UNION SELECT username, password FROM users", "path": "/search", "service": "web-server", "source_ip": "192.168.1.55"},
            # XSS
            {"message": "GET /comment?body=<script>alert(document.cookie)</script>", "path": "/comment", "service": "web-server", "source_ip": "192.168.1.66"},
            # Cmd Injection
            {"message": "POST /ping?host=127.0.0.1;cat /etc/passwd", "path": "/ping", "service": "web-server", "source_ip": "192.168.1.77"},
            # Traversal
            {"message": "GET /file?name=../../../../etc/passwd", "path": "/file", "service": "web-server", "source_ip": "192.168.1.88"},
            # Malware
            {"message": "powershell -enc AAAA... mimikatz execution", "path": "", "service": "system", "source_ip": "192.168.1.99"},
        ])

        engine = DetectionEngine()
        detections = engine.analyze(test_events)

        rules_found = {d["rule"] for d in detections}
        self.assertIn("sql_injection", rules_found)
        self.assertIn("xss", rules_found)
        self.assertIn("command_injection", rules_found)
        self.assertIn("directory_traversal", rules_found)
        self.assertIn("malware_indicator", rules_found)

    def test_03b_false_positive_regressions(self):
        engine = DetectionEngine()
        # A routine SSH user named "sudo" (or any message containing the word
        # sudo) must NOT trigger privilege escalation.
        benign_events = normalize_events([
            {"message": "Jul 20 10:15:01 server sshd: session opened for user sudo", "service": "sshd", "source_ip": "10.0.0.5"},
            {"message": "GET /search?q=hello&&world HTTP/1.1 200", "service": "web-server", "source_ip": "10.0.0.6"},
            {"message": "curl: failed to connect", "service": "system", "source_ip": "10.0.0.7"},
            {"message": "administrator logged in successfully", "service": "windows", "source_ip": "10.0.0.8"},
        ])
        detections = engine.analyze(benign_events)
        rules_found = {d["rule"] for d in detections}
        self.assertNotIn("privilege_escalation", rules_found)
        self.assertNotIn("command_injection", rules_found)

        # A genuine escalation indicator still fires.
        escalation = normalize_events([
            {"message": "sudo: pam_unix(sudo:session): session opened for user root", "service": "sudo", "source_ip": "10.0.0.9"},
        ])
        self.assertIn("privilege_escalation", {d["rule"] for d in engine.analyze(escalation)})

    def test_03c_correlation_rules(self):
        engine = DetectionEngine()

        # 5 failed logins from the same IP within 5 minutes -> Brute Force
        brute_events = normalize_events([
            {"message": f"Failed password for user bob from 10.1.1.9 port 1000{i} ssh2", "source_ip": "10.1.1.9",
             "username": "bob", "event_type": "failed_login", "timestamp": datetime(2026, 7, 20, 10, 0, i)}
            for i in range(5)
        ])
        rules = {d["rule"] for d in engine.analyze(brute_events)}
        self.assertIn("repeated_failed_login", rules)

        # 6 distinct destination ports from one IP within 2 minutes -> Port Scan
        scan_events = normalize_events([
            {"message": f"connection to port {8000 + i}", "source_ip": "10.2.2.8",
             "destination_port": 8000 + i, "event_type": "network_connection",
             "timestamp": datetime(2026, 7, 20, 10, 0, 0)}
            for i in range(6)
        ])
        rules = {d["rule"] for d in engine.analyze(scan_events)}
        self.assertIn("port_scan", rules)

    def test_03f_port_scan_requires_distinct_ports_in_one_window(self):
        base = datetime(2026, 7, 20, 10, 0)
        events = normalize_events([
            {"message": "connection", "source_ip": "198.51.100.20", "destination_port": port,
             "event_type": "network_connection",
             "timestamp": base + (timedelta(seconds=index) if index < 5 else timedelta(minutes=10 * (index - 4)))}
            for index, port in enumerate([80, 80, 80, 80, 80, 81, 82, 83, 84])
        ])
        self.assertNotIn("port_scan", {d["rule"] for d in DetectionEngine().analyze(events)})

    def test_03d_detection_evasion(self):
        """Signatures must survive common WAF-bypass obfuscation (M5)."""
        engine = DetectionEngine()
        evasive = normalize_events([
            # Inline SQL comment used as whitespace
            {"message": "GET /q?x=1 UNION/**/SELECT password FROM users", "path": "/q", "source_ip": "10.9.0.1"},
            # Padded whitespace around the boolean tautology
            {"message": "GET /login?u=admin' OR 1 = 1 -- ", "path": "/login", "source_ip": "10.9.0.2"},
            # Double URL-encoded directory traversal (%252f -> %2f -> /)
            {"message": "GET /file?name=..%252f..%252fetc/passwd", "path": "/file", "source_ip": "10.9.0.3"},
            # Backslash traversal
            {"message": "GET /d?f=..\\..\\boot.ini", "path": "/d", "source_ip": "10.9.0.4"},
            # Whitespace inside the opening script tag
            {"message": "GET /c?body=<script >alert(document.cookie)</script>", "path": "/c", "source_ip": "10.9.0.5"},
        ])
        rules = {d["rule"] for d in engine.analyze(evasive)}
        self.assertIn("sql_injection", rules)
        self.assertIn("directory_traversal", rules)
        self.assertIn("xss", rules)

        # Normalization must NOT invent matches when the tokens are merely near
        # each other in benign prose — adjacency of "union select" is preserved.
        benign = normalize_events([
            {"message": "the labor union will select a new committee", "source_ip": "10.9.0.6"},
        ])
        self.assertNotIn("sql_injection", {d["rule"] for d in engine.analyze(benign)})

    def test_03e_correlation_evasion(self):
        """Correlation must resist sliding-window / timestamp evasion (M4)."""
        engine = DetectionEngine()

        # A dense burst of 6 failures in 6s that a stray failure 30 minutes
        # earlier used to hide: the old total-span check let one outlier blow
        # out max-min and suppress the whole detection.
        burst = [
            {"message": "Failed password for user root from 10.5.5.5 port 2200%d ssh2" % i,
             "source_ip": "10.5.5.5", "username": "root", "event_type": "failed_login",
             "timestamp": datetime(2026, 7, 20, 10, 0, i)}
            for i in range(6)
        ]
        burst.append({
            "message": "Failed password for user root from 10.5.5.5 port 22099 ssh2",
            "source_ip": "10.5.5.5", "username": "root", "event_type": "failed_login",
            "timestamp": datetime(2026, 7, 20, 9, 30, 0),
        })
        rules = {d["rule"] for d in engine.analyze(normalize_events(burst))}
        self.assertIn("repeated_failed_login", rules)

        # Timestamps that failed to parse (None) must not slip past correlation:
        # fall back to the raw count so timestamp-stripping is not an evasion.
        untimed = normalize_events([
            {"message": "Failed password for user root from 10.6.6.6 port 5000%d ssh2" % i,
             "source_ip": "10.6.6.6", "username": "root", "event_type": "failed_login",
             "timestamp": None}
            for i in range(5)
        ])
        self.assertIn("repeated_failed_login", {d["rule"] for d in engine.analyze(untimed)})

    def test_04_log_upload_and_pipeline(self):
        log_content = (
            '192.168.1.55 - - [20/Jul/2026:10:05:00 +0000] "GET /api/users?id=1%20UNION%20SELECT%20username,%20password%20FROM%20users HTTP/1.1" 500 128 "-" "Mozilla/5.0"\n'
            'Jul 20 10:15:01 server-01 sshd[25123]: Failed password for invalid user admin from 192.168.2.110 port 54321 ssh2\n'
            'Jul 20 10:15:02 server-01 sshd[25123]: Failed password for invalid user admin from 192.168.2.110 port 54322 ssh2\n'
            'Jul 20 10:15:03 server-01 sshd[25123]: Failed password for invalid user admin from 192.168.2.110 port 54323 ssh2\n'
            'Jul 20 10:15:04 server-01 sshd[25123]: Failed password for invalid user admin from 192.168.2.110 port 54324 ssh2\n'
            'Jul 20 10:15:05 server-01 sshd[25123]: Failed password for invalid user admin from 192.168.2.110 port 54325 ssh2\n'
        )

        upload_resp = self.client.post(
            "/api/logs/upload",
            headers=self.headers,
            files={"file": ("audit_sample.log", log_content.encode("utf-8"), "text/plain")}
        )
        self.assertEqual(upload_resp.status_code, 200)
        self.assertEqual(upload_resp.json()["status"], "parsed")

        # Bad extension rejected
        bad_ext = self.client.post(
            "/api/logs/upload",
            headers=self.headers,
            files={"file": ("audit_sample.exe", log_content.encode("utf-8"), "application/octet-stream")}
        )
        self.assertEqual(bad_ext.status_code, 415)

    def test_04b_cross_file_brute_force(self):
        source = "198.51.100.99"
        file_ids = []
        for part, seconds in enumerate(([1, 2, 3], [4, 5]), start=1):
            if part == 2:
                unrelated = self.client.post(
                    "/api/logs/upload", headers=self.headers,
                    files={"file": ("same_ip_unrelated.log",
                                    b"2026-10-01T10:00:03Z [INFO] connection open from 198.51.100.99\n",
                                    "text/plain")},
                )
                self.assertEqual(unrelated.status_code, 200)
                unrelated_file_id = unrelated.json()["id"]
            content = "".join(
                f"Oct  1 10:00:{second:02d} server sshd[100]: Failed password for user alice from {source} port 2200{second} ssh2\n"
                for second in seconds
            )
            response = self.client.post(
                "/api/logs/upload", headers=self.headers,
                files={"file": (f"cross_{part}.log", content.encode(), "text/plain")},
            )
            self.assertEqual(response.status_code, 200)
            file_ids.append(response.json()["id"])
        alerts = self.client.get("/api/threats?limit=500", headers=self.headers).json()
        brute = [alert for alert in alerts if alert["source_ip"] == source and alert["rule_triggered"] == "repeated_failed_login"]
        self.assertEqual(len(brute), 1)
        self.assertEqual(self.client.delete(f"/api/logs/files/{unrelated_file_id}", headers=self.headers).status_code, 200)
        after_unrelated_delete = self.client.get("/api/threats?limit=500", headers=self.headers).json()
        self.assertTrue(any(alert["source_ip"] == source and alert["rule_triggered"] == "repeated_failed_login"
                            for alert in after_unrelated_delete))
        self.assertEqual(self.client.delete(f"/api/logs/files/{file_ids[0]}", headers=self.headers).status_code, 200)
        remaining = self.client.get("/api/threats?limit=500", headers=self.headers).json()
        self.assertFalse(any(alert["source_ip"] == source and alert["rule_triggered"] == "repeated_failed_login"
                             for alert in remaining))

    def test_04c_cross_file_correlation_is_user_scoped(self):
        other_email = f"other_{int(utc_now().timestamp())}@securesight.ai"
        registration = self.client.post("/api/auth/register", json={
            "email": other_email, "password": self.test_password, "full_name": "Other Analyst",
            "security_question": "Tool?", "security_answer": "SecureSight",
        })
        self.assertEqual(registration.status_code, 201)
        login = self.client.post("/api/auth/login", json={"email": other_email, "password": self.test_password})
        other_headers = {"Authorization": f"Bearer {login.json()['access_token']}"}
        source = "198.51.100.99"
        content = "".join(
            f"Oct  1 10:00:{second:02d} server sshd[101]: Failed password for user alice from {source} port 2200{second} ssh2\n"
            for second in (6, 7, 8)
        )
        upload = self.client.post("/api/logs/upload", headers=other_headers,
                                  files={"file": ("other.log", content.encode(), "text/plain")})
        self.assertEqual(upload.status_code, 200)
        alerts = self.client.get("/api/threats", headers=other_headers).json()
        self.assertFalse(any(alert["rule_triggered"] == "repeated_failed_login" for alert in alerts))

    def test_05_event_explorer_and_source_ip(self):
        resp = self.client.get("/api/logs/events", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["total"], 0)
        results = data["results"]
        # Verify Source IP field is present and populated
        for event in results:
            self.assertIn("source_ip", event)
            self.assertIsNotNone(event["source_ip"])

        # Test IP search filtering
        ip_resp = self.client.get("/api/logs/events?ip_address=192.168.1.55", headers=self.headers)
        self.assertEqual(ip_resp.status_code, 200)
        self.assertGreaterEqual(ip_resp.json()["total"], 1)

    def test_06_dashboard_stats(self):
        resp = self.client.get("/api/dashboard/stats", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        stats = resp.json()
        self.assertGreater(stats["total_events"], 0)
        self.assertGreater(stats["total_threats"], 0)
        self.assertGreater(stats["total_files"], 0)

    def test_06b_dashboard_shows_latest_fifteen_dates(self):
        rows = "timestamp,source_ip,service\n" + "".join(
            f"2027-01-{day:02d}T10:00:00Z,198.51.100.30,app\n" for day in range(1, 19)
        )
        response = self.client.post("/api/logs/upload", headers=self.headers,
                                    files={"file": ("timeline.csv", rows.encode(), "text/csv")})
        self.assertEqual(response.status_code, 200)
        dates = [row["date"] for row in self.client.get("/api/dashboard/stats", headers=self.headers).json()["events_over_time"]]
        self.assertEqual(len(dates), 15)
        self.assertEqual(dates[0], "2027-01-04")
        self.assertEqual(dates[-1], "2027-01-18")

    def test_07_ai_assistant_db_retrieval(self):
        with patch("backend.app.api.assistant.call_gemini", return_value="Verified SIEM answer") as generate:
            response = self.client.post(
                "/api/assistant/query", headers=self.headers, json={"message": "What threats were detected?"}
            )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["answer"], "Verified SIEM answer")
        question, context = generate.call_args.args
        self.assertEqual(question, "What threats were detected?")
        self.assertGreater(context["total_events"], 0)
        self.assertGreater(context["total_threats"], 0)
        self.assertNotIn("evidence", str(context).lower())

    def test_07a_assistant_history_restores_and_clears(self):
        with patch("backend.app.api.assistant.call_gemini", return_value="First answer"):
            first = self.client.post("/api/assistant/query", headers=self.headers,
                                     json={"message": "First question"})
        self.assertEqual(first.status_code, 200)
        conversation_id = first.json()["conversation_id"]
        with patch("backend.app.api.assistant.call_gemini", return_value="Second answer") as generate:
            second = self.client.post("/api/assistant/query", headers=self.headers,
                                      json={"message": "Second question", "conversation_id": conversation_id})
        self.assertEqual(second.status_code, 200)
        self.assertEqual(second.json()["conversation_id"], conversation_id)
        history = generate.call_args.args[1]["conversation_history"]
        self.assertEqual(history[-2:], [{"role": "user", "content": "First question"},
                                        {"role": "assistant", "content": "First answer"}])
        latest = self.client.get("/api/assistant/conversations/latest", headers=self.headers)
        self.assertEqual(latest.status_code, 200)
        self.assertEqual(len(latest.json()["messages"]), 6)
        cleared = self.client.delete("/api/assistant/conversations", headers=self.headers)
        self.assertEqual(cleared.status_code, 200)
        self.assertIsNone(self.client.get("/api/assistant/conversations/latest", headers=self.headers).json())

    def test_07b_threat_list_pagination(self):
        resp = self.client.get("/api/threats?limit=2", headers=self.headers)
        self.assertEqual(resp.status_code, 200)
        self.assertLessEqual(len(resp.json()), 2)

    def test_07c_threat_list_reports_filtered_total(self):
        active_resp = self.client.get("/api/threats?status=active", headers=self.headers)
        self.assertEqual(active_resp.status_code, 200)
        self.assertEqual(active_resp.headers.get("x-total-count"), str(len(active_resp.json())))

        empty_resp = self.client.get("/api/threats?status=false_positive", headers=self.headers)
        self.assertEqual(empty_resp.status_code, 200)
        self.assertEqual(empty_resp.headers.get("x-total-count"), "0")
        self.assertEqual(empty_resp.json(), [])

    def test_08_reports_generation(self):
        # CSV Export
        csv_resp = self.client.get("/api/reports/alerts.csv", headers=self.headers)
        self.assertEqual(csv_resp.status_code, 200)
        self.assertIn("text/csv", csv_resp.headers["content-type"])
        self.assertIn("threat_type,severity,source_ip", csv_resp.text)

        # PDF Export
        pdf_resp = self.client.get("/api/reports/pdf", headers=self.headers)
        self.assertEqual(pdf_resp.status_code, 200)
        self.assertEqual(pdf_resp.headers["content-type"], "application/pdf")
        self.assertTrue(pdf_resp.content.startswith(b"%PDF"))

    def test_08b_profile_reauth_required(self):
        """Sensitive profile changes require the current password (M2)."""
        # Missing current password -> rejected (400, not 401 which would log out)
        r1 = self.client.put("/api/auth/me", headers=self.headers,
                             json={"password": "BrandNewPass1!"})
        self.assertEqual(r1.status_code, 400)
        # Wrong current password -> rejected
        r2 = self.client.put("/api/auth/me", headers=self.headers,
                             json={"password": "BrandNewPass1!", "current_password": "WrongPass1!"})
        self.assertEqual(r2.status_code, 400)
        # A non-sensitive change (name only) is still allowed without a password
        r3 = self.client.put("/api/auth/me", headers=self.headers,
                             json={"full_name": "Renamed Analyst"})
        self.assertEqual(r3.status_code, 200)
        # Correct current password -> a security-answer change succeeds,
        # invalidating older tokens and returning a replacement.
        r4 = self.client.put("/api/auth/me", headers=self.headers,
                             json={"security_answer": "new answer", "current_password": self.test_password})
        self.assertEqual(r4.status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=self.headers).status_code, 401)
        self.__class__.headers = {"Authorization": f"Bearer {r4.json()['access_token']}"}

    def test_09_email_change_reissues_token(self):
        new_email = f"renamed_{int(utc_now().timestamp())}@securesight.ai"
        resp = self.client.put("/api/auth/me", headers=self.headers,
                               json={"email": new_email, "current_password": self.test_password})
        self.assertEqual(resp.status_code, 200)
        body = resp.json()
        self.assertIn("access_token", body)
        self.assertIsNotNone(body["access_token"])
        # The new token must work immediately.
        me_resp = self.client.get("/api/auth/me", headers={"Authorization": f"Bearer {body['access_token']}"})
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.json()["email"], new_email)


    def test_10_rate_limiter_trusts_forwarded_headers_only_when_configured(self):
        from fastapi import HTTPException, Request
        from backend.app.core import rate_limit as rate_limit_module

        def make_request(spoofed_ip=None):
            headers = []
            if spoofed_ip is not None:
                headers.append((b"x-forwarded-for", spoofed_ip.encode("utf-8")))
            return Request({
                "type": "http",
                "headers": headers,
                "client": ("127.0.0.1", 5123),
            })

        previous = os.environ.get("TRUST_PROXY_HEADERS")
        try:
            # Secure default: rotating X-Forwarded-For must not create separate
            # rate-limit buckets for the same direct client.
            os.environ.pop("TRUST_PROXY_HEADERS", None)
            rate_limit_module._limiter._hits.clear()
            untrusted = rate_limit_module.rate_limit("audit-untrusted-proxy", 3, 60)
            for index in range(3):
                untrusted(make_request(f"203.0.113.{index}"))
            with self.assertRaises(HTTPException):
                untrusted(make_request("203.0.113.99"))

            # Explicit trusted-proxy mode preserves the old per-client behavior.
            os.environ["TRUST_PROXY_HEADERS"] = "true"
            rate_limit_module._limiter._hits.clear()
            trusted = rate_limit_module.rate_limit("audit-trusted-proxy", 3, 60)
            for index in range(4):
                trusted(make_request(f"203.0.113.{index}"))
            for _ in range(3):
                trusted(make_request())
            with self.assertRaises(HTTPException):
                trusted(make_request())
        finally:
            if previous is None:
                os.environ.pop("TRUST_PROXY_HEADERS", None)
            else:
                os.environ["TRUST_PROXY_HEADERS"] = previous
            rate_limit_module._limiter._hits.clear()


if __name__ == "__main__":
    unittest.main()
