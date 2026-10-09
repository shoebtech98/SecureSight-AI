"""Regressions for account takeover and bounded API inputs."""

import unittest
from pathlib import Path
from uuid import uuid4

from fastapi.testclient import TestClient

from backend.app.core import rate_limit as rate_limit_module
from backend.app.main import app


class SecurityRegressionTests(unittest.TestCase):
    def setUp(self):
        self.previous_limiter = rate_limit_module._limiter
        rate_limit_module._limiter = rate_limit_module.SlidingWindowRateLimiter()
        self.client = TestClient(app)

    def tearDown(self):
        self.client.close()
        rate_limit_module._limiter = self.previous_limiter

    def register(self, email, **overrides):
        payload = {
            "email": email,
            "full_name": "Synthetic Test User",
            "password": "SecurePassword123!",
        }
        payload.update(overrides)
        response = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def login(self, email, password="SecurePassword123!"):
        response = self.client.post("/api/auth/login", json={"email": email, "password": password})
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": "Bearer " + response.json()["access_token"]}

    def test_email_reassignment_and_password_change_revoke_old_tokens(self):
        prefix = uuid4().hex
        old_email = f"{prefix}@example.com"
        new_email = f"renamed-{prefix}@example.com"
        first = self.register(old_email)
        old_headers = self.login(old_email)
        changed = self.client.put(
            "/api/auth/me", headers=old_headers,
            json={"email": new_email, "current_password": "SecurePassword123!"},
        )
        self.assertEqual(changed.status_code, 200)
        current_headers = {"Authorization": "Bearer " + changed.json()["access_token"]}
        second = self.register(old_email)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(self.client.get("/api/auth/me", headers=old_headers).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/me", headers=current_headers).json()["id"], first["id"])

        password_change = self.client.put(
            "/api/auth/me", headers=current_headers,
            json={"password": "DifferentPassword123!", "current_password": "SecurePassword123!"},
        )
        self.assertEqual(password_change.status_code, 200)
        self.assertEqual(self.client.post("/api/auth/refresh", headers=current_headers).status_code, 401)
        renewed = {"Authorization": "Bearer " + password_change.json()["access_token"]}
        self.assertEqual(self.client.get("/api/auth/me", headers=renewed).status_code, 200)

    def test_recovery_code_is_single_use_and_revokes_sessions(self):
        email = f"{uuid4().hex}@example.com"
        registered = self.register(email)
        code = registered["recovery_code"]
        old_headers = self.login(email)
        self.assertEqual(self.client.post("/api/auth/reset-password", json={
            "email": email, "security_answer": "guess", "new_password": "DifferentPassword123!",
        }).status_code, 422)
        self.assertEqual(self.client.post("/api/auth/reset-password", json={
            "email": email, "recovery_code": "x" * len(code), "new_password": "DifferentPassword123!",
        }).status_code, 400)
        reset_payload = {"email": email, "recovery_code": code, "new_password": "DifferentPassword123!"}
        self.assertEqual(self.client.post("/api/auth/reset-password", json=reset_payload).status_code, 200)
        self.assertEqual(self.client.get("/api/auth/me", headers=old_headers).status_code, 401)
        self.assertEqual(self.client.post("/api/auth/reset-password", json=reset_payload).status_code, 400)

        current_headers = self.login(email, "DifferentPassword123!")
        self.assertFalse(self.client.get("/api/auth/me", headers=current_headers).json()["has_recovery_code"])
        rotated = self.client.post(
            "/api/auth/recovery-code", headers=current_headers,
            json={"current_password": "DifferentPassword123!"},
        )
        self.assertEqual(rotated.status_code, 200)
        self.assertNotEqual(rotated.json()["recovery_code"], code)
        self.assertEqual(self.client.get("/api/auth/me", headers=current_headers).status_code, 401)
        renewed = {"Authorization": "Bearer " + rotated.json()["access_token"]}
        self.assertTrue(self.client.get("/api/auth/me", headers=renewed).json()["has_recovery_code"])

    def test_blank_legacy_recovery_answer_is_rejected(self):
        email = f"{uuid4().hex}@example.com"
        rejected = self.client.post("/api/auth/register", json={
            "email": email, "full_name": "Synthetic Test User", "password": "SecurePassword123!",
            "security_question": "Question", "security_answer": "   ",
        })
        self.assertEqual(rejected.status_code, 422)
        self.register(email)
        headers = self.login(email)
        update = self.client.put("/api/auth/me", headers=headers, json={
            "security_answer": "   ", "current_password": "SecurePassword123!",
        })
        self.assertEqual(update.status_code, 422)

    def test_event_search_has_bounded_query(self):
        email = f"{uuid4().hex}@example.com"
        self.register(email)
        headers = self.login(email)
        self.assertEqual(self.client.get("/api/logs/events", params={"search": "a" * 257}, headers=headers).status_code, 422)
        self.assertEqual(self.client.get("/api/logs/events", params={"limit": 100000}, headers=headers).status_code, 422)

    def test_new_account_starts_with_zero_security_data(self):
        email = f"{uuid4().hex}@example.com"
        self.register(email)
        headers = self.login(email)
        dashboard = self.client.get("/api/dashboard/stats", headers=headers)
        self.assertEqual(dashboard.status_code, 200)
        for field in ("total_events", "total_threats", "active_threats", "total_files", "critical_alerts"):
            self.assertEqual(dashboard.json()[field], 0)
        self.assertEqual(dashboard.json()["recent_threats"], [])
        self.assertEqual(dashboard.json()["threat_type_distribution"], [])
        incidents = self.client.get("/api/threats/stats", headers=headers)
        self.assertEqual(incidents.status_code, 200)
        self.assertEqual(incidents.json()["active"], 0)
        events = self.client.get("/api/logs/events", headers=headers)
        self.assertEqual(events.status_code, 200)
        self.assertEqual(events.json()["total"], 0)

    def test_demo_samples_still_produce_expected_events_and_alerts(self):
        email = f"{uuid4().hex}@example.com"
        self.register(email)
        headers = self.login(email)
        samples = Path(__file__).resolve().parents[2] / "data" / "samples"
        for name in ("ssh_auth.log", "nginx_access.log"):
            uploaded = self.client.post(
                "/api/logs/upload", headers=headers,
                files={"file": (name, (samples / name).read_bytes(), "text/plain")},
            )
            self.assertEqual(uploaded.status_code, 200, uploaded.text)
            self.assertEqual(uploaded.json()["status"], "parsed")
        stats = self.client.get("/api/dashboard/stats", headers=headers)
        self.assertEqual(stats.status_code, 200, stats.text)
        self.assertEqual(stats.json()["total_events"], 32)
        self.assertEqual(stats.json()["total_threats"], 12)


if __name__ == "__main__":
    unittest.main()
