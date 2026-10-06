import json
import unittest
from io import BytesIO
from unittest.mock import patch

from backend.app.services.gemini import GeminiError, call_gemini


class GeminiClientTests(unittest.TestCase):
    def test_sends_bounded_context_and_reads_answer(self):
        response = BytesIO(json.dumps({
            "candidates": [{"content": {"parts": [{"text": "Two alerts need review."}]}}]
        }).encode())
        with patch.dict("os.environ", {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "gemini-3.1-flash-lite"}), \
             patch("backend.app.services.gemini.urlopen") as open_url:
            open_url.return_value.__enter__.return_value = response
            answer = call_gemini("Summarize alerts", {"total_threats": 2})
        self.assertEqual(answer, "Two alerts need review.")
        request = open_url.call_args.args[0]
        self.assertEqual(request.get_header("X-goog-api-key"), "test-key")
        body = json.loads(request.data)
        self.assertIn("total_threats", body["contents"][0]["parts"][0]["text"])

    def test_missing_key_fails_clearly(self):
        with patch.dict("os.environ", {"GEMINI_API_KEY": ""}):
            with self.assertRaisesRegex(GeminiError, "GEMINI_API_KEY"):
                call_gemini("Hello", {})


if __name__ == "__main__":
    unittest.main()
