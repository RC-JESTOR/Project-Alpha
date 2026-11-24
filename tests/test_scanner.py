"""End-to-end self-test for Project Alpha against a local sandbox HTTP server."""

import http.server
import json
import os
import tempfile
import threading
import unittest

from project_alpha.cli import main as cli_main


class _SandboxHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "SandboxServer/0.1-dev")
        self.send_header("Set-Cookie", "session_id=demo123; Path=/")
        self.end_headers()

        html = """<!DOCTYPE html>
<html>
<body>
  <!-- TODO: remove debug secret key -->
  <h1>Local Sandbox App</h1>
  <form method="POST" action="/submit">
    <input type="text" name="username">
    <input type="submit" value="Go">
  </form>
  <a href="/about">About Page</a>
  <a href="https://example.com" target="_blank">External Link</a>
  <script>document.getElementById("x").innerHTML = "demo";</script>
</body>
</html>"""
        self.wfile.write(html.encode("utf-8"))


class ProjectAlphaTestSuite(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _SandboxHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def test_end_to_end_audit_and_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_out = os.path.join(tmp, "report.json")
            html_out = os.path.join(tmp, "report.html")
            rc = cli_main([
                "--url", f"http://127.0.0.1:{self.port}",
                "--mode", "http",
                "--max-pages", "5",
                "--output-json", json_out,
                "--output-html", html_out,
                "--authorized",
            ])
            self.assertEqual(rc, 0)
            self.assertTrue(os.path.isfile(json_out))
            self.assertTrue(os.path.isfile(html_out))

            with open(json_out, encoding="utf-8") as fh:
                data = json.load(fh)
            ids = {f["id"] for f in data["findings"]}
            self.assertIn("HDR-CONTENT-SECURITY-POLICY", ids)
            self.assertIn("COOKIE-FLAGS", ids)
            self.assertIn("FORM-CSRF", ids)
            self.assertIn("DOM-SINK", ids)
            self.assertIn("DOM-TABNABBING", ids)


if __name__ == "__main__":
    unittest.main()
