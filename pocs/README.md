# pywb security proof-of-concept files

## AMF RCE proof of concept

`amf_poc.py` is a self-contained, loopback-only reproduction of unauthenticated OS command execution in pywb's AMF replay request handling.

### What it does

- Starts a real pywb HTTP server on an ephemeral loopback port.
- Uses an existing but empty collection with no special recorder configuration.
- Sends one crafted AMF3 remoting body to an ordinary replay route.
- Executes a fixed, harmless `os.system()` command that writes `pywb-amf-rce` to a temporary marker file.
- Verifies the marker, stops the server, and removes temporary evidence.

No target or command arguments are accepted. Do not modify it to target systems you do not own or have permission to test.

### Affected configuration

Validated against pywb 2.11.0 with Python 3.14.10 and py3AMF 0.9.1. An ordinary replay collection and the default py3AMF dependency are sufficient. No valid capture, recorder settings, custom WARC filename, live origin, or pre-planted payload file is required.

### Install and run

From the repository root:

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.txt requests
PYTHONPATH=. .venv/bin/python pocs/amf_poc.py
```

### Expected result

```text
[+] Sending 464-byte AMF3 remoting gadget
[+] Replay POST returned HTTP 404
[+] DEFAULT-CONFIG AMF OS-SYSTEM RCE CONFIRMED: .../amf-rce-proof.txt
[+] Marker contents: pywb-amf-rce
[+] Server stopped; temporary evidence cleaned up
```

The HTTP 404 is expected: command execution occurs during AMF deserialization before the later archive lookup fails.

### Other findings

`other_high_impact_pocs.py` contains loopback PoCs for live-mode SSRF, ACL identity-header spoofing, and cross-user cookie leakage. Its configuration requirements and output are documented in the source comments.
