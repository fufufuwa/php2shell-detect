# Differential Results — measured matrices

All measurements from this repository's Docker lab (single-worker prefork,
loopback-bound), 2026-10-21/22. Raw transcripts available on request.

## 1. Headline: stale-PS(id) leak oracle, PHP 8.5.x pair

Identical configuration for both builds (`memory_limit=16M` global, `8M` on
`/leak`, `post_max_size=32M`, `MaxRequestWorkers 1`, `KeepAlive Off`).

| Target | Build | Result (4 tries) | Cookie observed |
|---|---|---|---|
| vuln-85 | php:8.5.11-apache | **4/4 leaks** | `len=16384`, prefix `b'LAAAAAAA'` — 16 KiB heap dump |
| patch-85 | php:8.5.12-apache | **0/4 leaks** | `len=32`, random hex — normal session id |

The leaked cookie body contains heap pointers (0x7f... ranges) and recycled
allocator data. The forged `zend_string.len=16384` is honored verbatim by the
vulnerable build's next-request session init; the patched build's
delayed-OOM machinery resets the state and issues a fresh id.

Sample leaked-cookie prefix (URL-decoded):

```
LAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x9f\xc7\x805\xb4\x8c\xaab\xa0p\xca\x95...
```

## 2. Full tier regression (php2shell.py v2)

| Container | Build / config | T0 version | T1 surface | T2 leak | T2b alloc | Verdict |
|---|---|---|---|---|---|---|
| unlimit0118 lab | 8.5.11, /leak 8M | hidden (expose_php=0) | LIVE | **3/3 LEAK** | 1M→1052672, 2M→2101248 | **VULNERABLE** |
| p2s-8512p | 8.5.12, same config | hidden | LIVE | 0/3 | 1M→2097152, 2M→2101248 | NO-LEAK-EVIDENCE |
| lab 8081 | 8.4.26, stock 128M | 8.4.26 AFFECTED | LIVE | 0/3 (no OOM at 128M) | no OOM | **VULNERABLE** (version matrix) |
| lab 8082 | 8.4.27, stock | 8.4.27 patched | LIVE | 0/3 | no OOM | LIKELY-PATCHED |
| p2s-c0 | 8.4.26, cleanup=0 8M | 8.4.26 AFFECTED | LIVE | 0/3 (shape mismatch) | 1M→1052672, 2M→2101248 | **VULNERABLE** (version matrix) |
| p2s-c0p | 8.4.27, same | 8.4.27 patched | LIVE | 0/3 | 1M→2097152, 2M→2101248 | LIKELY-PATCHED |

Key observations:

- The leak oracle drives a **VULNERABLE verdict without any version header**
  (the 8.5.11 lab hides `X-Powered-By` via `expose_php=0`).
- T1 (illegal-sid warnings, P1 injection) fires on **patched builds too** —
  it proves the rfc1867 early-session surface is live, not the CVE. Tools
  that report T1-style signals as "vulnerable" produce false positives on
  patched builds (observed in the wild).
- The 8.4.x pair shows no leak with the 8.5.11 reclaim shape: the shape is
  per-build. Absence of a leak does **not** disprove the CVEs.

## 3. OOM alloc fingerprint matrix (auxiliary tier)

`tried to allocate N` from the pre-RINIT OOM, by filename length:

| memory_limit | fnlen | vuln 8.4.26 | patch 8.4.27 |
|---|---|---|---|
| 8M | 1 MiB | 1052672 | 2097152 |
| 8M | 1.5 MiB | 1052672 | 2097152 |
| 8M | 2 MiB | 2101248 | 2097152 |
| 8M | 3 MiB | 2617344 | 4096 |
| 16M | 1 MiB | 1052672 | 2097152 |
| 16M | 2 MiB | 2097184 | 2101248 |
| 16M | 4 MiB | 4194306 | 4198400 |

The alloc value is a joint function of (build, memory_limit, fnlen) — at 16M
the patched parser also tracks fnlen. **Not a standalone verdict**; kept as
corroborating signal only.

## 4. Attack-surface primitives (fire on both builds — surface, not CVE)

Verified live on 8.4.26 **and** 8.4.27 (cleanup=0, 8M):

- **P1** cookie-less sid injection via multipart `PHPSESSID` form field
  (ingested regardless of `use_only_cookies=1`) — 758-byte session on disk.
- **P2** attacker-controlled session key `upload_progress_<marker>` verbatim.
- **P5** silent write denial: marker `a|b` → 0-byte session file vs `ab` →
  546 bytes (encode rejects keys containing `|`).
- Illegal-sid in-band warnings: `Session ID is too long or contains illegal
  characters` + `PHP Request Startup` context.

## 5. Negative results (published for the record)

- Serialize-state orphanization (arm → probe on the same worker) produced
  **zero observable anomalies** on both 8.4.26 and 8.4.27 across filename
  (1–3 MiB) and pad-field (3–10 MiB) carriers, with and without planted
  2 MiB sessions. Consistent with the public 18-shot negative matrix:
  arming is universal, conversion is build/heap-history sensitive and
  needs debugger/ASAN instrumentation to observe.
- The public ASAN convictions (heap-use-after-free at
  `var_unserializer.re:855`, var_destroy `__destruct` reentry) remain the
  authoritative proof of the root cause; note that this var_destroy reentry
  UAF **survives 8.4.27** and may be an independent bug worth separate
  reporting.

## 6. Reproduce

```sh
cd lab
docker compose up -d
python leak_differential.py                 # headline 4/4 vs 0/4
python ../php2shell.py http://127.0.0.1:28132/leak   # full tier scan, vuln
python ../php2shell.py http://127.0.0.1:28133/leak   # full tier scan, patched
python ../php2shell.py http://127.0.0.1:28081/       # 8.4.26 stock (version-matrix tier)
python ../php2shell.py http://127.0.0.1:28082/       # 8.4.27 stock
```
