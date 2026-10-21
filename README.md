# php2shell-detect

**Non-destructive detection toolkit and version-differential oracle for
PHP2Shell — CVE-2026-109618 / CVE-2026-109619** (PHP core state corruption,
disclosed 2026-10-21, fixed in 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35).

The headline contribution is a **stale-PS(id) leak oracle** that separates
vulnerable from patched builds with a clean, out-of-band signal — verified
**4/4 leaks on PHP 8.5.11 vs 0/4 on PHP 8.5.12** under identical
configuration:

| Target | Build | Leak oracle (4 tries) | Cookie |
|---|---|---|---|
| vulnerable | php:8.5.11-apache | **4/4 leaks** | 16 KiB heap dump, forged length honored |
| patched | php:8.5.12-apache | **0/4 leaks** | normal 32-hex session id |

Full measured matrices: [docs/DIFFERENTIAL-RESULTS.md](docs/DIFFERENTIAL-RESULTS.md).

## Why this exists

Public tooling for PHP2Shell falls into three camps, each with a gap:

- **Exploit PoCs** (arm + leak + fire) prove the bug on one pinned build but
  are per-build — hardcoded offsets crash anything else.
- **Research archives** document primitives and ASAN convictions but ship no
  remote-verifiable differential.
- **Scanners** report attack-surface signals that **also fire on patched
  builds** (illegal-sid warnings, upload-progress behavior), producing false
  positives.

This repo fills the gap: a scanner whose strongest tier is a true
vulnerable-vs-patched differential, plus honest labeling of every
non-differential signal.

## How the oracle works

Official root cause (php-src, "Avoid state corruption via bailout"):

- **CVE-2026-109618** — an OOM bailout interrupts PHP while internal request
  data is only half-initialized; subsequent request cleanup treats the
  invalid data as valid.
- **CVE-2026-109619** — request-private state survives the freeing of its
  backing memory; a later request on the same worker reuses it before
  re-initialization resets it.

The oracle drives CVE-2026-109619's second half (state reuse) end to end:

```
ARM   multipart: 1001 spray fields + PHPSESSID=<NUL> +
      PHP_SESSION_UPLOAD_PROGRESS + a file part + a 12 MiB field
      -> RFC1867 parsing runs BEFORE module RINIT; the upload-progress
         callback has half-initialized session state (PS(id)) when the
         12 MiB field trips memory_limit
      -> OOM bailout skips the MULTIPART_EVENT_END cleanup
      -> PS(id) dangles into the next request on the same worker

READ  multipart: 841 reclaim fields (43-byte values) +
      one forged 79-byte field (zend_string.len = 16384 at +0x10,
      marker 'L' at +0x18) + 150 tail array fields
      -> next request's session init trusts the dangling pointer and
         forged length
      -> Set-Cookie: PHPSESSID=<16 KiB of recycled heap memory>

VERDICT   cookie >= 16000 bytes starting with the marker == LEAK
          == cross-request state reuse proven, no version header needed
```

Non-destructive: the worker survives (all requests return 200), the signal
is out-of-band (`Set-Cookie` — works with `display_errors=Off`), and nothing
is written to application data.

The arm/read field layouts were first demonstrated by
[unlimit0118/CVE-2026-109619-php2shell-poc](https://github.com/unlimit0118/CVE-2026-109619-php2shell-poc);
this repo contributes the patched-build differential, the scanner
integration, and the honest-limitation analysis.

## Quick start (local lab)

```sh
cd lab
docker compose up -d          # 4 loopback containers: 8.5.11/8.5.12 + 8.4.26/8.4.27
python leak_differential.py   # headline experiment: expect 4/4 vs 0/4
```

Scan a lab target with the full tier set:

```sh
python php2shell.py http://127.0.0.1:28132/leak   # 8.5.11 -> VULNERABLE via leak oracle
python php2shell.py http://127.0.0.1:28133/leak   # 8.5.12 -> NO-LEAK-EVIDENCE
python php2shell.py http://127.0.0.1:28081/       # 8.4.26 -> VULNERABLE via version matrix
python php2shell.py http://127.0.0.1:28082/       # 8.4.27 -> LIKELY-PATCHED
```

## Scanner tiers (`php2shell.py`, stdlib-only, Python 3.8+)

| Tier | Signal | Verdict power |
|---|---|---|
| T0 | `X-Powered-By` in the affected version matrix | necessary condition (can be hidden) |
| T1 | illegal-sid in-band warnings; P1 cookie-less sid injection | surface is live — **fires on patched too, never a CVE verdict by itself** |
| **T2** | **stale-PS(id) leak oracle (arm + read)** | **true version differential; drives VULNERABLE without any version header** |
| T2b | OOM alloc fingerprint (filename ladder) | corroborating only — (build, memory_limit, fnlen)-dependent |
| T3 | kill-receipt rounds (`--destructive`, opt-in) | destructive tier for explicitly authorized deep verification |

Outputs per target: human report (`.report.md`), machine verdict
(`.verdict.json`), full request/response transcript (`.transcript.jsonl`).
`--json` prints the verdict document to stdout for pipeline integration;
`--batch targets.txt` scans a list.

## Honest limitations

1. **The T2 reclaim shape is per-build.** The 841×43B layout is verified on
   PHP 8.5.11 (4/4). Other builds need their own shape matrices — a no-leak
   result does **not** disprove the CVEs. Shape contributions for 8.2.x /
   8.3.x / 8.4.x are the #1 thing this repo hopes to collect.
2. **T1 signals fire on patched builds.** They prove the rfc1867
   early-session surface is reachable, nothing more.
3. **Single-worker stickiness is required** for the oracle (arm and read
   must land on the same worker). Multi-worker production deployments hit
   probabilistically; `--leak-tries` (default 3) retries.
4. **No weaponization included.** The fire stage (forged HashTable →
   `zend_call_function` → arbitrary call) requires per-build offsets and is
   out of scope for a detection tool. Public ASAN convictions already prove
   the root cause; see
   [WoYinDao/CVE-2026-109618-CVSS-9.2-Critical](https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical).
5. The var_destroy `__destruct`-reentry UAF documented there **survives
   8.4.27** and may be an independent bug — flagged for separate research.

## Verification ask

If you reproduce the differential (or break it), please open an issue with:

- build (exact `php -v` / image digest), SAPI, `memory_limit`,
  `post_max_size`, worker model;
- the per-try output of `leak_differential.py`;
- for other builds: shape matrices (reclaim field count / value size /
  forged offset) that produce a clean vuln-vs-patch separation.

PRs adding shape matrices, SAPI coverage (FPM/CGI/FrankenPHP), or
false-positive reports against patched builds are especially welcome.

## Credits & prior art

- [unlimit0118/CVE-2026-109619-php2shell-poc](https://github.com/unlimit0118/CVE-2026-109619-php2shell-poc) —
  the arm/read leak shapes on PHP 8.5.11 (this repo's oracle builds on that
  disclosure).
- [WoYinDao/CVE-2026-109618-CVSS-9.2-Critical](https://github.com/WoYinDao/CVE-2026-109618-CVSS-9.2-Critical) —
  P1–P5 primitives, patch-diff analysis, ASAN convictions, the 18-shot
  negative matrix that motivated this repo's honest-limitation stance.
- [pentestershell/php2shellbt](https://github.com/pentestershell/php2shellbt) —
  the scanner precedent whose patched-build false positives this repo
  explicitly corrects.
- PHP upstream for the 2026-10-21 fixes and the state-corruption advisory.

## License & authorized use

MIT (see [LICENSE](LICENSE)); credits in [NOTICE](NOTICE)).

This repository contains **detection tooling and a local lab** for
already-public, already-patched CVEs. It includes no weaponization offsets
and no target lists. Use the scanner only against systems you are
explicitly authorized to test. The lab binds to 127.0.0.1 only.
