# A2 verification record

Issue 15 release-quality verification was run on the `isaaclares-it401-a2` branch on September 20, 2026.

## Completed locally

- `43 passed` from `.venv/bin/python -m pytest -q`.
- Tests use mocked NVD and CISA responses; no live network or credential is required.
- Existing Assignment 1 artifact remains at `docs/submission/InfraRisk-Analyzer-A1.pdf`.
- Versioned Assignment 2 source and PDF are at `docs/submission/a2-submission.html` and `docs/submission/InfraRisk-Analyzer-A2.pdf`.
- Checked-in browser captures cover the final homepage, compact Change Review Board, narrow layout, and combined NVD/CISA review.
- Route behavior covers invalid input, missing key, NVD failure/rate limit/network/empty response, CISA changed markup/network failure, exact-match miss, and partial NVD-success/CISA-failure.
- NVD keyword discovery returns normalized product-search candidates and is covered by a route regression test; the side-by-side discovery state is captured in the final browser verification.
- Tracked-file scan found no credential-bearing file; `.env.example` contains only a placeholder and `.env` is ignored.
- External Intelligence routes read local change data and do not mutate it or persist source records.

## Live-source check

The private local `.env` was detected without printing its value. An authenticated NVD keyword search for Palo Alto Networks / PAN-OS returned two normalized results. The current CISA catalog no longer renders the old table; the fallback card parser successfully normalized a current public CISA catalog entry. The requested older CVE was not found in the current server-rendered result page, so the application correctly preserves an unavailable/not-listed uncertainty rather than inventing evidence.
