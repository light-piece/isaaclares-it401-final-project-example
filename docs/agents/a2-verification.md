# A2 verification record

Issue 15 release-quality verification was run on the `isaaclares-it401-a2` branch on September 20, 2026.

## Completed locally

- `41 passed` from `.venv/bin/python -m pytest -q`.
- Tests use mocked NVD and CISA responses; no live network or credential is required.
- Existing Assignment 1 artifact remains at `docs/submission/InfraRisk-Analyzer-A1.pdf`.
- Versioned Assignment 2 source and PDF are at `docs/submission/a2-submission.html` and `docs/submission/InfraRisk-Analyzer-A2.pdf`.
- Checked-in browser captures cover the homepage, Change Review Board, narrow layout, and combined NVD/CISA review.
- Route behavior covers invalid input, missing key, NVD failure/rate limit/network/empty response, CISA changed markup/network failure, exact-match miss, and partial NVD-success/CISA-failure.
- Tracked-file scan found no credential-bearing file; `.env.example` contains only a placeholder and `.env` is ignored.
- External Intelligence routes read local change data and do not mutate it or persist source records.

## Operator-only final step

An authenticated live NVD acquisition check was not run because this environment has no real `NVD_API_KEY`. Before submission, configure a private ignored `.env`, run one valid review against NVD and the CISA catalog, inspect the returned fields and timestamps, then remove or retain the local secret without committing it. The automated suite remains the reproducible release check.
