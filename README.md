# Isaac Lares, COURSE: IT401, Assignment: A1

# Application Name: InfraRisk Analyzer

# PROJECT OVERVIEW

**Review infrastructure changes before they become outages.**

InfraRisk Analyzer is a Flask application created by Isaac for IT 401 at CSU Channel Islands. It demonstrates how an early-career Operator could review proposed IT Changes, compare Change Risk, and identify mitigations before a scheduled maintenance window.

> **Demonstration data, not a production change-management or approval system.** The IT Changes in this project are fictional. Low, Medium, and High are manually assigned Risk Levels explained by visible Risk Signals.

## Preliminary semester project concept

The semester direction is an IT change-risk analysis tool for infrastructure operations. The project is designed to showcase systems thinking for DevOps, system administration, systems engineering, network engineering, and cybersecurity-adjacent roles.

Future assignments can extend the foundation with persistent IT Changes, Risk Findings, Approval Records, Audit Trail events, and AI-generated Risk Summaries that highlight missing review items, mitigation gaps, and rollback concerns.

## Intended users

InfraRisk Analyzer is aimed at junior sysadmins, network-ops practitioners, and DevOps learners who need a structured way to review infrastructure changes before they affect production systems.

## Problem addressed

Operational changes often fail because teams miss impact, review, or rollback details before the change window. InfraRisk Analyzer makes those concerns visible in a compact Change Review Board so an Operator can focus on what needs mitigation before escalation.

## Assignment 1 features

- Shared responsive layout with navigation, footer, and an original inline SVG server-rack/warning-triangle logo
- Customized landing page with the project name, tagline, purpose, attribution, capability panels, and Review Change Risk call to action
- Six fictional IT Changes loaded from JSON
- `/explore` presented as a Change Review Board
- Filtering by Risk Level and Change Type using shareable GET parameters
- High-to-Low Risk Level ordering, risk count summary, live result count, clear-filter action, and no-results state
- Dense IT Change cards with Change Ticket, Change Owner, Affected System, Scheduled Window, Review Status, Risk Signals, Mitigation, Rollback Plan, Approval Records, and Audit Trail events
- Validation that rejects unsupported filter values with an HTTP `400` response
- Route-level pytest coverage for display, filters, validation, ordering, metadata, disclaimer, and empty results

## Information model

InfraRisk Analyzer currently manages fictional IT Changes. Each IT Change has:

- `title`
- `change_type`: Firewall, DNS, Access, Patching, Deployment, or Server Config
- `risk_level`: High, Medium, or Low
- `affected_system`
- `scheduled_window`
- `summary`
- `risk_signals`
- `mitigation`
- `rollback_plan`
- `change_owner`
- `change_ticket`
- `review_status`: Draft, Needs Review, Ready for Window, or Blocked
- `approval_records`
- `audit_trail`

No database schema is required for Assignment 1.

## Run locally

Requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Example filtered URL:

```text
http://127.0.0.1:5000/explore?risk_level=High&change_type=Firewall
```

## Test

```bash
python -m pytest -q
```

The tests exercise the application through its public HTTP interface. They do not require network access or external credentials.

## Project structure

```text
app.py                       Flask application factory and entry point
config.py                    Environment-aware configuration
data/it_changes.json         Six fictional IT Change records
models/__init__.py           ITChange and ApprovalRecord models
routes/main.py               Home and Change Review Board routes
templates/base.html          Shared document layout
templates/index.html         Landing page
templates/explore.html       Filters, IT Changes, and review metadata
static/style.css             Responsive presentation
tests/test_app.py            Public route behavior tests
docs/screenshots/            Browser-verification captures
docs/submission/             A1 PDF hand-in artifact
```

## Screenshots

### Home page

![InfraRisk Analyzer home page](docs/screenshots/home-desktop.png)

### Filtered Change Review Board

![Change Review Board filtered to High Risk Firewall changes](docs/screenshots/explore-desktop.png)

### Narrow responsive layout

![Change Review Board at the narrow responsive breakpoint](docs/screenshots/explore-mobile.png)

## Future work

Assignment 2 should prioritize persistent IT Changes with create and edit workflows. Later work may add stored Risk Findings, Approval Records, Audit Trail events, search and retrieval, external ticket or cloud export ingestion, and AI-generated Risk Summaries.

Project terminology and data decisions are documented in [`CONTEXT.md`](CONTEXT.md), [`docs/adr/0001-use-static-proposed-change-data-for-a1.md`](docs/adr/0001-use-static-proposed-change-data-for-a1.md), and [`docs/adr/0002-select-infrarisk-analyzer.md`](docs/adr/0002-select-infrarisk-analyzer.md).

## Submission artifact

The generated Assignment 1 report is available at [`docs/submission/InfraRisk-Analyzer-A1.pdf`](docs/submission/InfraRisk-Analyzer-A1.pdf).
