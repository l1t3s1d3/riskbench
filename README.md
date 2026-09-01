# RiskDesk + DevSecOps Pipeline

Two projects that work together. RiskDesk is a vulnerability adjudication application. The DevSecOps pipeline is a containerized CI/CD stack with integrated security scanning. They connect: the pipeline's scanners push findings into RiskDesk, and RiskDesk's adjudication decisions control what the pipeline allows to deploy.

---

## RiskDesk

A FastAPI + SQLite application (~8,000 lines of Python, ~2,800 lines of JS/HTML/CSS) for unified vulnerability management across CrowdStrike Falcon, Wiz, GitHub Advanced Security, and the DevSecOps pipeline's own scanners. No build toolchain. No npm. No webpack. One `pip install` and `python -m app.cli serve`.

### What it does

RiskDesk is the place where vulnerability decisions happen. Scanners find things; RiskDesk decides what to do about them. Every finding gets a risk score, an SLA clock, and eventually a disposition: fix it, accept the risk, adjust the severity, or flag it as a false positive. Those decisions are durable — a scope-based adjudication on CVE-2024-3094 at vuln scope covers all current and future findings for that CVE across all sources, so you don't re-argue the same decision every time a new scan runs.

### Core capabilities

**Three-source connector architecture.** Falcon Spotlight (endpoint vulns via OAuth2 + cursor pagination), Wiz (cloud vulns + misconfigs via GraphQL with tenant-specific schema introspection), and GitHub Advanced Security (Dependabot, code scanning, secret scanning via REST). Each connector normalizes results into the same record shape. A fourth "pipeline" connector receives Trivy and ZAP results from CI. All four sources appear in the same Findings tab with the same filters, scoring, and adjudication behavior.

**Scope-based adjudication.** Decisions attach to scopes — finding, vuln-on-asset, vuln, or component — not to individual rows. One accept decision on CVE-X at vuln scope governs all 34 findings for that CVE across all sources. The policy engine enforces: justifications must be ≥40 characters, the approver can't be the submitter, risk acceptances require an expiry date. Decisions go through pending → approved/rejected with a full audit trail.

**Risk scoring.** Every finding gets a 0–100 priority score from a factor ledger: base CVSS, EPSS exploit probability, KEV catalog membership, internet exposure, data classification, fix availability, and asset criticality. Missing inputs are reported as "not applied" with an explicit caveat — the score reports a floor, not a default. SLAs are computed from effective severity: Critical 15d, High 30d, Medium 90d.

**Exception workflow.** Teams submit exception requests through the UI. Exceptions go through submitted → under_review → (info_requested ↔ under_review) → approved/rejected. Approved exceptions automatically create adjudication records that satisfy the pipeline quality gate. Threaded comments with internal-only notes for the security team.

**CIS and STIG compliance tracking.** Import CIS-CAT and STIG Viewer CSV exports. The parser auto-detects format. Per-host compliance percentages, trend over time, failed check details with Cisco/vendor documentation links. Compliance targets with glide path calculation — "you need to close 4 controls per month to hit 100% by April 2027."

**Asset correlation.** Group assets across sources by hostname, IP, or manual mapping. Deduplicated finding counts show how much cross-source overlap inflates the backlog.

**Saved views.** Name and save any filter combination. Shared views appear for all users. One-click access from the findings sidebar. These become the standing agenda for weekly triage meetings.

**EPSS and KEV feed enrichment.** Pulls the EPSS CSV from FIRST.org and the KEV catalog from CISA. Updates every matching CVE in the database. Available as a UI button, API call, or CLI command.

**API tokens.** Long-lived bearer tokens for CI pipelines and scripts. Stored hashed. Shown once at creation. Same role permissions as the creating user. Tokens are how the pipeline authenticates to RiskDesk.

**Connector configuration.** Admins enter API credentials from the Sources tab — Client ID, Client Secret, API URL — without editing .env or restarting the app. Sensitive fields display masked. Saved configs override .env and take effect immediately.

**Executive reporting.** `/api/report` returns a JSON summary: open findings by severity, compliance scores with target status, pending approvals, expiring decisions. `/api/report/pptx` generates a one-page PPTX deck in PLI style (requires python-pptx).

**Pipeline container management.** The Settings tab shows every container in the DevSecOps pipeline with start/stop/restart/logs controls. Requires the Docker socket to be mounted.

### File structure

```
riskdesk/
├── app/
│   ├── main.py              FastAPI routes (1,456 lines)
│   ├── models.py             SQLAlchemy models (578 lines)
│   ├── compliance.py          CIS/STIG import + tracking
│   ├── adjudication.py        Scope-based decisions + policy
│   ├── queries.py             Finding search + effective severity
│   ├── risk.py                Priority scoring + factor ledger
│   ├── exceptions.py          Exception request workflow
│   ├── correlation.py         Cross-source asset matching
│   ├── enrichment.py          EPSS + KEV feed integration
│   ├── reporting.py           Executive summary + PPTX
│   ├── pipeline.py            CI scan import + container mgmt
│   ├── tokens.py              API token management
│   ├── connector_config.py    Admin-editable credentials
│   ├── auth.py                Local + SSO proxy + bearer auth
│   ├── assignment.py          Auto-routing rules
│   ├── scheduler.py           Background sync scheduler
│   ├── sync.py                Upsert engine + stale marking
│   ├── config.py              Policy + settings
│   ├── enums.py               Source, Severity, Disposition
│   ├── db.py                  SQLAlchemy + WAL mode
│   ├── cli.py                 CLI: init, sync, demo, expire
│   ├── connectors/
│   │   ├── falcon.py          CrowdStrike Spotlight
│   │   ├── wiz.py             Wiz GraphQL + introspection
│   │   ├── github.py          GHAS (Dependabot/code/secret)
│   │   ├── demo.py            Synthetic data generator
│   │   └── base.py            NormalizedRecord contract
│   └── static/
│       ├── index.html         Shell + tab navigation
│       ├── app.js             All UI logic (2,184 lines)
│       └── styles.css          Docket/ledger aesthetic
├── requirements.txt
├── .env.example
├── run.sh / run.ps1 / run.bat
└── README.md
```

### Running it

```bash
cd riskdesk
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m app.cli init
python -m app.cli demo          # load synthetic data to explore the UI
python -m app.cli serve         # http://localhost:8080
```

On Windows, run `run.ps1` or `run.bat` instead — they handle venv creation and dependency installation.

### Key design decisions

**Scope-based adjudication over row-level decisions.** A decision at vuln scope is durable across re-imports. New scan data that arrives with the same CVE is automatically covered by the existing decision. This is what makes the quality gate work — you don't need to re-adjudicate after every scan.

**Cross-source deduplication strategy.** Findings are NOT deduplicated across sources (a Falcon finding ≠ a Wiz finding for the same CVE on the same host). Vulns ARE deduplicated by canonical ID. Adjudication at vuln scope covers all sources. The asset correlation module provides optional cross-source grouping for deduped counting.

**Scoring transparency.** Missing inputs (EPSS, internet exposure, data classification) surface as "not applied" with an explicit caveat. The factor ledger in the detail drawer shows exactly how each score was computed. No silent defaults.

**Re-import idempotency.** Unique constraint on (source, source_finding_id). Re-syncing never creates duplicates.

**Role hierarchy.** admin (Lucas, Liang) → executive (Eric, Chris) → security (Ezechias) → team (Derron, Igor) → viewer.

---

## DevSecOps Pipeline

A Docker Compose stack with 10 containers covering the full path from code checkin to production deploy. All open-source tools.

### How it works

A developer pushes to Gitea. Woodpecker CI picks up the commit and runs the pipeline: SonarQube for SAST, Trivy for SCA/container/secret scanning, then a quality gate that queries RiskDesk. If the gate passes, the code deploys to staging, OWASP ZAP runs DAST against the staging URL, and a maintainer must manually approve the production deploy.

Separately, two continuous scanning agents run on their own schedules. The Trivy agent scans all Docker images on the host every hour. The OpenSCAP agent evaluates CIS benchmarks and STIGs daily. Both report back to RiskDesk automatically.

### Components

| Service | Image | Purpose | Port |
|---|---|---|---|
| Gitea | gitea/gitea:1.22 | Self-hosted Git | 3000 |
| Woodpecker | woodpeckerci/woodpecker-server:v2 | CI/CD engine | 8000 |
| SonarQube | sonarqube:10-community | SAST | 9090 |
| OWASP ZAP | zaproxy/zap-stable | DAST | 8090 |
| DefectDojo | defectdojo/defectdojo-django | Vuln aggregator | 8080 |
| Trivy agent | custom (aquasec/trivy) | Container + SCA scanning | — |
| OpenSCAP agent | custom (Ubuntu + openscap) | CIS/STIG compliance | — |
| PostgreSQL | postgres:16-alpine | Shared database | — |
| Redis | redis:7-alpine | DefectDojo cache | — |

### Pipeline stages

1. **Build & test** — standard project build
2. **SonarQube SAST** — static code analysis
3. **Trivy SCA** — dependency vulnerability scan with severity gate
4. **Secret detection** — fails the build on any detected secret
5. **Container image scan** — Trivy on the built Docker image
6. **Quality gate** — queries RiskDesk for unreviewed critical findings; blocks deploy if any exist
7. **Deploy to staging** — if all gates pass
8. **DAST** — ZAP baseline scan against the staging URL
9. **Manual approval** — maintainer clicks "Approve" in Woodpecker UI
10. **Deploy to production** — after approval

### Integration with RiskDesk

**Scan results flow in.** Every pipeline scanner (Trivy, ZAP) POSTs results to `/api/pipeline/import` using a bearer token. The import endpoint normalizes Trivy JSON and ZAP JSON into the same finding format the connectors use. Pipeline findings appear in the Findings tab alongside Wiz, Falcon, and GitHub findings.

**Adjudication decisions flow out.** The quality gate step queries RiskDesk: "does this repository have any unreviewed critical findings?" If the security team hasn't adjudicated them, the deploy blocks. An approved exception request in RiskDesk creates an adjudication record that satisfies the gate. This means the security team's decisions in RiskDesk directly control what ships.

**Compliance results flow in.** The OpenSCAP agent exports results as CIS-CAT-format CSV and uploads them to `/api/compliance/import`. They appear in the Compliance tab alongside manually imported benchmark results.

**Container management.** The Settings tab in RiskDesk shows all pipeline containers. Admins can start, stop, restart, and view logs without SSH. Requires mounting the Docker socket into the RiskDesk container.

### Running it

```bash
cd devsecops-pipeline
cp .env.example .env
# Edit .env: set passwords, RiskDesk API token, agent intervals

docker compose up -d

# First-time Gitea → Woodpecker OAuth setup:
# 1. Open http://localhost:3000, create admin account
# 2. Settings → Applications → new OAuth app
#    Redirect URI: http://localhost:8000/authorize
# 3. Copy Client ID + Secret into .env
# 4. docker compose restart woodpecker-server
```

### Migration

All state lives in named Docker volumes. To move to a new host:

```bash
docker compose down
tar czf pipeline-data.tar.gz /var/lib/docker/volumes/devsecops-pipeline_*
# move to new host
tar xzf pipeline-data.tar.gz -C /
docker compose up -d
```

### Continuous agents

The Trivy and OpenSCAP agents run independently of CI — they're not pipeline steps, they're long-running containers that scan on a schedule.

**Trivy agent** scans all Docker images on the host (via mounted Docker socket) and filesystem paths for dependency vulnerabilities. Default interval: every hour. Results go to both RiskDesk and DefectDojo.

**OpenSCAP agent** evaluates hosts against CIS benchmarks and DISA STIGs using the SCAP Security Guide content. Default interval: daily. Results export as CIS-CAT CSV and upload to RiskDesk's compliance import. Configure profiles in `openscap-agent/profiles.yml`. For CIS-CAT Pro or DISA STIG content, mount the XCCDF bundles into `/content/`.

---

## Three gate mechanisms

The pipeline has three gates that work together to enforce "no unreviewed criticals in the environment":

1. **Automated quality gate** (pipeline stage 6). A Python script queries RiskDesk's API for unreviewed critical findings on the repository being deployed. If any exist, `exit(1)` blocks the build. The security team clears the gate by adjudicating the findings in RiskDesk — fix, accept, adjust, or false-positive. No one edits the pipeline config.

2. **Manual approval gate** (pipeline stage 9). Production deploys require a human to click "Approve" in the Woodpecker UI. This is the "a person looked at this before it went to prod" gate. It doesn't replace the quality gate — it supplements it.

3. **Exception workflow** (RiskDesk). When a team needs to deploy despite a finding — because it's a false positive, because the fix breaks something else, because the risk is accepted — they submit an exception request through RiskDesk. The security team reviews it. An approved exception creates an adjudication record that satisfies the quality gate. The pipeline unblocks without anyone touching CI config, and the decision is audited.

---

## Environment and context

Built for PLI (Practising Law Institute), a legal education organization serving attorneys and judges. The security team is ~3 people. The environment includes Azure and AWS cloud, CrowdStrike Falcon Complete, Wiz, GitHub Advanced Security, Microsoft Purview, and SolarWinds.

Key people and roles in the system:
- **Lucas, Liang** — admin role (full access)
- **Eric Poon** (CIO), **Chris** — executive role (approve decisions, view reports)
- **Ezechias** — security role (triage, adjudicate, manage scans)
- **Derron** — team role (endpoint work, assigned findings)
- **Igor** — team role (network devices, assigned findings)
