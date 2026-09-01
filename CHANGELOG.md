# Changelog

All notable changes to the PLI Security Platform.

## [0.1.0] — 2026-09-01

Initial release. Built from scratch over a multi-session build.

### RiskDesk

#### Core
- FastAPI + SQLite vulnerability adjudication application
- Three-source connector architecture (Falcon, Wiz, GitHub Advanced Security)
- Scope-based adjudication: finding, vuln-on-asset, vuln, component
- Policy enforcement: 40-char justification, separate approver, expiry on risk accepts
- Risk scoring (0–100) with transparent factor ledger
- SLA tracking: Critical 15d, High 30d, Medium 90d
- Re-import idempotency via unique constraint on (source, source_finding_id)

#### Workflows
- Exception request workflow: submitted → under_review → approved/rejected
- Threaded comments with internal-only notes
- Assignment rules with auto-routing after sync
- Scheduled imports with background scheduler

#### Compliance
- CIS-CAT and STIG Viewer CSV import with auto-format detection
- Per-host compliance percentages and trend tracking
- Compliance targets with glide-path calculation
- Tested against actual CIS Cisco IOS XE 17.x benchmark

#### Data enrichment
- EPSS feed integration from FIRST.org
- CISA KEV catalog integration
- Asset correlation across sources (hostname, IP, manual)
- Deduplicated finding counts

#### Authentication and access
- Three auth modes: none (dev), local (username/password), proxy (SSO)
- Role hierarchy: admin → executive → security → team → viewer
- API token system for CI pipelines and automation
- Bearer token authentication on all endpoints

#### Administration
- Connector configuration from the UI (no .env editing)
- Saved views / filter system with sharing
- Executive reporting (JSON + PPTX)
- Pipeline container management from Settings tab

#### Frontend
- Vanilla JS, no build toolchain
- Tabs: Findings, Register, Activity, Exceptions, Compliance, Rules, Sources, Settings
- Docket/ledger aesthetic with PLI seal red (#A51C30)

### DevSecOps Pipeline

#### Stack
- Docker Compose with 10 services
- Gitea (git), Woodpecker CI, SonarQube (SAST), OWASP ZAP (DAST)
- DefectDojo (aggregator), PostgreSQL, Redis

#### Pipeline stages
- Build → SAST → SCA → secrets → container scan → quality gate → staging → DAST → approval → production

#### Agents
- Trivy agent: continuous container and dependency scanning
- OpenSCAP agent: CIS/STIG compliance scanning with SCAP Security Guide

#### Integration
- Pipeline import endpoint normalizes Trivy/ZAP results into RiskDesk findings
- Quality gate queries RiskDesk for unreviewed criticals
- OpenSCAP agent uploads CIS-CAT CSV to RiskDesk compliance import
- Container management from RiskDesk admin UI

### Deployment
- Single-VM deployment script for Ubuntu 22.04/24.04
- Systemd service for RiskDesk with hardening
- Auto-generated secrets for all credentials
- UFW firewall configuration
- Nightly cron: expire decisions, EPSS/KEV feeds, backups
- Helper scripts: status, uninstall, configure-woodpecker
