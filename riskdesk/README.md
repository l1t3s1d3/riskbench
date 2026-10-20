# RiskDesk

One queue for vulnerability findings from **Wiz**, **CrowdStrike Falcon Spotlight**, and
**GitHub Advanced Security**, and one register for the decisions made about them.

The point of the tool is the second half. Pulling findings together is the easy part;
what is hard to do defensibly is record *why* a finding was accepted, adjusted, or
deferred, who approved it, when that lapses, and have those decisions keep applying as
new scan data arrives.

---

## Quick start

Needs **Python 3.10 or newer**. FastAPI resolves the `int | None` annotations in the
route signatures at runtime, so 3.9 will fail at import rather than degrade.

### Windows

Either double-click **`run.bat`**, or from PowerShell:

```powershell
cd riskdesk
powershell -ExecutionPolicy Bypass -File run.ps1 -Demo
```

The `-ExecutionPolicy Bypass` applies to that one invocation only and changes nothing
machine-wide. The script calls `.venv\Scripts\python.exe` directly rather than running
`Activate.ps1`, so the virtual environment itself never touches execution policy.

Options: `-Port 9000`, `-Demo` to load synthetic data, `-SkipInstall` on a known-good
environment.

### macOS / Linux

```bash
cd riskdesk
./run.sh
```

### Either way

The launcher creates a virtualenv, installs dependencies, writes `.env` from the
template, creates the database, and serves on <http://127.0.0.1:8080>. Re-running it is
safe — an existing environment and `.env` are left alone.

With no credentials configured yet, load synthetic data to see the interface working:

```
python -m app.cli demo
```

Everything it generates is invented, tagged as demo in the database, and flagged with a
persistent banner in the UI. Clear it with `python -m app.cli reset --demo-only`.

### If Windows opens the Microsoft Store instead of running Python

That is the App Execution Alias, not a broken install. Turn it off under
**Settings → Apps → Advanced app settings → App execution aliases**, and switch off the
`python.exe` and `python3.exe` entries. Or install Python from python.org with **"Add
python.exe to PATH"** ticked.

### If you see "could not open requirements file"

The launcher now prints the folder it resolved on startup — check that line first:

```
  Project folder: C:\Tools\riskdesk
```

If that path is wrong, or the script stops with "This does not look like the RiskDesk
project folder", the usual cause is extraction. Dragging the zip out in Explorer often
produces `riskdesk\riskdesk\`, so the outer folder has no `requirements.txt` in it. Run
the launcher from the inner folder — the one containing `requirements.txt` and `app\`.
Copying `run.ps1` somewhere on its own does the same thing.

If the path is right and it still fails, the venv is likely half-built from an earlier
attempt. Delete the `.venv` folder and run the launcher again.

### Running commands manually on Windows

The launcher wraps these, but if you want to drive it yourself, use the venv interpreter
directly — no activation needed:

```powershell
.venv\Scripts\python.exe -m app.cli check
.venv\Scripts\python.exe -m app.cli sync all
.venv\Scripts\python.exe -m app.cli expire
```

If you would rather activate the environment for a session:

```powershell
.venv\Scripts\Activate.ps1     # PowerShell, needs RemoteSigned or looser
.venv\Scripts\activate.bat     # Command Prompt, no policy involved
```

Everywhere the rest of this README says `python -m app.cli …`, that is the same command.

---

## Connecting your sources

Copy `.env.example` to `.env` and fill in what you have. Sources are independent — one
configured source is enough to start.

```bash
python -m app.cli check     # tests every configured connector
python -m app.cli sync all  # pulls from every configured source
```

`check` also runs from the Sources tab in the UI, per source.

### Wiz

| Setting | Notes |
|---|---|
| `WIZ_CLIENT_ID` / `WIZ_CLIENT_SECRET` | Service account, read access to vulnerability and configuration findings |
| `WIZ_API_URL` | Region-specific, e.g. `https://api.us17.app.wiz.io/graphql`. Copy from Settings → Service Accounts |

**Verify the GraphQL query before your first sync.** Wiz's schema is versioned per
tenant and field names do drift. A single unknown field fails the entire query rather
than degrading, so:

```bash
python -m app.cli wiz-introspect --type VulnerabilityFinding
```

Compare the output against `VULN_FINDINGS_QUERY` in `app/connectors/wiz.py` and edit
the constant if anything has moved. The queries are isolated at the top of that module
specifically so this is a five-minute job, not a code hunt.

Pulls vulnerability findings (including secret-detection findings) and cloud
configuration findings. Configuration findings are a separate entitlement; if yours
does not include them the sync logs a warning and continues rather than failing.

### CrowdStrike Falcon

| Setting | Notes |
|---|---|
| `FALCON_CLIENT_ID` / `FALCON_CLIENT_SECRET` | API client with the **Spotlight vulnerabilities: READ** scope |
| `FALCON_BASE_URL` | Must match your cloud — `api.crowdstrike.com`, `api.us-2…`, `api.eu-1…`, `api.laggar.gcw…` |
| `FALCON_FILTER_FQL` | Defaults to open findings only |

Spotlight is licensed separately from Falcon Complete's EDR coverage. If a valid token
returns 403, that is the missing scope rather than a bad credential — `check` says so
explicitly.

### GitHub Advanced Security

| Setting | Notes |
|---|---|
| `GITHUB_TOKEN` | Fine-grained PAT or App token |
| `GITHUB_ORG` | Organisation to scan |

Token needs read on **Dependabot alerts**, **code scanning alerts**, and **secret
scanning alerts** across the org. Classic PATs need `security_events` + `repo`.

**A note on naming.** GitHub Copilot does not expose a vulnerability API. The findings
you want live in Advanced Security, which is what this connector reads. Copilot Autofix
availability rides along on code scanning alerts and is captured as the `fix_available`
flag on those records. If any of the three alert families is disabled for your org, that
stream is skipped with a warning and the rest still sync.

---

## How decisions work

This is the part worth reading before using the tool in anger.

### Decisions attach to a scope, not to a row

If an acceptance were stored per-finding, accepting CVE-2021-44228 across 40 hosts would
write 40 rows — and when Wiz reports it on host 41 next month, the acceptance would
silently not apply. So every decision is recorded against a **scope**:

| Scope | Covers |
|---|---|
| `finding` | One instance on one asset |
| `vuln_on_asset` | This CVE on this asset, including future re-detections |
| `vuln` | This CVE everywhere, now and in future scans |
| `component` | A package or rule everywhere — `pkg:npm/lodash`, `codeql:js/sql-injection` |

Resolution runs most-specific first, so a per-finding exception overrides a
CVE-wide acceptance.

A bulk action across mixed CVEs at `vuln` scope creates **one decision per CVE**, not one
giant decision. That keeps the register reviewable and lets a single CVE be revoked
later without unpicking everything else.

Before you commit, the form tells you exactly how far the decision reaches:

> This creates **2** decisions from **4** selected findings.
> **2 of them reach beyond what you selected.**
> · CVE-2024-3094 (all assets) — Covers all 47 open findings, and any reported later. That is 45 beyond your selection.

Bulk actions that quietly do more than you asked are how a register stops being
defensible. Better to say so up front.

Separately, an `adjudication_applications` table records exactly which findings existed
at the moment of the decision. Scope resolution is dynamic; that table is the evidence
of what was actually in front of the person who signed.

### Dispositions

The five from your existing framework, plus one factual correction that is deliberately
*not* a risk decision:

| Disposition | Effect |
|---|---|
| Fix immediately | Routes work. Takes effect immediately. |
| Complex resolution | Routes work. Takes effect immediately. |
| Developer review | Routes work. Takes effect immediately. |
| Accept risk | Needs approval + expiry. Drops the finding to P4, suppresses SLA. |
| Adjust risk | Needs approval + expiry. Overrides effective severity; original is kept and shown struck through. |
| False positive / not affected | Needs approval + expiry. |

### The approval gate

Risk decisions start as `pending_approval` and change nothing until someone on the
approver roster signs. Enforced:

- Justification of at least 40 characters (`RISKDESK_...` policy, tunable in `app/config.py`)
- An expiry date — open-ended acceptances are refused
- An approver who is **not** the requester, and who is on the roster

Routing decisions skip the gate; they move work rather than change posture.

### Expiry is automatic

When an acceptance passes its expiry it lapses on its own, effective severity reverts,
and the finding returns to the backlog at full weight. Put this on a nightly schedule:

```
python -m app.cli expire
```

**Windows Task Scheduler.** Run this once from an elevated PowerShell, adjusting the
path — `-WorkingDirectory` matters, since the app resolves `.env` and `data\` relative
to the project root:

```powershell
$root = "C:\Tools\riskdesk"
$action = New-ScheduledTaskAction `
    -Execute "$root\.venv\Scripts\python.exe" `
    -Argument "-m app.cli expire" `
    -WorkingDirectory $root
$trigger = New-ScheduledTaskTrigger -Daily -At 2am
Register-ScheduledTask -TaskName "RiskDesk expire decisions" `
    -Action $action -Trigger $trigger -Description `
    "Lapses vulnerability risk acceptances past their expiry date."
```

Check it ran with `Get-ScheduledTaskInfo -TaskName "RiskDesk expire decisions"`. On
macOS or Linux the equivalent is a cron entry calling the same command.

It also runs at application startup, so the scheduled task is about catching lapses on
days nobody opens the app. Renewing creates a **new** record and expires the
old one, so the history of what was accepted, when, and on what argument survives
rather than being edited over.

---

## Scoring, and what it does not know

Priority score is severity baseline + CISA KEV + EPSS + internet exposure + environment
+ data classification + fix availability, capped at 100.

Three of those inputs are not currently wired to a feed in your environment. Rather than
defaulting them — which would produce a confident-looking number built on assumptions —
the engine reports them as **not applied**. The detail panel renders every factor as a
ledger line, greys the unapplied ones, and appends:

> **This score is incomplete.** Internet-facing status, Environment tag, Data
> classification are not available for this asset, so those factors contributed nothing.
> Treat the number as a floor, not a measurement.

Where a source *does* assert one of these, it is used: Wiz's exposure flags populate
`internet_facing`, and environment is read from cloud tags and Falcon host groups only
when a tag says so explicitly. Wiz-sourced EPSS lands on the shared vulnerability record,
so it flows through to Falcon findings for the same CVE automatically.

Wiring EPSS and an asset classification feed would sharpen the two adjudication buckets
that currently need the most human judgment. The schema has the columns; they just need
a populator.

Remediation SLAs come from `app/config.py` — 15/30/90/180 days by severity, with KEV
capped at 14. Change those to whatever your executive sponsor signs off on.

---

## Command line

```
python -m app.cli init                    create the database
python -m app.cli check                   test every configured connector
python -m app.cli sync wiz                pull from one source
python -m app.cli sync all                pull from every configured source
python -m app.cli sync falcon --limit 500 stop after N findings (useful for a first look)
python -m app.cli demo                    load synthetic data for all three
python -m app.cli expire                  lapse decisions past their expiry (the server also does this hourly)
python -m app.cli reset --demo-only       clear synthetic rows only
python -m app.cli reset                   clear everything (asks for confirmation)
python -m app.cli wiz-introspect --type VulnerabilityFinding
python -m app.cli serve --port 8080
```

Syncs are idempotent, keyed on `(source, source_finding_id)`. Findings a source stops
reporting are **not** deleted — they are marked `stale` after a grace window
(`RISKDESK_STALE_DAYS`, default 14) and keep their decision history. "This finding
disappeared" and "someone accepted this risk" are different facts and an auditor will
eventually ask about both.

### Finding lifecycle

```
open ──source reports resolved──▶ fixed ──┐
  │                                       ├──person confirms──▶ verified_fixed
  └──unreported for the grace window──▶ stale ┘
any closed state ──source reports it again──▶ open (counted as a reopen)
```

- `fixed` and `stale` both close the finding (`closed_at` is set) and stop the SLA
  clock; both can be verified from the finding drawer.
- The grace window is measured from the last sync that received the finding
  (`last_synced_at`), not the source's own "updated" timestamp, which can be months old
  on a live alert.
- Stale marking is skipped for `--limit` syncs, demo syncs, and any alert family the
  connector could not read that run (e.g. a missing GitHub code-scanning permission), so
  a partial pull never closes a backlog.
- Every transition is recorded. `GET /api/findings/{id}/timeline` merges it with the
  decisions, exceptions and tickets that touched the finding;
  `GET /api/lifecycle/metrics?days=90` reports opened vs closed, time to close,
  closed-within-SLA, reopens, the verification backlog, and tickets whose state disagrees
  with their findings. Both appear in the UI (finding drawer, Activity tab).
- New columns are added to an existing database automatically at startup.

### Historical remediation

The connectors each run a second **resolved-pass** that pulls recently-closed
items so remediation history is captured with the source's own fix date:

| Source | What's pulled | Window | Disable |
|---|---|---|---|
| Wiz | `vulnerabilityFindings` with `status: RESOLVED` and `resolvedAt` in window | `WIZ_RESOLVED_WINDOW_DAYS` (default 180) | set to 0 |
| GitHub | `state=fixed` and `state=dismissed` across all three alert families | `GITHUB_RESOLVED_WINDOW_DAYS` (default 180) | set to 0 |
| Falcon Spotlight | `status:'closed'+closed_timestamp:>'now-Nd'` | `FALCON_RESOLVED_WINDOW_DAYS` (default 180) | set to 0 |
| Falcon EDR (Alerts v2) | `/alerts/queries/alerts/v2` + hydrate; open and closed in window | `FALCON_DETECTIONS_WINDOW_DAYS` (default 90) | `FALCON_DETECTIONS=0` |

GitHub `dismissed` alerts are recorded as `suppressed_at_source`, not `fixed`,
so they don't inflate remediation metrics. Falcon detections land in the
`detection` category — same lifecycle treatment as a vulnerability, so the
same reports apply.

**Backload prior history** with `POST /api/findings/import-historical` or the
"Historical remediation import" panel on the Sources tab. The CSV columns are
`canonical_id, source, asset, severity, first_detected, closed_at, status`
(plus `cve_id, title, category, component, component_version,
source_finding_id, asset_type` optional). Re-importing is idempotent.

**Report on it**:

| Endpoint | What it returns |
|---|---|
| `GET /api/lifecycle/trends?days=365&granularity=week` | Opened / closed / backlog time series. `granularity` is `day`, `week`, `month`, or `quarter`. |
| `GET /api/findings/remediated?start=&end=&severity=&source=&category=` | Paginated remediation history with per-row time-to-close and SLA attainment, plus by-severity / by-source / by-month aggregates. |
| `GET /api/export/remediated.csv?...` | Same scope, CSV for audits. |
| `GET /api/lifecycle/metrics?days=90` | Rolling snapshot: MTTR, closed-within-SLA %, reopens, verification backlog, ticket drift. |

The Activity tab in the UI renders the trend chart (weekly / monthly bars with
a backlog line) and the remediated-findings table with the same filters.

---

## Exports

| Endpoint | Contents |
|---|---|
| `/api/export/register.csv` | Every decision: disposition, state, scope, justification, requester, approver, dates |
| `/api/export/findings.csv?…` | Current filter, with base vs. effective severity, priority, SLA, and the governing decision |

Both are linked from the UI. The register export is the artifact for an auditor or a
steering deck.

---

## Architecture

```
app/
  enums.py         controlled vocabularies, severity normalisation
  models.py        Asset / Vuln / Finding / Adjudication / AuditEvent / SyncRun
  risk.py          scope resolution, effective severity, priority scoring
  adjudication.py  scope planning, policy gate, approve / revoke / renew / expire
  queries.py       filtering, sorting, facets
  sync.py          the only thing that writes connector output to the database
  main.py          FastAPI routes
  cli.py           command line
  connectors/
    base.py        NormalizedRecord — the contract every source maps into
    wiz.py  falcon.py  github.py  demo.py
  static/          index.html, styles.css, app.js — plain JS, no build step
```

Three layers are kept deliberately separate: **Asset** (the thing that has the problem),
**Vuln** (the problem), **Finding** (one instance of a problem on a thing, per tool).
A CVE is one row no matter how many tools report it, which is what makes a CVE-scoped
decision cover Wiz and Falcon at once.

Connectors are pure read-and-map — they never touch the database, so a new source is one
file implementing `fetch()`, and any connector can be tested against a saved API payload.

The front end is vanilla JS on purpose. No build step, no toolchain to keep current, and
nothing to relearn when you come back to it in eight months.

---

## Before this leaves your desk

**There is no authentication.** The "acting as" dropdown is a local convenience for
trying the approval workflow, not an identity system — anyone who can reach the port can
act as anyone on the roster. That is fine on `127.0.0.1`. It is not fine on a shared
host. Put it behind your IdP (or at minimum a reverse proxy with SSO) before anyone
other than you uses it, and replace `current_user()` in `app/main.py` with the header
your proxy sets.

**Credentials live in `.env`, which is gitignored.** The service accounts here can read
your entire vulnerability posture; treat the file accordingly.

**On Windows, the database lives in `data\riskdesk.db`** next to the code. That file is
the register — every decision, justification and approval. Back it up, or point
`RISKDESK_DB_URL` at somewhere that already is. It is excluded from git via `.gitignore`.

**SQLite is the right call at your scale** (tens of thousands of findings, hundreds of
decisions) and WAL mode is on. If this grows to multiple concurrent users, point
`RISKDESK_DB_URL` at Postgres — the models are plain SQLAlchemy and nothing else changes.
