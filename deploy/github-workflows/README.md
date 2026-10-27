# Org-wide security pipeline

Run the same security checks on every repo in your GitHub org, with results
flowing into both each repo's Security tab **and** RiskDesk.

## What runs

| Scanner | Catches | Languages |
|---|---|---|
| **gitleaks** | Secrets in source and git history | any |
| **semgrep** (p/default + security-audit + OWASP top 10) | SAST patterns | polyglot |
| **trivy** fs scan | Vulnerable deps, IaC misconfigs, container issues | polyglot |
| **CodeQL** (security-extended) | Deep SAST | python, js/ts, java, go, c/c++, c#, ruby, swift, kotlin |
| **ruff** | Python lint / bug patterns | python |
| **bandit** | Python SAST | python |
| **pip-audit** | Python dep CVEs | python |

All of them emit SARIF uploaded to GitHub Code Scanning. CodeQL and the
Python extras only run when the language or manifest is actually present in
the repo, so a Go-only repo doesn't waste minutes on `pip-audit`.

## Why upload to GHAS

Two wins:
1. Findings show up in each repo's native **Security** tab with the usual
   dismiss / won't-fix / fixed workflow.
2. RiskDesk's GitHub connector pulls them automatically as code-scanning
   alerts. You don't need a second ingestion path -- the aggregation
   architecture stays "GHAS is the pipe, RiskDesk is downstream."

## How to roll it out

Pick one of three patterns depending on your org's plan and tolerance for
drift.

### Pattern 1 - Org-level Required Workflow (strongest)

GHAS feature. One workflow forcibly applies to every selected repo and
cannot be bypassed on PRs or disabled by repo owners.

1. Create a repo in your org called `security-pipeline` (or re-use an
   existing admin repo).
2. Commit `security.yml` from this folder to
   `.github/workflows/required-security.yml` in that repo.
3. **Org Settings** -> **Code security** -> **Required workflows** -> **Add
   required workflow**:
   - Source: `your-org/security-pipeline`
   - Workflow path: `.github/workflows/required-security.yml`
   - Branch: `main`
   - Apply to: **All repositories** (or a selected set)

Done. Pushes and PRs across every targeted repo now run the pipeline.

Updates to the file in the source repo propagate immediately. Branch
protection can require this check -- no PR merges until it passes.

### Pattern 2 - Reusable workflow + per-repo caller

Works on every GitHub plan including free.

1. Create a repo literally named `.github` in your org (GitHub treats it
   specially as the org's defaults repo).
2. Commit `security.yml` to `<your-org>/.github/.github/workflows/security.yml`
   on the `main` branch.
3. In each repo that should run it, commit
   `.github/workflows/security.yml` with the contents of
   `call-security.yml` from this folder (edit `<your-org>`).

To roll the caller workflow out across many repos at once:

```sh
# Install multi-gitter: https://github.com/lindell/multi-gitter
multi-gitter run \
  --token "$GITHUB_PAT" \
  --org your-org \
  --repo-include "." \
  --author-name "Security Bot" \
  --author-email "security-bot@your-org" \
  --commit-message "add org security workflow" \
  --pr-title "Add org security pipeline" \
  --branch "security-workflow" \
  'bash -c "mkdir -p .github/workflows && cp '"$PWD"'/call-security.yml .github/workflows/security.yml && sed -i s/<your-org>/your-org/ .github/workflows/security.yml"'
```

Review and merge the PRs it opens. Branch protection on each repo can
require the "Security / summary" check.

### Pattern 3 - Copy per repo

Just copy `security.yml` into every repo's `.github/workflows/` directory.
No reusable layer, so you have to update N copies when something changes.
Only pick this if your org can't use pattern 1 or 2 for some reason.

## Branch protection

For either pattern, protect `main` and require the status check **"Security
pipeline / summary"**. The `summary` job rolls up every scanner into one
check, so repo rulesets only need to track one name.

## Tuning

- `severity-threshold`: `critical` | `high` (default) | `medium` | `low`.
  Lower values fail more PRs. Start with `high`, tighten over time.
- `skip-codeql: true`: skip the CodeQL job if the repo already runs it in a
  sibling workflow -- the ones GitHub ships by default or an existing custom
  one.
- Add org-level **ignore files** for scanners that need them, e.g. a shared
  `.gitleaks.toml` or `.semgrepignore`, by committing them to the `.github`
  repo and `uses: actions/checkout@v4; cp /github/workspace/.github/.gitleaks.toml .`
  in the workflow if you need per-repo overrides.

## RiskDesk side

Once this is live and alerts are being created in each repo:

1. Confirm GHAS is on in each repo's **Settings -> Code security**:
   Dependabot alerts, Code scanning alerts, Secret scanning alerts.
2. Create a fine-grained PAT with **Dependabot alerts: Read**, **Code
   scanning alerts: Read**, **Secret scanning alerts: Read**, **Metadata:
   Read** scoped to the whole org (or a selected set of repos).
3. In RiskDesk: `/etc/riskdesk/env` -> set `GITHUB_TOKEN` and `GITHUB_ORG`,
   restart.
4. Sources tab -> GitHub Advanced Security Diagnostics -> Run Test Suite.
5. Trigger a sync or set a daily schedule.

Semgrep / trivy / ruff / bandit findings all surface as **code_scanning**
alerts in GHAS, so they appear as `category=code_scanning` in RiskDesk and
flow through the same lifecycle, SLA and remediation reporting that
Dependabot alerts do.
