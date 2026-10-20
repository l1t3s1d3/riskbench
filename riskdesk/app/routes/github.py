"""GitHub Advanced Security routes.

Diagnostic, testing, and security-overview endpoints for GHAS.  The sync
itself stays in sync.py; this module adds the tooling to troubleshoot it.
"""
from __future__ import annotations

import time
import traceback

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from ..api_queries import GITHUB_ALERT_FAMILIES
from ..config import reload_settings, settings
from ..connectors.github import GitHubConnector
from ..db import get_session
from .deps import current_user

router = APIRouter(prefix="/api/github", tags=["github"])


def _connector() -> GitHubConnector:
    reload_settings()
    return GitHubConnector()


# ---------------------------------------------------------------------------
#  Test suite — structured step-by-step diagnostic
# ---------------------------------------------------------------------------

@router.post("/test-suite")
def github_test_suite(request: Request):
    """Run a structured diagnostic against the GitHub API.

    Steps: config -> auth -> org access -> each alert family (dependabot,
    code scanning, secret scanning) -> repo listing -> per-repo probe.
    """
    c = _connector()
    steps: list[dict] = []

    def _step(name: str, description: str, fn):
        t0 = time.time()
        try:
            result = fn()
            elapsed = round(time.time() - t0, 2)
            steps.append({
                "step": name, "description": description,
                "status": "pass", "elapsed_s": elapsed, **result,
            })
            return True
        except Exception as exc:
            elapsed = round(time.time() - t0, 2)
            steps.append({
                "step": name, "description": description,
                "status": "fail", "elapsed_s": elapsed,
                "error": str(exc), "traceback": traceback.format_exc(),
            })
            return False

    def _skip(name: str, description: str, reason: str):
        steps.append({
            "step": name, "description": description,
            "status": "skip", "reason": reason,
        })

    # Step 1: Config
    def check_config():
        cfg = c.cfg
        missing = []
        if not cfg.token:
            missing.append("GITHUB_TOKEN")
        if not cfg.org:
            missing.append("GITHUB_ORG")
        if missing:
            raise RuntimeError(
                f"Missing required settings: {', '.join(missing)}. "
                "Set GITHUB_TOKEN and GITHUB_ORG in your .env file."
            )
        return {
            "config": {
                "org": cfg.org,
                "api_url": cfg.api_url,
                "token_prefix": cfg.token[:8] + "..." if len(cfg.token) > 8 else "(set)",
                "include_dependabot": cfg.include_dependabot,
                "include_code_scanning": cfg.include_code_scanning,
                "include_secret_scanning": cfg.include_secret_scanning,
            },
        }

    remaining_steps = [
        ("auth", "Authenticate and check token scopes"),
        ("org_access", "Verify organization access"),
        ("dependabot", "Probe Dependabot alerts"),
        ("code_scanning", "Probe code scanning alerts"),
        ("secret_scanning", "Probe secret scanning alerts"),
        ("repos", "List repositories with security features"),
        ("sample", "Fetch and map a sample alert through the sync pipeline"),
    ]

    ok = _step("config", "Verify environment variables are set", check_config)
    if not ok:
        for s in remaining_steps:
            _skip(s[0], s[1], "Configuration incomplete")
        return _summary(steps)

    # Step 2: Auth — check token validity and scopes
    def check_auth():
        import httpx
        r = httpx.get(
            f"{c.cfg.api_url}/user",
            headers=c._headers(), timeout=30,
        )
        if r.status_code == 401:
            raise RuntimeError(
                "Token rejected (401). Check that GITHUB_TOKEN is valid and not expired. "
                "Fine-grained tokens need: Dependabot alerts, Code scanning alerts, "
                "Secret scanning alerts (read). Classic PATs need: security_events, repo."
            )
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub returned {r.status_code}: {r.text[:200]}")
        user = r.json()
        scopes = r.headers.get("x-oauth-scopes", "")
        return {
            "user": user.get("login"),
            "token_type": "fine-grained" if not scopes else "classic",
            "scopes": scopes or "(fine-grained PAT — scopes listed on creation page)",
            "rate_limit": r.headers.get("x-ratelimit-remaining"),
        }

    remaining_steps = remaining_steps[1:]
    ok = _step("auth", "Authenticate and check token scopes", check_auth)
    if not ok:
        for s in remaining_steps:
            _skip(s[0], s[1], "Authentication failed")
        return _summary(steps)

    # Step 3: Org access
    def check_org():
        import httpx
        r = httpx.get(
            f"{c.cfg.api_url}/orgs/{c.cfg.org}",
            headers=c._headers(), timeout=30,
        )
        if r.status_code == 404:
            raise RuntimeError(
                f"Organization '{c.cfg.org}' not found. Either the org name is wrong, "
                "or the token does not have access to it. For fine-grained PATs, the "
                "token must be created by or approved for this org."
            )
        if r.status_code >= 400:
            raise RuntimeError(f"GitHub returned {r.status_code}: {r.text[:200]}")
        org = r.json()
        return {
            "org_name": org.get("login"),
            "org_display": org.get("name"),
            "plan": (org.get("plan") or {}).get("name"),
            "public_repos": org.get("public_repos"),
            "total_private_repos": org.get("total_private_repos"),
            "ghas_enabled": org.get("advanced_security_enabled_for_new_repositories"),
        }

    remaining_steps = remaining_steps[1:]
    ok = _step("org_access", "Verify organization access", check_org)
    if not ok:
        for s in remaining_steps:
            _skip(s[0], s[1], "Organization access failed")
        return _summary(steps)

    # Steps 4-6: Probe each alert family
    def _probe_family(family):
        def _inner():
            import httpx
            path = family["org_path"].format(org=c.cfg.org)
            r = httpx.get(
                f"{c.cfg.api_url}{path}",
                params={"per_page": 3, "state": "open"},
                headers=c._headers(), timeout=30,
            )
            if r.status_code == 404:
                raise RuntimeError(
                    f"404 — {family['label']} alerts not accessible. "
                    f"Required scopes: {family['scopes']}. "
                    "Also check that the feature is enabled in the org security settings."
                )
            if r.status_code == 403:
                msg = (r.json() or {}).get("message", "")
                raise RuntimeError(
                    f"403 Forbidden — {msg}. The token may lack the required scope: "
                    f"{family['scopes']}"
                )
            if r.status_code >= 400:
                raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
            alerts = r.json()
            count = len(alerts)
            sample = alerts[0] if alerts else None

            summary_data = {"alerts_in_page": count}
            if sample:
                summary_data["sample"] = _alert_summary(family["name"], sample)
            else:
                summary_data["note"] = f"No open {family['label'].lower()} alerts found."
            return summary_data
        return _inner

    for family in GITHUB_ALERT_FAMILIES:
        _step(family["name"], f"Probe {family['label']} alerts", _probe_family(family))

    # Step 7: List repos with security features
    def check_repos():
        import httpx
        r = httpx.get(
            f"{c.cfg.api_url}/orgs/{c.cfg.org}/repos",
            params={"per_page": 10, "sort": "pushed", "direction": "desc", "type": "all"},
            headers=c._headers(), timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        repos = r.json()
        repo_list = []
        for repo in repos[:10]:
            sec = repo.get("security_and_analysis") or {}
            repo_list.append({
                "name": repo.get("full_name"),
                "private": repo.get("private"),
                "advanced_security": (sec.get("advanced_security") or {}).get("status"),
                "secret_scanning": (sec.get("secret_scanning") or {}).get("status"),
                "secret_scanning_push_protection": (
                    sec.get("secret_scanning_push_protection") or {}
                ).get("status"),
                "dependabot_alerts": (sec.get("dependabot_security_updates") or {}).get("status"),
            })
        return {
            "total_fetched": len(repos),
            "repos": repo_list,
        }

    _step("repos", "List repositories with security features", check_repos)

    # Step 8: Fetch and map a sample through the full pipeline
    def sample_alert():
        import httpx
        for family in GITHUB_ALERT_FAMILIES:
            path = family["org_path"].format(org=c.cfg.org)
            r = httpx.get(
                f"{c.cfg.api_url}{path}",
                params={"per_page": 1, "state": "open"},
                headers=c._headers(), timeout=30,
            )
            if r.status_code < 400:
                alerts = r.json()
                if alerts:
                    item = alerts[0]
                    mapper = {
                        "dependabot": c._map_dependabot,
                        "code_scanning": c._map_code_scanning,
                        "secret_scanning": c._map_secret_scanning,
                    }.get(family["name"])
                    if mapper:
                        rec = mapper(item)
                        if rec:
                            return {
                                "family": family["label"],
                                "raw_alert": item,
                                "mapped": {
                                    "source_finding_id": rec.source_finding_id,
                                    "category": rec.category,
                                    "severity": rec.severity,
                                    "status": rec.status,
                                    "asset_name": rec.asset.name,
                                    "vuln_title": rec.vuln.title,
                                    "canonical_id": rec.vuln.canonical_id,
                                    "component": rec.component,
                                    "fix_available": rec.fix_available,
                                },
                            }
        raise RuntimeError(
            "No open alerts found across any family. The org may have no security "
            "alerts, or the token may lack access."
        )

    _step("sample", "Fetch and map a sample alert through the sync pipeline", sample_alert)

    return _summary(steps)


def _summary(steps):
    passed = sum(1 for s in steps if s["status"] == "pass")
    failed = sum(1 for s in steps if s["status"] == "fail")
    skipped = sum(1 for s in steps if s["status"] == "skip")
    return {"steps": steps, "passed": passed, "failed": failed, "skipped": skipped}


def _alert_summary(family: str, alert: dict) -> dict:
    if family == "dependabot":
        adv = alert.get("security_advisory") or {}
        return {
            "number": alert.get("number"),
            "severity": adv.get("severity"),
            "cve": adv.get("cve_id"),
            "summary": (adv.get("summary") or "")[:120],
            "repo": (alert.get("repository") or {}).get("full_name"),
        }
    if family == "code_scanning":
        rule = alert.get("rule") or {}
        return {
            "number": alert.get("number"),
            "severity": rule.get("security_severity_level") or rule.get("severity"),
            "rule_id": rule.get("id"),
            "description": (rule.get("description") or "")[:120],
            "tool": (alert.get("tool") or {}).get("name"),
            "repo": (alert.get("repository") or {}).get("full_name"),
        }
    if family == "secret_scanning":
        return {
            "number": alert.get("number"),
            "secret_type": alert.get("secret_type_display_name") or alert.get("secret_type"),
            "validity": alert.get("validity"),
            "push_protection_bypassed": alert.get("push_protection_bypassed"),
            "repo": (alert.get("repository") or {}).get("full_name"),
        }
    return {"number": alert.get("number")}


# ---------------------------------------------------------------------------
#  Security overview — org-wide GHAS coverage and alert counts
# ---------------------------------------------------------------------------

@router.get("/security-overview")
def github_security_overview(request: Request):
    """Org-wide security overview: GHAS enablement, alert counts by family,
    top repos by alert count, and severity breakdown."""
    c = _connector()
    if not c.configured():
        return {"ok": False, "error": "GitHub connector is not configured."}

    import httpx

    try:
        c._headers()  # validates token
    except Exception as exc:
        return {"ok": False, "error": f"Authentication failed: {exc}"}

    overview: dict = {"ok": True, "org": c.cfg.org}

    # Alert counts per family
    families = {}
    for family in GITHUB_ALERT_FAMILIES:
        path = family["org_path"].format(org=c.cfg.org)
        for state in ("open", "fixed"):
            try:
                r = httpx.get(
                    f"{c.cfg.api_url}{path}",
                    params={"per_page": 1, "state": state},
                    headers=c._headers(), timeout=30,
                )
                if r.status_code < 400:
                    # Use the Link header or list length to estimate total
                    items = r.json()
                    count = len(items)
                    # GitHub doesn't return total count directly; for a quick
                    # overview we report "at least N" based on the first page.
                    # A count of 1 with a Link header means more exist.
                    link = r.headers.get("Link", "")
                    has_more = 'rel="next"' in link
                    families.setdefault(family["name"], {})[state] = {
                        "count": count,
                        "has_more": has_more,
                    }
                else:
                    families.setdefault(family["name"], {})[state] = {
                        "error": f"HTTP {r.status_code}",
                    }
            except Exception as exc:
                families.setdefault(family["name"], {})[state] = {"error": str(exc)}

    overview["families"] = families

    # Severity breakdown for open alerts (dependabot has severity on the advisory)
    severity_counts: dict[str, int] = {}
    for sev in ("critical", "high", "medium", "low"):
        try:
            r = httpx.get(
                f"{c.cfg.api_url}/orgs/{c.cfg.org}/dependabot/alerts",
                params={"per_page": 1, "state": "open", "severity": sev},
                headers=c._headers(), timeout=15,
            )
            if r.status_code < 400:
                items = r.json()
                link = r.headers.get("Link", "")
                severity_counts[sev] = len(items)
                if 'rel="next"' in link:
                    severity_counts[sev] = f"{len(items)}+"
            else:
                severity_counts[sev] = f"error:{r.status_code}"
        except Exception:
            severity_counts[sev] = "error"
    overview["dependabot_by_severity"] = severity_counts

    # Top repos by recent alerts
    top_repos: dict[str, dict] = {}
    for family in GITHUB_ALERT_FAMILIES:
        path = family["org_path"].format(org=c.cfg.org)
        try:
            r = httpx.get(
                f"{c.cfg.api_url}{path}",
                params={"per_page": 25, "state": "open", "sort": "updated", "direction": "desc"},
                headers=c._headers(), timeout=30,
            )
            if r.status_code < 400:
                for alert in r.json():
                    repo_name = (alert.get("repository") or {}).get("full_name", "unknown")
                    entry = top_repos.setdefault(repo_name, {
                        "repo": repo_name, "dependabot": 0,
                        "code_scanning": 0, "secret_scanning": 0,
                    })
                    entry[family["name"]] += 1
        except Exception:
            pass

    overview["top_repos"] = sorted(
        top_repos.values(),
        key=lambda r: r["dependabot"] + r["code_scanning"] + r["secret_scanning"],
        reverse=True,
    )[:15]

    return overview


# ---------------------------------------------------------------------------
#  Per-repo alert listing
# ---------------------------------------------------------------------------

@router.get("/repos/{owner}/{repo}/alerts")
def github_repo_alerts(
    owner: str, repo: str, request: Request,
    family: str = Query("dependabot", pattern="^(dependabot|code_scanning|secret_scanning)$"),
    state: str = Query("open", pattern="^(open|fixed|dismissed|auto_dismissed)$"),
    limit: int = Query(25, ge=1, le=100),
):
    """Fetch alerts for a specific repository."""
    c = _connector()
    if not c.configured():
        raise HTTPException(400, "GitHub connector is not configured.")

    import httpx

    family_info = next((f for f in GITHUB_ALERT_FAMILIES if f["name"] == family), None)
    if not family_info:
        raise HTTPException(400, f"Unknown alert family: {family}")

    path = family_info["repo_path"].format(owner=owner, repo=repo)
    try:
        r = httpx.get(
            f"{c.cfg.api_url}{path}",
            params={"per_page": limit, "state": state},
            headers=c._headers(), timeout=60,
        )
    except Exception as exc:
        raise HTTPException(502, f"GitHub API request failed: {exc}")

    if r.status_code == 404:
        raise HTTPException(404, f"Repository {owner}/{repo} not found or alerts not enabled.")
    if r.status_code == 403:
        raise HTTPException(403, f"Access denied: {(r.json() or {}).get('message', '')}")
    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"GitHub error: {r.text[:300]}")

    alerts = r.json()
    mapper = {
        "dependabot": c._map_dependabot,
        "code_scanning": c._map_code_scanning,
        "secret_scanning": c._map_secret_scanning,
    }.get(family)

    results = []
    for alert in alerts:
        summary = _alert_summary(family, alert)
        mapped = None
        map_error = None
        if mapper:
            try:
                rec = mapper(alert)
                if rec:
                    mapped = {
                        "canonical_id": rec.vuln.canonical_id,
                        "severity": rec.severity,
                        "category": rec.category,
                        "component": rec.component,
                        "fix_available": rec.fix_available,
                    }
            except Exception as exc:
                map_error = str(exc)
        results.append({**summary, "mapped": mapped, "mapping_error": map_error})

    return {
        "repo": f"{owner}/{repo}",
        "family": family,
        "state": state,
        "count": len(results),
        "alerts": results,
    }


# ---------------------------------------------------------------------------
#  Dry run — preview sync without writing to DB
# ---------------------------------------------------------------------------

@router.post("/dry-run")
def github_dry_run(request: Request, limit: int = Query(15, ge=1, le=50)):
    """Simulate a GitHub sync without writing to the database."""
    c = _connector()
    if not c.configured():
        return {"ok": False, "error": "GitHub connector is not configured."}

    try:
        # Validate auth
        import httpx
        r = httpx.get(f"{c.cfg.api_url}/user", headers=c._headers(), timeout=15)
        if r.status_code >= 400:
            return {"ok": False, "error": f"Auth failed: HTTP {r.status_code}"}
    except Exception as exc:
        return {"ok": False, "error": f"Auth failed: {exc}"}

    records = []
    errors = []
    by_family: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    seen = 0

    for family in GITHUB_ALERT_FAMILIES:
        flag = {
            "dependabot": c.cfg.include_dependabot,
            "code_scanning": c.cfg.include_code_scanning,
            "secret_scanning": c.cfg.include_secret_scanning,
        }.get(family["name"], True)
        if not flag:
            continue

        path = family["org_path"].format(org=c.cfg.org)
        mapper = {
            "dependabot": c._map_dependabot,
            "code_scanning": c._map_code_scanning,
            "secret_scanning": c._map_secret_scanning,
        }.get(family["name"])
        if not mapper:
            continue

        try:
            r = httpx.get(
                f"{c.cfg.api_url}{path}",
                params={"per_page": min(limit - seen, 25), "state": "open"},
                headers=c._headers(), timeout=60,
            )
            if r.status_code >= 400:
                errors.append({
                    "family": family["label"],
                    "error": f"HTTP {r.status_code}: {r.text[:200]}",
                })
                continue
            for alert in r.json():
                if seen >= limit:
                    break
                try:
                    rec = mapper(alert)
                    if rec:
                        records.append({
                            "source_finding_id": rec.source_finding_id,
                            "family": family["label"],
                            "category": rec.category,
                            "severity": rec.severity,
                            "status": rec.status,
                            "asset": rec.asset.name,
                            "vuln_title": rec.vuln.title,
                            "canonical_id": rec.vuln.canonical_id,
                            "component": rec.component,
                            "fix_available": rec.fix_available,
                            "fix_version": rec.fix_version,
                        })
                        by_family[family["label"]] = by_family.get(family["label"], 0) + 1
                        by_severity[rec.severity] = by_severity.get(rec.severity, 0) + 1
                        seen += 1
                except Exception as exc:
                    errors.append({
                        "family": family["label"],
                        "alert_number": alert.get("number"),
                        "error": str(exc),
                    })
        except Exception as exc:
            errors.append({"family": family["label"], "error": str(exc)})

    return {
        "ok": True,
        "total": len(records),
        "by_family": by_family,
        "by_severity": by_severity,
        "records": records,
        "errors": errors[:10],
    }


# ---------------------------------------------------------------------------
#  Direct API explorer — run arbitrary GitHub API calls
# ---------------------------------------------------------------------------

@router.post("/query")
async def github_api_query(request: Request):
    """Execute an arbitrary GitHub API call for debugging.

    Accepts: {"method": "GET", "path": "/orgs/myorg/dependabot/alerts", "params": {...}}
    """
    c = _connector()
    if not c.configured():
        return {"ok": False, "error": "GitHub connector is not configured."}

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    method = body.get("method", "GET").upper()
    if method not in ("GET", "HEAD"):
        raise HTTPException(400, "Only GET and HEAD methods are allowed for safety.")

    path = body.get("path", "").strip()
    if not path:
        raise HTTPException(400, "No path provided.")
    # Expand {org} placeholder
    path = path.replace("{org}", c.cfg.org)

    params = body.get("params") or {}

    import httpx
    t0 = time.time()
    try:
        url = f"{c.cfg.api_url}{path}" if path.startswith("/") else path
        r = httpx.request(method, url, params=params, headers=c._headers(), timeout=60)
        elapsed = round(time.time() - t0, 2)

        try:
            data = r.json()
        except Exception:
            data = r.text[:2000]

        return {
            "ok": r.status_code < 400,
            "status_code": r.status_code,
            "elapsed_s": elapsed,
            "rate_limit_remaining": r.headers.get("x-ratelimit-remaining"),
            "data": data,
            "headers": {
                "x-ratelimit-remaining": r.headers.get("x-ratelimit-remaining"),
                "x-ratelimit-limit": r.headers.get("x-ratelimit-limit"),
                "x-ratelimit-reset": r.headers.get("x-ratelimit-reset"),
                "link": r.headers.get("link"),
            },
        }
    except Exception as exc:
        return {
            "ok": False, "error": str(exc),
            "traceback": traceback.format_exc(),
        }


# ---------------------------------------------------------------------------
#  GHAS enablement status for org repos
# ---------------------------------------------------------------------------

@router.get("/repos")
def github_list_repos(
    request: Request,
    limit: int = Query(30, ge=1, le=100),
    sort: str = Query("pushed", pattern="^(pushed|full_name|created|updated)$"),
):
    """List org repos with their GHAS enablement status."""
    c = _connector()
    if not c.configured():
        raise HTTPException(400, "GitHub connector is not configured.")

    import httpx
    r = httpx.get(
        f"{c.cfg.api_url}/orgs/{c.cfg.org}/repos",
        params={"per_page": limit, "sort": sort, "direction": "desc", "type": "all"},
        headers=c._headers(), timeout=30,
    )
    if r.status_code >= 400:
        raise HTTPException(r.status_code, f"GitHub error: {r.text[:200]}")

    repos = []
    for repo in r.json():
        sec = repo.get("security_and_analysis") or {}
        repos.append({
            "full_name": repo.get("full_name"),
            "private": repo.get("private"),
            "archived": repo.get("archived"),
            "language": repo.get("language"),
            "pushed_at": repo.get("pushed_at"),
            "advanced_security": (sec.get("advanced_security") or {}).get("status"),
            "secret_scanning": (sec.get("secret_scanning") or {}).get("status"),
            "push_protection": (
                sec.get("secret_scanning_push_protection") or {}
            ).get("status"),
            "dependabot_updates": (
                sec.get("dependabot_security_updates") or {}
            ).get("status"),
            "html_url": repo.get("html_url"),
        })

    return {"org": c.cfg.org, "total": len(repos), "repos": repos}


# ---------------------------------------------------------------------------
#  Query templates — pre-built GitHub API call templates
# ---------------------------------------------------------------------------

@router.get("/query-templates")
def github_query_templates():
    """Return pre-built API call templates for GitHub Advanced Security troubleshooting."""
    return {"templates": [
        {
            "name": "dependabot_open",
            "label": "Open Dependabot alerts",
            "description": "All open dependency vulnerability alerts across the org.",
            "path": "/orgs/{org}/dependabot/alerts",
            "params": {"state": "open", "per_page": 10},
        },
        {
            "name": "dependabot_critical",
            "label": "Critical Dependabot alerts",
            "description": "Only critical-severity Dependabot alerts.",
            "path": "/orgs/{org}/dependabot/alerts",
            "params": {"state": "open", "severity": "critical", "per_page": 10},
        },
        {
            "name": "code_scanning_open",
            "label": "Open code scanning alerts",
            "description": "CodeQL and third-party SAST alerts across the org.",
            "path": "/orgs/{org}/code-scanning/alerts",
            "params": {"state": "open", "per_page": 10},
        },
        {
            "name": "code_scanning_errors",
            "label": "Code scanning errors / warnings",
            "description": "Code scanning alerts with error or warning severity.",
            "path": "/orgs/{org}/code-scanning/alerts",
            "params": {"state": "open", "severity": "error", "per_page": 10},
        },
        {
            "name": "secret_scanning_open",
            "label": "Open secret scanning alerts",
            "description": "Exposed credentials detected across the org.",
            "path": "/orgs/{org}/secret-scanning/alerts",
            "params": {"state": "open", "per_page": 10},
        },
        {
            "name": "secret_scanning_active",
            "label": "Active (verified) secrets",
            "description": "Secrets that GitHub verified are still valid/active.",
            "path": "/orgs/{org}/secret-scanning/alerts",
            "params": {"state": "open", "validity": "active", "per_page": 10},
        },
        {
            "name": "repos_list",
            "label": "Organization repositories",
            "description": "List repos sorted by most recently pushed.",
            "path": "/orgs/{org}/repos",
            "params": {"sort": "pushed", "direction": "desc", "per_page": 10, "type": "all"},
        },
        {
            "name": "rate_limit",
            "label": "Rate limit status",
            "description": "Check your current API rate limit usage.",
            "path": "/rate_limit",
            "params": {},
        },
        {
            "name": "org_info",
            "label": "Organization details",
            "description": "Basic org info including plan and GHAS enablement.",
            "path": "/orgs/{org}",
            "params": {},
        },
    ]}
