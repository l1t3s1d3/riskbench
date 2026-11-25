"""Detailed per-bucket reporting.

The dashboard rollup gives bucket counts. This module answers the next
layer of questions decision-makers ask: who owns the oldest intake items,
which bucket 3 research is about to breach its 30-day cap, which CVEs
dominate bucket 1, how are the buckets trending week over week.

All reads go through the resolution map, so an item that is covered by
a scoped decision is reported under its governing disposition's bucket
even if its finding row has none of its own.
"""
from __future__ import annotations

import datetime as dt
from collections import Counter, defaultdict
from statistics import median

from sqlalchemy import func, select

from .buckets import BUCKETS, bucket_for_finding
from .enums import Disposition
from .models import Adjudication, Asset, AuditEvent, Finding, Vuln
from .queries import build_resolution_map


def _aware(d: dt.datetime | None) -> dt.datetime | None:
    if d is None:
        return None
    return d if d.tzinfo else d.replace(tzinfo=dt.timezone.utc)


def _age_days(anchor: dt.datetime | None, now: dt.datetime) -> float:
    anchor = _aware(anchor)
    if anchor is None:
        return 0.0
    return max(0.0, (now - anchor).total_seconds() / 86400.0)


def _anchor_for(bucket_num: int, adj, first_detected: dt.datetime | None) -> dt.datetime | None:
    """How age is measured in each bucket.

    Bucket 0 (intake) ages from the first-detection timestamp.
    All other buckets age from when the governing decision landed."""
    if bucket_num == 0 or adj is None:
        return first_detected
    return adj.decided_at or adj.requested_at or first_detected


def bucket_report(db, now: dt.datetime | None = None, top_n: int = 10) -> dict:
    """Full per-bucket breakdown for the executive report and the UI.

    Returns a dict with:
      * generated_at
      * buckets: one entry per bucket with count, age stats, top CVEs,
        top owners, over-cap findings, and a few oldest sample ids.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    resolution = build_resolution_map(db, now)

    rows = db.execute(
        select(Finding.id, Finding.severity, Finding.source, Finding.category,
               Finding.first_detected, Finding.asset_id, Vuln.kev, Vuln.canonical_id,
               Asset.owner, Asset.business_unit, Asset.environment, Asset.name)
        .join(Vuln, Finding.vuln_id == Vuln.id)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.status == "open")
    ).all()

    by_bucket: dict[int, list[dict]] = defaultdict(list)
    for (fid, sev, source, cat, first_detected, asset_id, kev, canonical,
         owner, bu, env, asset_name) in rows:
        adj = resolution.get(fid)
        bnum = bucket_for_finding(adj, now)
        anchor = _anchor_for(bnum, adj, first_detected)
        by_bucket[bnum].append({
            "finding_id": fid,
            "severity": sev,
            "source": source,
            "category": cat,
            "cve": canonical,
            "asset_name": asset_name,
            "owner": owner or "",
            "business_unit": bu or "",
            "environment": env or "",
            "age_days": _age_days(anchor, now),
            "kev": bool(kev),
        })

    bucket_entries: list[dict] = []
    for b in BUCKETS:
        items = by_bucket.get(b.number, [])
        ages = [i["age_days"] for i in items]
        over_cap = (
            sorted([i for i in items if i["age_days"] > b.max_days],
                   key=lambda x: x["age_days"], reverse=True)
            if b.max_days else []
        )
        oldest = sorted(items, key=lambda x: x["age_days"], reverse=True)[:top_n]
        cves = Counter(i["cve"] for i in items if i["cve"]).most_common(top_n)
        owners = Counter(i["owner"] for i in items if i["owner"]).most_common(top_n)
        severities = Counter(i["severity"] for i in items)
        kev_count = sum(1 for i in items if i["kev"])
        bucket_entries.append({
            "number": b.number,
            "title": b.title,
            "summary": b.summary,
            "max_days": b.max_days,
            "count": len(items),
            "kev": kev_count,
            "severities": dict(severities),
            "age": {
                "median_days": round(median(ages), 2) if ages else 0,
                "max_days": round(max(ages), 2) if ages else 0,
                "p90_days": _p90(ages),
            },
            "over_cap_count": len(over_cap),
            "over_cap": [{
                "finding_id": i["finding_id"], "age_days": round(i["age_days"], 1),
                "cve": i["cve"], "asset": i["asset_name"], "owner": i["owner"],
                "severity": i["severity"],
            } for i in over_cap[:top_n]],
            "oldest": [{
                "finding_id": i["finding_id"], "age_days": round(i["age_days"], 1),
                "cve": i["cve"], "asset": i["asset_name"], "severity": i["severity"],
            } for i in oldest],
            "top_cves": [{"cve": c, "count": n} for c, n in cves],
            "top_owners": [{"owner": o, "count": n} for o, n in owners],
        })

    return {
        "generated_at": now.isoformat(),
        "total_open_findings": sum(b["count"] for b in bucket_entries),
        "buckets": bucket_entries,
    }


def _p90(values: list[float]) -> float:
    if not values:
        return 0.0
    s = sorted(values)
    idx = max(0, int(round(0.9 * (len(s) - 1))))
    return round(s[idx], 2)


def bucket_trend(db, weeks: int = 8, now: dt.datetime | None = None) -> dict:
    """Weekly history of bucket counts, reconstructed from the audit log.

    Rolls through each decision audit event back `weeks` weeks and
    builds the bucket distribution as of each week boundary. Intake
    (bucket 0) is computed as the delta between current open findings
    and the sum of all other buckets at that point.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(weeks=weeks)
    # Walk currently-open findings; approximate historical bucket by the
    # decision in force at each week boundary.
    rows = db.execute(
        select(Finding.id, Finding.first_detected)
        .where(Finding.status == "open")
    ).all()
    if not rows:
        return {"weeks": [], "series": {str(b.number): [] for b in BUCKETS}}

    adjs = db.execute(select(Adjudication)).scalars().all()
    # For each finding, build an ordered timeline of (ts, bucket_number).
    # Historical reconstruction: an adjudication's effect begins at
    # decided_at (for routing / approved risk decisions) and ends at
    # expires_at or now, whichever is earlier.
    from .queries import build_resolution_map as _brm  # reuse scope precedence

    labels: list[str] = []
    series: dict[str, list[int]] = {str(b.number): [] for b in BUCKETS}
    for w in range(weeks, 0, -1):
        at = now - dt.timedelta(weeks=w - 1)
        labels.append(at.date().isoformat())
        # Expensive but bounded: snapshot bucket counts at `at`.
        snapshot = _brm(db, now=at)
        counts = {b.number: 0 for b in BUCKETS}
        for fid, first_detected in rows:
            if _aware(first_detected) and _aware(first_detected) > at:
                continue  # didn't exist yet
            counts[bucket_for_finding(snapshot.get(fid), at)] += 1
        for num, c in counts.items():
            series[str(num)].append(c)

    return {"weeks": labels, "series": series}
