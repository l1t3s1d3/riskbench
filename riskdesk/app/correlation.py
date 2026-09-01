"""Asset correlation across sources.

The problem: Falcon knows a host as PLI-NYC-WS003 with sensor AID abc123;
Wiz knows the same VM as a cloud resource with ID wiz-456. The Findings tab
counts both, and a CVE-scoped decision covers both, but there is no way to
say "show me everything about this one device."

This module provides:
  1. Auto-correlation rules (hostname match, IP match)
  2. Manual correlation (admin says "these asset IDs are the same device")
  3. A canonical view that rolls up findings from all sources for one device
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict

from sqlalchemy import func, select

from .models import Asset, AssetCorrelation, Finding, utcnow

log = logging.getLogger(__name__)


def auto_correlate(db, method: str = "hostname", dry_run: bool = False) -> dict:
    """Group assets across sources by a shared key.

    Methods:
      hostname  case-insensitive name match (most reliable for endpoints)
      ip        match on ip_address (less stable, but catches cloud VMs)
    """
    assets = db.execute(select(Asset)).scalars().all()

    groups: dict[str, list[int]] = defaultdict(list)
    for a in assets:
        if method == "hostname":
            key = (a.name or "").strip().lower()
        elif method == "ip":
            key = (a.ip_address or "").strip()
        else:
            raise ValueError(f"Unknown method: {method}")
        if key:
            groups[key].append(a.id)

    # Only groups with assets from 2+ sources are correlations
    multi = {}
    for key, ids in groups.items():
        sources = set()
        for aid in ids:
            a = next((x for x in assets if x.id == aid), None)
            if a:
                sources.add(a.source)
        if len(sources) > 1:
            multi[key] = ids

    if dry_run:
        return {
            "method": method,
            "candidates": len(multi),
            "sample": {k: v for k, v in list(multi.items())[:20]},
        }

    created = 0
    for canonical_name, asset_ids in multi.items():
        existing = db.execute(
            select(AssetCorrelation).where(AssetCorrelation.canonical_name == canonical_name)
        ).scalar_one_or_none()
        if existing:
            # Merge new IDs
            current = set(existing.asset_ids or [])
            current.update(asset_ids)
            existing.asset_ids = list(current)
            existing.match_method = method
        else:
            db.add(AssetCorrelation(
                canonical_name=canonical_name,
                asset_ids=asset_ids,
                match_method=method,
            ))
            created += 1

    db.commit()
    return {"method": method, "created": created, "total_groups": len(multi)}


def create_manual_correlation(
    db, canonical_name: str, asset_ids: list[int],
    actor: str, environment: str | None = None,
    data_classification: str | None = None,
    owner: str | None = None, notes: str | None = None,
) -> AssetCorrelation:
    """Admin manually says these assets are the same device."""
    existing = db.execute(
        select(AssetCorrelation).where(AssetCorrelation.canonical_name == canonical_name)
    ).scalar_one_or_none()
    if existing:
        current = set(existing.asset_ids or [])
        current.update(asset_ids)
        existing.asset_ids = list(current)
        existing.match_method = "manual"
        if environment:
            existing.environment = environment
        if data_classification:
            existing.data_classification = data_classification
        if owner:
            existing.owner = owner
        if notes:
            existing.notes = notes
        db.commit()
        return existing

    corr = AssetCorrelation(
        canonical_name=canonical_name,
        asset_ids=asset_ids,
        match_method="manual",
        environment=environment,
        data_classification=data_classification,
        owner=owner,
        notes=notes,
        created_by=actor,
    )
    db.add(corr)
    db.commit()
    return corr


def get_correlations(db, q: str | None = None) -> list[dict]:
    stmt = select(AssetCorrelation).order_by(AssetCorrelation.canonical_name)
    if q:
        stmt = stmt.where(AssetCorrelation.canonical_name.ilike(f"%{q}%"))
    rows = db.execute(stmt).scalars().all()

    result = []
    for corr in rows:
        asset_ids = corr.asset_ids or []
        assets_detail = []
        finding_count = 0
        sources = set()
        for aid in asset_ids:
            a = db.get(Asset, aid)
            if not a:
                continue
            fc = db.execute(
                select(func.count()).select_from(Finding)
                .where(Finding.asset_id == aid, Finding.status == "open")
            ).scalar() or 0
            finding_count += fc
            sources.add(a.source)
            assets_detail.append({
                "id": a.id, "source": a.source, "name": a.name,
                "type": a.asset_type, "ip": a.ip_address,
                "os": a.os_name, "cloud_provider": a.cloud_provider,
                "findings": fc,
            })
        result.append({
            "id": corr.id,
            "canonical_name": corr.canonical_name,
            "match_method": corr.match_method,
            "environment": corr.environment,
            "data_classification": corr.data_classification,
            "owner": corr.owner,
            "notes": corr.notes,
            "sources": list(sources),
            "asset_count": len(assets_detail),
            "finding_count": finding_count,
            "assets": assets_detail,
        })
    return result


def get_correlation_detail(db, corr_id: int) -> dict | None:
    corr = db.get(AssetCorrelation, corr_id)
    if not corr:
        return None
    base = get_correlations(db)
    match = [c for c in base if c["id"] == corr_id]
    return match[0] if match else None


def get_deduplicated_counts(db) -> dict:
    """Deduplicated finding count using correlations."""
    total_raw = db.execute(
        select(func.count()).select_from(Finding).where(Finding.status == "open")
    ).scalar() or 0

    correlations = db.execute(select(AssetCorrelation)).scalars().all()
    # For correlated assets, count unique (vuln_id) across the group
    dedup_savings = 0
    for corr in correlations:
        if not corr.asset_ids or len(corr.asset_ids) < 2:
            continue
        # Count findings per vuln across the correlated assets
        from sqlalchemy import distinct
        unique_vulns = db.execute(
            select(func.count(distinct(Finding.vuln_id)))
            .where(Finding.asset_id.in_(corr.asset_ids), Finding.status == "open")
        ).scalar() or 0
        total_in_group = db.execute(
            select(func.count())
            .select_from(Finding)
            .where(Finding.asset_id.in_(corr.asset_ids), Finding.status == "open")
        ).scalar() or 0
        dedup_savings += (total_in_group - unique_vulns)

    return {
        "raw_count": total_raw,
        "deduplicated_count": total_raw - dedup_savings,
        "duplicate_findings": dedup_savings,
        "correlation_groups": len(correlations),
    }
