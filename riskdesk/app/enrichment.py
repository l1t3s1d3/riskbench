"""EPSS and KEV feed enrichment.

Pulls two small, stable feeds and enriches the Vuln table:

  EPSS   https://epss.cyentia.com/epss_scores-YYYY-MM-DD.csv.gz
         ~250KB compressed. Updated daily by FIRST.org.

  KEV    https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
         ~300KB. Updated as CISA adds entries.

Both are public, unauthenticated, and permissively licensed for this use.
Run `python -m app.cli enrich` or call POST /api/enrich from the UI.
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import json
import logging

import httpx
from sqlalchemy import select, update

from .db import SessionLocal
from .models import AuditEvent, Vuln, utcnow

log = logging.getLogger(__name__)

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def enrich_epss(db=None, timeout: int = 60) -> dict:
    """Pull the current EPSS feed and update every matching CVE."""
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        log.info("Fetching EPSS feed from %s", EPSS_URL)
        r = httpx.get(EPSS_URL, timeout=timeout, follow_redirects=True)
        r.raise_for_status()
        raw = gzip.decompress(r.content).decode("utf-8")
        reader = csv.reader(io.StringIO(raw))

        # Skip comment lines (start with #) and find the header
        header = None
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if "cve" in row[0].lower():
                header = [c.strip().lower() for c in row]
                break
            # If first data row has no header, assume cve,epss,percentile
            header = ["cve", "epss", "percentile"]
            # Process this row as data
            _update_epss_row(db, row, header)
            break

        if not header:
            return {"error": "Could not parse EPSS CSV header"}

        updated = 0
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            if _update_epss_row(db, row, header):
                updated += 1
            if updated % 5000 == 0 and updated > 0:
                db.commit()

        db.commit()
        log.info("EPSS: updated %d CVEs", updated)
        db.add(AuditEvent(
            actor="system", action="enrich.epss",
            entity_type="feed", entity_id="epss",
            summary=f"EPSS feed: {updated} CVEs updated",
        ))
        db.commit()
        return {"source": "epss", "updated": updated}
    except Exception as exc:
        log.exception("EPSS enrichment failed")
        return {"source": "epss", "error": str(exc)}
    finally:
        if own_db:
            db.close()


def _update_epss_row(db, row: list, header: list) -> bool:
    if len(row) < 2:
        return False
    idx = {h: i for i, h in enumerate(header)}
    cve = row[idx.get("cve", 0)].strip().upper()
    if not cve.startswith("CVE-"):
        return False
    try:
        epss = float(row[idx.get("epss", 1)])
        percentile = float(row[idx.get("percentile", 2)]) if "percentile" in idx and len(row) > idx["percentile"] else None
    except (ValueError, IndexError):
        return False

    result = db.execute(
        update(Vuln)
        .where(Vuln.cve_id == cve)
        .values(epss_score=epss, epss_percentile=percentile)
    )
    return (result.rowcount or 0) > 0


def enrich_kev(db=None, timeout: int = 60) -> dict:
    """Pull the CISA KEV catalog and flag matching CVEs."""
    own_db = db is None
    if own_db:
        db = SessionLocal()
    try:
        log.info("Fetching KEV catalog from %s", KEV_URL)
        r = httpx.get(KEV_URL, timeout=timeout, follow_redirects=True)
        r.raise_for_status()
        data = r.json()
        vulns = data.get("vulnerabilities", [])

        updated = 0
        for entry in vulns:
            cve = (entry.get("cveID") or "").strip().upper()
            if not cve.startswith("CVE-"):
                continue
            due_str = entry.get("dueDate")
            due = None
            if due_str:
                try:
                    due = dt.datetime.strptime(due_str, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
                except ValueError:
                    pass
            result = db.execute(
                update(Vuln)
                .where(Vuln.cve_id == cve)
                .values(kev=True, kev_due_date=due)
            )
            if result.rowcount:
                updated += 1

        db.commit()
        log.info("KEV: %d CVEs flagged from %d catalog entries", updated, len(vulns))
        db.add(AuditEvent(
            actor="system", action="enrich.kev",
            entity_type="feed", entity_id="kev",
            summary=f"KEV catalog: {updated} CVEs flagged from {len(vulns)} entries",
        ))
        db.commit()
        return {"source": "kev", "catalog_size": len(vulns), "updated": updated}
    except Exception as exc:
        log.exception("KEV enrichment failed")
        return {"source": "kev", "error": str(exc)}
    finally:
        if own_db:
            db.close()


def enrich_all(db=None) -> dict:
    """Run both feeds."""
    epss = enrich_epss(db)
    kev = enrich_kev(db)
    return {"epss": epss, "kev": kev}
