"""Auto-tagging OS vulnerabilities inside SLA as routine_fix."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from app.adjudication import create_decisions
from app.enums import Disposition
from app.models import Adjudication, AdjudicationApplication, Finding, Vuln
from app.routine_fix import AUTO_ACTOR, auto_tag_routine_fixes


def _mk_os_finding(db, source_id: str, severity: str = "medium",
                   days_old: int = 1, category: str = "os_vuln", canonical: str | None = None):
    from app.models import Asset
    asset = Asset(source="falcon", source_asset_id=f"host-{source_id}",
                  name=f"host-{source_id}", asset_type="server")
    db.add(asset)
    cid = canonical or f"CVE-{source_id}"
    vuln = db.execute(select(Vuln).where(Vuln.canonical_id == cid)).scalar_one_or_none()
    if vuln is None:
        vuln = Vuln(canonical_id=cid, severity=severity)
        db.add(vuln)
    db.flush()
    f = Finding(
        source="falcon", source_finding_id=source_id,
        asset_id=asset.id, vuln_id=vuln.id,
        category=category, status="open", severity=severity,
        first_detected=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days_old),
    )
    db.add(f)
    db.commit()
    return f


def test_auto_tag_inside_sla(db):
    f = _mk_os_finding(db, "f1", severity="medium", days_old=1)
    tagged = auto_tag_routine_fixes(db)
    assert tagged == 1
    adj = db.execute(select(Adjudication)).scalars().one()
    assert adj.disposition == Disposition.ROUTINE_FIX.value
    assert adj.requested_by == AUTO_ACTOR
    assert adj.scope_key == str(f.id)
    assert adj.expires_at is not None


def test_auto_tag_skips_overdue(db):
    """A medium-severity OS finding past 90 days is overdue and must not be
    silently absorbed into routine work."""
    _mk_os_finding(db, "f1", severity="medium", days_old=200)
    tagged = auto_tag_routine_fixes(db)
    assert tagged == 0
    assert db.execute(select(Adjudication)).scalars().all() == []


def test_auto_tag_skips_non_os(db):
    _mk_os_finding(db, "f1", severity="medium", days_old=1, category="dependency")
    tagged = auto_tag_routine_fixes(db)
    assert tagged == 0


def test_auto_tag_is_idempotent(db):
    _mk_os_finding(db, "f1", severity="medium", days_old=1)
    assert auto_tag_routine_fixes(db) == 1
    assert auto_tag_routine_fixes(db) == 0
    assert len(db.execute(select(Adjudication)).scalars().all()) == 1


def test_human_decision_supersedes_routine_fix(db):
    """A manual decision at any scope should retire the auto routine_fix on
    the same finding so the human decision governs."""
    f = _mk_os_finding(db, "f1", severity="medium", days_old=1)
    auto_tag_routine_fixes(db)
    created = create_decisions(
        db, finding_ids=[f.id], disposition="accept_risk",
        justification="Documented residual risk; compensating network segmentation.",
        compensating_controls="Segmented VLAN with ACL.",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30),
        actor="executive1", approver="executive2", scope="finding",
    )
    assert len(created) == 1
    # Both adjudications exist; the auto one is now expired.
    adjs = db.execute(select(Adjudication).order_by(Adjudication.id)).scalars().all()
    auto = [a for a in adjs if a.requested_by == AUTO_ACTOR][0]
    assert auto.state == "expired"


def test_vuln_scope_decision_retires_routine_fix_on_siblings(db):
    """A vuln-scope decision should clear routine_fix on every finding for
    that CVE, not only the one explicitly selected."""
    f1 = _mk_os_finding(db, "f1", severity="medium", days_old=1, canonical="CVE-SHARED")
    f2 = _mk_os_finding(db, "f2", severity="medium", days_old=1, canonical="CVE-SHARED")
    auto_tag_routine_fixes(db)
    assert db.execute(select(Adjudication)).scalars().all().__len__() == 2

    create_decisions(
        db, finding_ids=[f1.id], disposition="accept_risk",
        justification="Documented residual risk; compensating network segmentation.",
        compensating_controls="Segmented VLAN with ACL.",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30),
        actor="executive1", approver="executive2", scope="vuln",
    )
    auto_adjs = db.execute(
        select(Adjudication).where(Adjudication.requested_by == AUTO_ACTOR)
    ).scalars().all()
    assert len(auto_adjs) == 2
    assert all(a.state == "expired" for a in auto_adjs)
