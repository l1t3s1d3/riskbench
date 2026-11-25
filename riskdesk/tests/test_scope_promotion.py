"""Scope-promotion suggestions for a selection of findings."""
from __future__ import annotations

from app.models import Asset, Finding, Vuln
from app.scope_promotion import suggest_scope_promotions


def _mk(db, source_id, canonical, component_key=None, severity="high",
        owner="team-a", bu="Engineering", env="production",
        asset_id_src=None):
    asset = Asset(source="falcon", source_asset_id=asset_id_src or f"host-{source_id}",
                  name=f"host-{source_id}", asset_type="server",
                  owner=owner, business_unit=bu, environment=env)
    db.add(asset)
    db.flush()
    vuln = db.execute(
        __import__("sqlalchemy").select(Vuln).where(Vuln.canonical_id == canonical)
    ).scalar_one_or_none()
    if vuln is None:
        vuln = Vuln(canonical_id=canonical, severity=severity)
        db.add(vuln)
        db.flush()
    f = Finding(source="falcon", source_finding_id=source_id,
                asset_id=asset.id, vuln_id=vuln.id,
                category="os_vuln", status="open", severity=severity,
                component_key=component_key)
    db.add(f)
    db.commit()
    return f


def test_clean_promotion_when_selection_covers_all_siblings(db):
    """Three findings on one CVE across three hosts, all selected.
    Vuln-scope promotion is clean — no extras."""
    f1 = _mk(db, "a1", "CVE-1111")
    f2 = _mk(db, "a2", "CVE-1111")
    f3 = _mk(db, "a3", "CVE-1111")
    result = suggest_scope_promotions(db, [f1.id, f2.id, f3.id])
    vuln = next(s for s in result["suggestions"] if s["scope_type"] == "vuln")
    assert vuln["clean"]
    assert vuln["key_count"] == 1
    assert vuln["coverage_total"] == 3
    assert vuln["extra_beyond_selection"] == 0
    assert "1 vuln-scoped decision" in vuln["summary"]


def test_promotion_flags_extras_with_different_severity(db):
    """Selected two critical findings for CVE-X; a third medium exists
    unselected. Vuln scope must warn before promotion."""
    f1 = _mk(db, "b1", "CVE-2222", severity="critical")
    f2 = _mk(db, "b2", "CVE-2222", severity="critical")
    _mk(db, "b3", "CVE-2222", severity="medium")
    result = suggest_scope_promotions(db, [f1.id, f2.id])
    vuln = next(s for s in result["suggestions"] if s["scope_type"] == "vuln")
    assert vuln["extra_beyond_selection"] == 1
    assert not vuln["clean"]
    assert any("other severities" in w for w in vuln["warnings"])


def test_component_scope_promotion_collapses_many_cves(db):
    """A selection across different CVEs on the same component_key
    collapses cleanly at component scope."""
    f1 = _mk(db, "c1", "CVE-3001", component_key="pkg:npm/lodash")
    f2 = _mk(db, "c2", "CVE-3002", component_key="pkg:npm/lodash")
    f3 = _mk(db, "c3", "CVE-3003", component_key="pkg:npm/lodash")
    result = suggest_scope_promotions(db, [f1.id, f2.id, f3.id])
    comp = next(s for s in result["suggestions"] if s["scope_type"] == "component")
    assert comp["clean"]
    assert comp["key_count"] == 1
    assert comp["coverage_total"] == 3


def test_ranking_puts_clean_before_dirty(db):
    """Clean suggestions must come before those with extras."""
    f1 = _mk(db, "d1", "CVE-4001")
    f2 = _mk(db, "d2", "CVE-4001")
    # Siblings not in selection so vuln promotion is dirty.
    _mk(db, "d3", "CVE-4001")
    # vuln_on_asset is clean (both selected cover their own asset).
    result = suggest_scope_promotions(db, [f1.id, f2.id])
    clean_suggestions = [s for s in result["suggestions"] if s["clean"]]
    dirty_suggestions = [s for s in result["suggestions"] if not s["clean"]]
    assert clean_suggestions
    assert dirty_suggestions
    # The first non-finding suggestion should be clean.
    top = result["suggestions"][0]
    assert top["clean"]


def test_empty_selection_returns_nothing(db):
    result = suggest_scope_promotions(db, [])
    assert result["selection"]["count"] == 0
    assert result["suggestions"] == []


def test_finding_scope_is_always_offered(db):
    f1 = _mk(db, "e1", "CVE-5000")
    result = suggest_scope_promotions(db, [f1.id])
    assert any(s["scope_type"] == "finding" for s in result["suggestions"])


def test_scope_promotion_api(client, db, seed_data):
    fid = seed_data["finding"].id
    r = client.post("/api/review/scope-promotion", json={"finding_ids": [fid]})
    assert r.status_code == 200
    data = r.json()
    assert data["selection"]["count"] == 1
    assert len(data["suggestions"]) >= 1
