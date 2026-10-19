"""Tests for finding routes."""
from __future__ import annotations

import datetime as dt

from app.models import Finding


def test_list_findings_empty(client):
    r = client.get("/api/findings")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["findings"] == []


def test_get_finding_not_found(client):
    r = client.get("/api/findings/999")
    assert r.status_code == 404


def test_get_finding_detail(client, seed_data):
    fid = seed_data["finding"].id
    r = client.get(f"/api/findings/{fid}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == fid
    assert data["vuln"]["canonical_id"] == "CVE-2024-0001"


def test_verify_finding_wrong_status(client, seed_data):
    fid = seed_data["finding"].id
    r = client.post(f"/api/findings/{fid}/verify")
    assert r.status_code == 422
    assert "fixed" in r.json()["detail"].lower()


def test_verify_finding_success(client, seed_data, db):
    finding = seed_data["finding"]
    finding.status = "fixed"
    db.commit()
    r = client.post(f"/api/findings/{finding.id}/verify")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "verified_fixed"

    db.refresh(finding)
    assert finding.status == "verified_fixed"
    assert finding.verified_by is not None
    assert finding.verified_at is not None


def test_dashboard(client, seed_data):
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "open_findings" in data
    assert data["open_findings"] >= 1


def test_meta(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    data = r.json()
    assert "dispositions" in data
    assert "severities" in data
