"""Tests for adjudication routes."""
from __future__ import annotations


def test_list_adjudications_empty(client):
    r = client.get("/api/adjudications")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["adjudications"] == []


def test_preview_scope_empty(client):
    r = client.post("/api/adjudications/preview", json={"finding_ids": [], "scope": "finding"})
    assert r.status_code == 200
    data = r.json()
    assert data["selected"] == 0


def test_suggest_defaults(client):
    r = client.get("/api/adjudications/defaults/suggest?disposition=accept_risk&severity=high")
    assert r.status_code == 200
    data = r.json()
    assert "expires_at" in data
    assert "review_due" in data


def test_create_adjudication(client, seed_data):
    fid = seed_data["finding"].id
    r = client.post("/api/adjudications", json={
        "finding_ids": [fid],
        "disposition": "accept_risk",
        "justification": "Risk accepted for testing — compensating controls in place and verified.",
        "scope": "finding",
        "approver": "admin2",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["created"] >= 1


def test_get_adjudication_not_found(client):
    r = client.get("/api/adjudications/999")
    assert r.status_code == 404
