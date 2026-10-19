"""Tests for sync and diagnostics routes."""
from __future__ import annotations


def test_list_queries(client):
    r = client.get("/api/queries")
    assert r.status_code == 200
    data = r.json()
    assert "queries" in data
    sources = {q["source"] for q in data["queries"]}
    assert "wiz" in sources
    assert "falcon" in sources


def test_sync_runs_empty(client):
    r = client.get("/api/sync/runs")
    assert r.status_code == 200
    assert r.json() == []


def test_schedules_empty(client):
    r = client.get("/api/schedules")
    assert r.status_code == 200
    assert r.json() == []
