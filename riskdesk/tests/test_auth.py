"""Tests for auth routes."""
from __future__ import annotations


def test_auth_me_unauthenticated(client):
    r = client.get("/api/auth/me")
    assert r.status_code == 200
    data = r.json()
    assert "auth_mode" in data


def test_list_users(client):
    r = client.get("/api/users")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
