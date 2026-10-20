"""Tests for ticket routes and the TicketFinding join table."""
from __future__ import annotations

from app.models import Ticket, TicketFinding


def test_list_tickets_empty(client):
    r = client.get("/api/tickets")
    assert r.status_code == 200
    assert r.json() == []


def test_create_ticket_no_findings(client):
    r = client.post("/api/tickets", json={"finding_ids": []})
    assert r.status_code == 422


def test_create_ticket(client, seed_data, db):
    fid = seed_data["finding"].id
    r = client.post("/api/tickets", json={
        "finding_ids": [fid],
        "summary": "Test ticket",
        "provider": "manual",
    })
    assert r.status_code == 200
    data = r.json()
    assert data["finding_ids"] == [fid]
    assert data["finding_count"] == 1
    assert data["status"] == "open"

    tfs = db.query(TicketFinding).all()
    assert len(tfs) == 1
    assert tfs[0].finding_id == fid


def test_tickets_for_finding(client, seed_data, db):
    fid = seed_data["finding"].id
    ticket = Ticket(
        external_id="MANUAL-001", provider="manual",
        summary="Linked ticket", status="open",
        finding_count=1, severity="high", created_by="testuser",
    )
    db.add(ticket)
    db.flush()
    db.add(TicketFinding(ticket_id=ticket.id, finding_id=fid))
    db.commit()

    r = client.get(f"/api/tickets/for-finding/{fid}")
    assert r.status_code == 200
    tickets = r.json()
    assert len(tickets) == 1
    assert tickets[0]["external_id"] == "MANUAL-001"
    assert fid in tickets[0]["finding_ids"]


def test_get_ticket(client, seed_data, db):
    fid = seed_data["finding"].id
    ticket = Ticket(
        external_id="MANUAL-002", provider="manual",
        summary="Test ticket", status="open",
        finding_count=1, severity="high", created_by="testuser",
    )
    db.add(ticket)
    db.flush()
    db.add(TicketFinding(ticket_id=ticket.id, finding_id=fid))
    db.commit()

    r = client.get(f"/api/tickets/{ticket.id}")
    assert r.status_code == 200
    assert r.json()["external_id"] == "MANUAL-002"


def test_update_ticket(client, seed_data, db):
    fid = seed_data["finding"].id
    ticket = Ticket(
        external_id="MANUAL-003", provider="manual",
        summary="Update me", status="open",
        finding_count=1, severity="high", created_by="testuser",
    )
    db.add(ticket)
    db.flush()
    db.add(TicketFinding(ticket_id=ticket.id, finding_id=fid))
    db.commit()

    r = client.put(f"/api/tickets/{ticket.id}", json={"status": "resolved"})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "resolved"
    assert data["resolved_at"] is not None
