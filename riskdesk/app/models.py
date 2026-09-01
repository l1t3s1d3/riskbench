"""Persistence model.

Three layers, kept deliberately separate:

  Asset          the thing that has the problem   (host, cloud resource, repo)
  Vuln           the problem itself               (CVE, GHSA, CodeQL rule)
  Finding        one instance of a problem on a thing, as reported by one tool

Risk decisions live in Adjudication, which attaches to a *scope* rather than
directly to a Finding. That is what lets one decision cover 4,000 findings and
keep covering findings that arrive next week.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Index, Integer,
    String, Text, UniqueConstraint, JSON,
)
from sqlalchemy.orm import relationship

from .db import Base


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Asset(Base):
    __tablename__ = "assets"
    id = Column(Integer, primary_key=True)
    source = Column(String(16), nullable=False, index=True)
    source_asset_id = Column(String(256), nullable=False)

    name = Column(String(512), nullable=False)          # hostname / resource name / repo full name
    asset_type = Column(String(64))                     # endpoint, server, vm, container_image, repository, storage_account...
    os_name = Column(String(128))
    ip_address = Column(String(64))

    cloud_provider = Column(String(32))                 # azure, aws
    cloud_account = Column(String(256))                 # subscription id / account id
    region = Column(String(64))

    # Enrichment we do NOT currently have a reliable feed for. Left null on
    # purpose; the scoring engine reports them as "not applied" rather than
    # assuming a value. See docs/SCORING.md.
    environment = Column(String(32), default="unknown")
    internet_facing = Column(Boolean, nullable=True)
    data_classification = Column(String(64), nullable=True)

    owner = Column(String(256))
    tags = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=utcnow)
    last_seen = Column(DateTime, default=utcnow)

    findings = relationship("Finding", back_populates="asset")

    __table_args__ = (
        UniqueConstraint("source", "source_asset_id", name="uq_asset_source"),
        Index("ix_asset_name", "name"),
    )


class Vuln(Base):
    __tablename__ = "vulns"
    id = Column(Integer, primary_key=True)
    # Canonical key: CVE where one exists, otherwise the source's own stable id
    # (GHSA-xxxx, a CodeQL rule id, a Wiz cloud config rule id).
    canonical_id = Column(String(128), nullable=False, unique=True)
    cve_id = Column(String(32), index=True, nullable=True)

    title = Column(String(1024))
    description = Column(Text)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(256), nullable=True)
    severity = Column(String(16), nullable=False, default="info", index=True)

    # Exploitability enrichment. epss_* are null until an EPSS feed is wired up.
    epss_score = Column(Float, nullable=True)
    epss_percentile = Column(Float, nullable=True)
    kev = Column(Boolean, default=False, index=True)     # CISA KEV / BOD 22-01
    kev_due_date = Column(DateTime, nullable=True)

    published_at = Column(DateTime, nullable=True)
    remediation = Column(Text)
    references = Column(JSON, default=list)

    findings = relationship("Finding", back_populates="vuln")


class Finding(Base):
    __tablename__ = "findings"
    id = Column(Integer, primary_key=True)
    source = Column(String(16), nullable=False, index=True)
    source_finding_id = Column(String(512), nullable=False)

    asset_id = Column(Integer, ForeignKey("assets.id"), nullable=False, index=True)
    vuln_id = Column(Integer, ForeignKey("vulns.id"), nullable=False, index=True)

    category = Column(String(32), nullable=False, index=True)
    status = Column(String(32), nullable=False, default="open", index=True)

    # What is actually vulnerable, at a finer grain than the asset.
    component = Column(String(512))         # package name, image layer, service
    component_version = Column(String(128))
    component_key = Column(String(512), index=True)  # normalized, e.g. pkg:npm/lodash
    location = Column(String(1024))         # file path[:line] for code findings

    source_severity = Column(String(64))    # verbatim, for traceability
    severity = Column(String(16), nullable=False, index=True)  # normalized base severity

    fix_available = Column(Boolean, default=False, index=True)
    fix_version = Column(String(256))

    first_detected = Column(DateTime, default=utcnow, index=True)
    last_seen = Column(DateTime, default=utcnow, index=True)
    closed_at = Column(DateTime, nullable=True)

    source_url = Column(String(1024))
    raw = Column(JSON, default=dict)        # untouched source payload

    asset = relationship("Asset", back_populates="findings")
    vuln = relationship("Vuln", back_populates="findings")

    __table_args__ = (
        UniqueConstraint("source", "source_finding_id", name="uq_finding_source"),
        Index("ix_finding_triage", "status", "severity", "source"),
    )


class Adjudication(Base):
    """A recorded human decision about risk.

    scope_type / scope_key decide what it covers:
      finding        -> scope_key = str(finding.id)
      vuln_on_asset  -> scope_key = "<canonical_id>::<asset.id>"
      vuln           -> scope_key = "<canonical_id>"
      component      -> scope_key = "<component_key>"
    """
    __tablename__ = "adjudications"
    id = Column(Integer, primary_key=True)

    scope_type = Column(String(32), nullable=False, index=True)
    scope_key = Column(String(512), nullable=False, index=True)
    scope_label = Column(String(512))       # human-readable, for the register
    # Snapshot of the filter used when this was created in bulk, so the basis of
    # the decision is reconstructable later.
    scope_filter = Column(JSON, nullable=True)

    disposition = Column(String(32), nullable=False, index=True)
    state = Column(String(32), nullable=False, default="draft", index=True)

    justification = Column(Text, nullable=False)
    compensating_controls = Column(Text)

    # ADJUST_RISK payload
    adjusted_severity = Column(String(16), nullable=True)
    adjusted_priority = Column(String(8), nullable=True)   # P1..P4

    # Routing payload
    assigned_to = Column(String(256))
    remediation_due = Column(DateTime, nullable=True)

    requested_by = Column(String(256), nullable=False)
    requested_at = Column(DateTime, default=utcnow, nullable=False)
    approver = Column(String(256))          # intended approver
    approved_by = Column(String(256))       # who actually decided
    decided_at = Column(DateTime, nullable=True)
    decision_note = Column(Text)

    review_due = Column(DateTime, nullable=True, index=True)   # next periodic review
    expires_at = Column(DateTime, nullable=True, index=True)   # decision lapses

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    applications = relationship(
        "AdjudicationApplication", back_populates="adjudication",
        cascade="all, delete-orphan",
    )

    __table_args__ = (
        Index("ix_adj_scope", "scope_type", "scope_key", "state"),
    )

    def is_active(self, now: dt.datetime | None = None) -> bool:
        now = now or utcnow()
        if self.state != "approved":
            return False
        if self.expires_at is not None:
            exp = self.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=dt.timezone.utc)
            if exp <= now:
                return False
        return True


class AdjudicationApplication(Base):
    """Immutable record of which findings a decision touched at the moment it
    was made. Scope resolution is dynamic, so this is the evidence of intent."""
    __tablename__ = "adjudication_applications"
    id = Column(Integer, primary_key=True)
    adjudication_id = Column(Integer, ForeignKey("adjudications.id"), nullable=False, index=True)
    finding_id = Column(Integer, ForeignKey("findings.id"), nullable=False, index=True)
    applied_at = Column(DateTime, default=utcnow)

    adjudication = relationship("Adjudication", back_populates="applications")

    __table_args__ = (
        UniqueConstraint("adjudication_id", "finding_id", name="uq_adj_application"),
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"
    id = Column(Integer, primary_key=True)
    ts = Column(DateTime, default=utcnow, index=True)
    actor = Column(String(256), nullable=False, index=True)
    action = Column(String(64), nullable=False, index=True)
    entity_type = Column(String(32), index=True)
    entity_id = Column(String(64), index=True)
    summary = Column(String(1024))
    detail = Column(JSON, default=dict)


class SyncRun(Base):
    __tablename__ = "sync_runs"
    id = Column(Integer, primary_key=True)
    source = Column(String(16), nullable=False, index=True)
    started_at = Column(DateTime, default=utcnow, index=True)
    finished_at = Column(DateTime, nullable=True)
    status = Column(String(32), default="running")   # running, ok, error
    assets_upserted = Column(Integer, default=0)
    findings_upserted = Column(Integer, default=0)
    findings_new = Column(Integer, default=0)
    findings_closed = Column(Integer, default=0)
    error = Column(Text)
    triggered_by = Column(String(256))
    # Delta summary written by the sync engine for the review surface.
    delta = Column(JSON, default=dict)


class SyncSchedule(Base):
    """Per-source import schedule.

    The background scheduler checks these every minute. A schedule is
    independent of whether the connector is currently configured -- you can
    set up a daily cadence before credentials arrive, and it will skip with a
    warning until they are present.
    """
    __tablename__ = "sync_schedules"
    id = Column(Integer, primary_key=True)
    source = Column(String(16), nullable=False, unique=True)
    enabled = Column(Boolean, default=False, nullable=False)
    interval_hours = Column(Integer, default=24, nullable=False)
    # Optional time-of-day preference. Null means "any time the interval fires."
    preferred_hour_utc = Column(Integer, nullable=True)       # 0-23
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    last_status = Column(String(32), nullable=True)
    last_error = Column(Text, nullable=True)
    created_by = Column(String(256))
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    # Limit for scheduled runs; null means all.
    limit = Column(Integer, nullable=True)


class AssignmentRule(Base):
    """Criteria-based auto-routing.

    Rules evaluate in `priority` order (lowest number first) against each
    finding. The first match sets `assigned_to` on the finding and -- when
    `create_decision` is true -- also creates a routing adjudication so the
    assignment shows up in the register alongside risk decisions.

    Criteria use AND logic: every non-null column must match. Patterns
    (asset_pattern, component_pattern) are SQL LIKE with % wildcards.
    """
    __tablename__ = "assignment_rules"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False)
    description = Column(Text)
    enabled = Column(Boolean, default=True, nullable=False)
    priority = Column(Integer, default=100, nullable=False, index=True)

    # Criteria -- all non-null columns must match (AND).
    source = Column(String(16), nullable=True)                # wiz | falcon | github
    severity = Column(String(128), nullable=True)             # comma-separated: "critical,high"
    category = Column(String(128), nullable=True)             # comma-separated
    asset_pattern = Column(String(512), nullable=True)        # SQL LIKE, e.g. "pli-prod-%"
    component_pattern = Column(String(512), nullable=True)    # SQL LIKE
    environment = Column(String(64), nullable=True)           # production | non_production
    kev_only = Column(Boolean, default=False, nullable=False)
    fix_available_only = Column(Boolean, default=False, nullable=False)

    # Action
    assign_to = Column(String(256), nullable=False)
    disposition = Column(String(32), default="fix_immediately")  # which routing disposition
    remediation_days = Column(Integer, nullable=True)            # due = first_detected + this
    justification_template = Column(Text)                        # pre-filled justification

    created_by = Column(String(256))
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_rule_priority", "enabled", "priority"),
    )


# =========================================================================
# Authentication and exception workflow
# =========================================================================

class User(Base):
    """Local user account. SSO users are auto-provisioned on first login."""
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(128), nullable=False, unique=True, index=True)
    display_name = Column(String(256))
    email = Column(String(256))
    password_hash = Column(String(256), nullable=True)   # null for SSO-only users
    role = Column(String(32), nullable=False, default="team")  # admin, security, team, viewer
    team = Column(String(128))                           # e.g. "engineering", "infrastructure"
    active = Column(Boolean, default=True, nullable=False)
    auth_method = Column(String(32), default="local")    # local, sso, both
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class Session(Base):
    """Browser session. Token is stored in an httpOnly cookie."""
    __tablename__ = "sessions"
    id = Column(Integer, primary_key=True)
    token = Column(String(256), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(64))
    user_agent = Column(String(512))


class ExceptionRequest(Base):
    """A vulnerability exception submitted by a team member for security review.

    Lifecycle:
      draft -> submitted -> under_review -> approved | rejected | info_requested
                                                          |
                                                    (submitter responds)
                                                          |
                                                    under_review -> ...

    An approved exception creates an Adjudication record automatically, so it
    flows into the risk register and gets the same expiry/review treatment.
    """
    __tablename__ = "exception_requests"
    id = Column(Integer, primary_key=True)

    # What is being excepted
    title = Column(String(512), nullable=False)
    finding_ids = Column(JSON, default=list)            # list of finding ids
    scope = Column(String(32), default="finding")       # same scope model as adjudication
    scope_key = Column(String(512))
    scope_label = Column(String(512))

    # What the submitter wants
    requested_disposition = Column(String(32), nullable=False)  # accept_risk, adjust_risk, false_positive
    justification = Column(Text, nullable=False)
    business_impact = Column(Text)                      # why this matters to the business
    compensating_controls = Column(Text)
    adjusted_severity = Column(String(16), nullable=True)
    requested_duration_days = Column(Integer)            # how long the exception should last

    # Who
    submitted_by = Column(String(256), nullable=False, index=True)
    submitter_team = Column(String(128))
    submitter_email = Column(String(256))

    # Review
    status = Column(String(32), default="draft", nullable=False, index=True)
    # draft, submitted, under_review, info_requested, approved, rejected, withdrawn
    assigned_reviewer = Column(String(256), index=True)
    reviewed_by = Column(String(256))
    review_decision = Column(String(32))                # approved, rejected
    review_note = Column(Text)
    review_date = Column(DateTime, nullable=True)

    # Link to the adjudication created on approval
    adjudication_id = Column(Integer, ForeignKey("adjudications.id"), nullable=True)

    # Timestamps
    submitted_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("ix_exception_status", "status", "submitted_by"),
    )


class ExceptionComment(Base):
    """Threaded conversation on an exception request."""
    __tablename__ = "exception_comments"
    id = Column(Integer, primary_key=True)
    exception_id = Column(Integer, ForeignKey("exception_requests.id"), nullable=False, index=True)
    author = Column(String(256), nullable=False)
    body = Column(Text, nullable=False)
    is_internal = Column(Boolean, default=False)         # security-only note, hidden from submitter
    created_at = Column(DateTime, default=utcnow)


# =========================================================================
# CIS / STIG compliance tracking
# =========================================================================

class ComplianceBenchmark(Base):
    """A benchmark definition (e.g. CIS Cisco IOS XE 17.x, DISA STIG Windows Server 2022)."""
    __tablename__ = "compliance_benchmarks"
    id = Column(Integer, primary_key=True)
    framework = Column(String(32), nullable=False, index=True)   # cis | stig
    name = Column(String(512), nullable=False)                   # "CIS Cisco IOS XE 17.x Benchmark"
    version = Column(String(64))                                 # "2.2.1"
    xccdf_id = Column(String(512), nullable=True)                # full XCCDF benchmark id
    profile = Column(String(128))                                # "Level 1", "Level 2", "CAT I"
    profile_xccdf_id = Column(String(512), nullable=True)
    description = Column(Text)
    created_at = Column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("framework", "name", "version", "profile", name="uq_benchmark"),
    )


class ComplianceScan(Base):
    """One import of benchmark results against a set of hosts."""
    __tablename__ = "compliance_scans"
    id = Column(Integer, primary_key=True)
    benchmark_id = Column(Integer, ForeignKey("compliance_benchmarks.id"), nullable=False, index=True)
    scan_date = Column(DateTime, nullable=False, index=True)
    source_file = Column(String(512))
    imported_by = Column(String(256))
    imported_at = Column(DateTime, default=utcnow)
    total_checks = Column(Integer, default=0)
    total_pass = Column(Integer, default=0)
    total_fail = Column(Integer, default=0)
    total_manual = Column(Integer, default=0)
    total_error = Column(Integer, default=0)
    total_not_selected = Column(Integer, default=0)
    score_percent = Column(Float, nullable=True)          # from the summary row, or computed
    host_count = Column(Integer, default=0)
    notes = Column(Text)


class ComplianceCheck(Base):
    """One rule result on one host from one scan."""
    __tablename__ = "compliance_checks"
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey("compliance_scans.id"), nullable=False, index=True)
    benchmark_id = Column(Integer, ForeignKey("compliance_benchmarks.id"), nullable=False)
    hostname = Column(String(256), nullable=False, index=True)
    rule_id = Column(String(512), nullable=False, index=True)    # "1.1.1" or STIG VID
    rule_xccdf_id = Column(String(512))                          # full XCCDF rule id
    rule_title = Column(String(1024), nullable=False)
    result = Column(String(32), nullable=False, index=True)      # pass, fail, manual, error, notselected, unknown
    references = Column(Text)                                    # URL or reference string
    profile = Column(String(128))
    scan_date = Column(DateTime)

    __table_args__ = (
        Index("ix_check_scan_host", "scan_id", "hostname", "rule_id"),
    )


# =========================================================================
# Asset correlation
# =========================================================================

class AssetCorrelation(Base):
    """Maps assets from different sources to a single canonical identity.

    Correlation can be manual (an admin says "these are the same device") or
    rule-based (hostname match, IP match). The canonical_name is the
    human-friendly label shown in cross-source views.
    """
    __tablename__ = "asset_correlations"
    id = Column(Integer, primary_key=True)
    canonical_name = Column(String(512), nullable=False, index=True)
    asset_ids = Column(JSON, default=list)         # list of asset table ids
    match_method = Column(String(32), default="manual")  # manual, hostname, ip, rule
    environment = Column(String(64))
    data_classification = Column(String(64))
    owner = Column(String(256))
    notes = Column(Text)
    created_by = Column(String(256))
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


# =========================================================================
# Saved views
# =========================================================================

class SavedView(Base):
    """A named, reusable filter configuration."""
    __tablename__ = "saved_views"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False)
    description = Column(Text)
    filters = Column(JSON, nullable=False, default=dict)   # FindingFilter as dict
    owner = Column(String(256), nullable=False, index=True)
    shared = Column(Boolean, default=False)                # visible to all users
    pinned = Column(Boolean, default=False)                # shows in the rail
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


# =========================================================================
# API tokens
# =========================================================================

class ApiToken(Base):
    """Long-lived bearer token for automation (CI pipelines, scripts)."""
    __tablename__ = "api_tokens"
    id = Column(Integer, primary_key=True)
    name = Column(String(256), nullable=False)
    token_hash = Column(String(256), nullable=False, unique=True, index=True)
    token_prefix = Column(String(16), nullable=False)      # first 8 chars, for identification
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    scopes = Column(JSON, default=list)                    # list of permission names, empty = all user perms
    last_used = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True)
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow)


# =========================================================================
# Compliance targets
# =========================================================================

class ComplianceTarget(Base):
    """A target compliance percentage for a benchmark by a deadline."""
    __tablename__ = "compliance_targets"
    id = Column(Integer, primary_key=True)
    benchmark_id = Column(Integer, ForeignKey("compliance_benchmarks.id"), nullable=False, index=True)
    target_percent = Column(Float, nullable=False)         # e.g. 100.0
    target_date = Column(DateTime, nullable=False)         # e.g. April 2027
    baseline_percent = Column(Float)                       # starting point, e.g. 47.0
    baseline_date = Column(DateTime)
    description = Column(Text)
    created_by = Column(String(256))
    created_at = Column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("benchmark_id", name="uq_target_benchmark"),
    )


# =========================================================================
# Connector configuration (admin-editable from the UI)
# =========================================================================

class ConnectorConfig(Base):
    """Encrypted-at-rest connector credentials, editable from the admin UI.

    Values are stored as JSON. Sensitive fields (secrets, tokens) should be
    encrypted before storage in production; this version stores them as
    plaintext in SQLite, same as .env. The advantage over .env is that an
    admin can change them without restarting the app or touching the filesystem.
    """
    __tablename__ = "connector_configs"
    id = Column(Integer, primary_key=True)
    source = Column(String(32), nullable=False, unique=True, index=True)
    config = Column(JSON, nullable=False, default=dict)
    updated_by = Column(String(256))
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
