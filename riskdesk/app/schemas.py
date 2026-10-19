"""Pydantic response models for OpenAPI documentation.

Gives every endpoint a typed schema so the auto-generated docs at /api/docs
show exactly what each route returns.
"""
from __future__ import annotations

import datetime as dt

from pydantic import BaseModel, Field


# --- Shared building blocks -------------------------------------------------

class AssetOut(BaseModel):
    id: int
    name: str
    type: str | None = None
    os: str | None = None
    ip: str | None = None
    cloud_provider: str | None = None
    cloud_account: str | None = None
    region: str | None = None
    environment: str | None = None
    internet_facing: bool | None = None
    data_classification: str | None = None
    owner: str | None = None
    business_unit: str | None = None
    tags: dict = Field(default_factory=dict)


class VulnOut(BaseModel):
    canonical_id: str
    cve_id: str | None = None
    title: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    kev: bool = False
    published_at: str | None = None
    remediation: str | None = None
    references: list[str] = Field(default_factory=list)


class FactorOut(BaseModel):
    name: str
    applied: bool
    points: float
    note: str


class RiskOut(BaseModel):
    base_severity: str
    effective_severity: str
    adjusted: bool
    priority: str
    score: float
    sla_due: str | None = None
    sla_overdue: bool = False
    unknown_inputs: list[str] = Field(default_factory=list)
    factors: list[FactorOut] = Field(default_factory=list)


class DecisionOut(BaseModel):
    id: int
    scope_type: str
    scope_key: str
    scope_label: str | None = None
    disposition: str
    state: str
    justification: str | None = None
    compensating_controls: str | None = None
    adjusted_severity: str | None = None
    adjusted_priority: str | None = None
    assigned_to: str | None = None
    remediation_due: str | None = None
    requested_by: str
    requested_at: str | None = None
    approver: str | None = None
    approved_by: str | None = None
    decided_at: str | None = None
    decision_note: str | None = None
    review_due: str | None = None
    expires_at: str | None = None
    applied_count: int = 0
    scope_filter: dict | None = None


# --- Finding responses ------------------------------------------------------

class FindingOut(BaseModel):
    id: int
    source: str
    source_finding_id: str
    category: str
    status: str
    component: str | None = None
    component_version: str | None = None
    component_key: str | None = None
    location: str | None = None
    fix_available: bool = False
    fix_version: str | None = None
    first_detected: str | None = None
    last_seen: str | None = None
    source_url: str | None = None
    source_severity: str | None = None
    asset: AssetOut
    vuln: VulnOut
    risk: RiskOut
    decision: DecisionOut | None = None
    has_pending: bool = False
    is_demo: bool = False


class FindingListOut(BaseModel):
    total: int
    page: int
    page_size: int
    pages: int
    findings: list[FindingOut]
    filter: dict = Field(default_factory=dict)


class FindingIdsOut(BaseModel):
    total: int
    ids: list[int]


class FindingDetailOut(FindingOut):
    decision_history: list[DecisionOut] = Field(default_factory=list)
    raw: dict = Field(default_factory=dict)


class VerifyOut(BaseModel):
    ok: bool
    finding_id: int
    status: str


# --- Dashboard --------------------------------------------------------------

class SyncSummary(BaseModel):
    id: int
    source: str
    status: str
    started_at: str | None = None
    findings: int = 0
    new: int = 0
    closed: int = 0
    error: str | None = None


class DashboardOut(BaseModel):
    open_findings: int
    unique_vulns: int | None = None
    assets: int | None = None
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_source: dict[str, int] = Field(default_factory=dict)
    by_disposition: dict[str, int] = Field(default_factory=dict)
    overdue: int = 0
    kev_open: int = 0
    undecided: int = 0
    pending_approvals: int = 0
    expiring_30d: int = 0
    review_overdue: int = 0
    recent_syncs: list[SyncSummary] = Field(default_factory=list)


# --- Audit ------------------------------------------------------------------

class AuditEventOut(BaseModel):
    id: int
    ts: str
    actor: str
    action: str
    entity_type: str | None = None
    entity_id: str | None = None
    summary: str | None = None
    detail: dict = Field(default_factory=dict)


class AuditPageOut(BaseModel):
    events: list[AuditEventOut]
    total: int
    cursor: int | None = None
    has_more: bool = False


# --- Meta -------------------------------------------------------------------

class DispositionMeta(BaseModel):
    value: str
    label: str
    is_risk_decision: bool


class ScopeMeta(BaseModel):
    value: str
    label: str


class PolicyMeta(BaseModel):
    min_justification_chars: int
    max_acceptance_days: dict
    remediation_sla_days: dict
    require_separate_approver: bool


class MetaOut(BaseModel):
    org: str
    users: list[str]
    approvers: list[str]
    current_user: str
    dispositions: list[DispositionMeta]
    severities: list[str]
    categories: list[str]
    scopes: list[ScopeMeta]
    policy: PolicyMeta
    connectors: dict[str, bool]
    demo_findings: int


# --- Adjudications ----------------------------------------------------------

class AdjudicationListOut(BaseModel):
    total: int
    page: int
    page_size: int
    pages: int
    adjudications: list[DecisionOut]


class AdjudicationCreateOut(BaseModel):
    created: int
    adjudications: list[DecisionOut]


class ScopePreviewPlan(BaseModel):
    scope_type: str
    scope_key: str
    scope_label: str | None = None
    selected_in_scope: int
    coverage: str | None = None


class ScopePreviewOut(BaseModel):
    selected: int
    decisions_to_create: int
    plans: list[ScopePreviewPlan]
    truncated: bool = False


# --- Sync -------------------------------------------------------------------

class SyncRunOut(BaseModel):
    id: int
    source: str
    status: str
    started_at: str | None = None
    finished_at: str | None = None
    assets: int = 0
    findings: int = 0
    new: int = 0
    closed: int = 0
    error: str | None = None
    triggered_by: str | None = None


class SyncTriggerOut(BaseModel):
    run_id: int
    source: str
    status: str
    error: str | None = None
    assets: int = 0
    findings: int = 0
    new: int = 0
    closed: int = 0
    demo: bool = False
    new_by_severity: dict[str, int] = Field(default_factory=dict)
    auto_assigned: int = 0


class ScheduleOut(BaseModel):
    id: int
    source: str
    enabled: bool
    interval_hours: int
    preferred_hour_utc: int | None = None
    last_run_at: str | None = None
    next_run_at: str | None = None
    last_status: str | None = None
    last_error: str | None = None
    limit: int | None = None
    created_by: str | None = None
    updated_at: str | None = None


class QueryEntry(BaseModel):
    name: str
    source: str
    description: str | None = None
    query: str | None = None
    path: str | None = None
    default_filter: dict | str | None = None
    facets: list[str] | None = None
    editable: bool = False
    location: str | None = None


class QueryRegistryOut(BaseModel):
    queries: list[dict]


# --- Asset groups -----------------------------------------------------------

class AssetGroupOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    business_unit: str | None = None
    owner: str | None = None
    criticality: str = "medium"
    tags: dict = Field(default_factory=dict)
    asset_count: int = 0
    created_by: str | None = None
    created_at: str | None = None
    updated_at: str | None = None


class AssetGroupListOut(BaseModel):
    groups: list[AssetGroupOut]
    total: int


# --- Bulk adjudication ------------------------------------------------------

class BulkAdjudicationRowResult(BaseModel):
    row: int
    status: str
    canonical_id: str | None = None
    finding_ids: list[int] = Field(default_factory=list)
    error: str | None = None


class BulkAdjudicationOut(BaseModel):
    ok: bool
    processed: int
    succeeded: int
    failed: int
    results: list[BulkAdjudicationRowResult]


# --- SLA breach notification ------------------------------------------------

class SLABreachSummary(BaseModel):
    finding_id: int
    canonical_id: str
    asset_name: str
    severity: str
    priority: str
    sla_due: str
    days_overdue: int
    disposition: str | None = None


class SLABreachReportOut(BaseModel):
    total_overdue: int
    by_severity: dict[str, int] = Field(default_factory=dict)
    by_priority: dict[str, int] = Field(default_factory=dict)
    findings: list[SLABreachSummary]
    notification_sent: bool = False
