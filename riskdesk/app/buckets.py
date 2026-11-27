"""The five adjudication buckets.

Mirrors the "Vuln Buckets for Adjudication" policy document. Every open
finding lives in exactly one bucket at any time, computed from its
governing decision (or lack of one). Buckets drive the queue the
decision-makers work from and provide the age limits each bucket has
to be emptied within.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Optional

from .enums import Disposition


@dataclass(frozen=True)
class Bucket:
    number: int
    title: str
    summary: str
    #: Max days an item is allowed to sit in this bucket, or None for no cap.
    max_days: Optional[int] = None
    dispositions: tuple[str, ...] = field(default_factory=tuple)


BUCKETS: tuple[Bucket, ...] = (
    Bucket(
        number=0,
        title="Vuln intake",
        summary=("Not reviewed yet. Must be triaged into buckets 1-4 within 7 days "
                 "of intake."),
        max_days=7,
        dispositions=(),
    ),
    Bucket(
        number=1,
        title="Routine fix",
        summary=("Vuln understood, standard fix inside policy SLA, no mitigating "
                 "controls needed. OS patches land here automatically."),
        max_days=None,  # bounded by the SLA, not a bucket-level cap
        dispositions=(Disposition.FIX_IMMEDIATELY.value, Disposition.ROUTINE_FIX.value),
    ),
    Bucket(
        number=2,
        title="Complex fix with mitigation",
        summary=("Vuln understood but remediation is cross-team or long-running. "
                 "Mitigating/compensating controls bridge the time to fix."),
        max_days=None,
        dispositions=(Disposition.COMPLEX_RESOLUTION.value,),
    ),
    Bucket(
        number=3,
        title="Research required",
        summary=("Vuln or fix not yet understood. Investigation must transfer this "
                 "to bucket 1, 2, or 4 within 30 days."),
        max_days=30,
        dispositions=(Disposition.DEVELOPER_REVIEW.value,),
    ),
    Bucket(
        number=4,
        title="Accepted or transferred",
        summary=("Risk accepted with documented rationale, transferred to another "
                 "owner, or reclassified. Carries an expiry and re-review date."),
        max_days=None,
        dispositions=(Disposition.ACCEPT_RISK.value, Disposition.ADJUST_RISK.value,
                      Disposition.FALSE_POSITIVE.value),
    ),
)


_DISPOSITION_TO_BUCKET: dict[str, int] = {
    disp: b.number for b in BUCKETS for disp in b.dispositions
}


def bucket_for_disposition(disposition: Optional[str]) -> int:
    """Bucket number for an adjudication's disposition. `None` -> 0."""
    if not disposition:
        return 0
    return _DISPOSITION_TO_BUCKET.get(disposition, 0)


def bucket_for_finding(adj, now: dt.datetime | None = None) -> int:
    """Bucket for a finding given its governing (active, approved) decision.
    Returns 0 when there is no such decision."""
    if adj is None:
        return 0
    # Expired, revoked, or pending decisions do not govern the finding,
    # so the finding is still in intake. is_active() already includes the
    # state/expires_at check.
    now = now or dt.datetime.now(dt.timezone.utc)
    if not adj.is_active(now):
        return 0
    return bucket_for_disposition(adj.disposition)


def bucket_meta() -> list[dict]:
    """Serializable bucket definitions for the UI."""
    return [
        {
            "number": b.number, "title": b.title, "summary": b.summary,
            "max_days": b.max_days, "dispositions": list(b.dispositions),
        } for b in BUCKETS
    ]
