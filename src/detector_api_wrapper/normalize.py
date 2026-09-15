"""
Response normalization.

Converts each provider's raw, inconsistent JSON into a single standard
result schema (see draft, Section 5 - Input/Output Data Handling).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal

Status = Literal["ok", "not_found", "error"]


@dataclass
class Evidence:
    claim: str
    source: str
    raw_ref: str


@dataclass
class ApiResult:
    resource_id: str
    provider: str
    status: Status
    data: dict = field(default_factory=dict)
    evidence: list[Evidence] = field(default_factory=list)
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    error: str | None = None


def normalize_response(raw: dict, provider: str, resource_id: str) -> ApiResult:
    """
    Map a provider's raw JSON into the standard ApiResult schema.

    NOTE: intentional stub. The actual field mapping depends on
    confirming the real provider's response schema first (see draft,
    closing note). Wire the real mapping in here once that's confirmed.
    """
    return ApiResult(
        resource_id=resource_id,
        provider=provider,
        status="ok",
        data={},
        evidence=[],
        error=None,
    )
