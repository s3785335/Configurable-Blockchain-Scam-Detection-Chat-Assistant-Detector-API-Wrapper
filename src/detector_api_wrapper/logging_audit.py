"""
Logger / audit trail.

Records raw request + raw response for every call, kept separate from the
sanitized output so results can be traced back to their source later.

Intentionally minimal: swap `_emit` for your real logging/observability
stack (structured logger, log shipping, etc.) without touching callers.
"""

import logging
from datetime import datetime, timezone

_logger = logging.getLogger("detector_api_wrapper.audit")


def _emit(record: dict) -> None:
    _logger.info(record)


def log_call(resource_id: str, provider: str, raw_options: dict, raw_response: dict | None, error: str | None = None) -> None:
    """
    Log a single call for audit purposes.

    NOTE: raw_response may contain unsanitized provider output -- this is
    intentional (it's the audit trail), but this log must never be the
    source used to build a user-facing result. Use the sanitized ApiResult
    for that.
    """
    _emit(
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_id": resource_id,
            "provider": provider,
            "options": raw_options,
            "raw_response": raw_response,
            "error": error,
        }
    )
