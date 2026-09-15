"""
Detector API Wrapper

Zero-configure entry point: callers only need environment variables set
(e.g. API_WRAPPER_KEY) and can call `call_api(resource_id)` directly.
"""

from .core import call_api, call_api_async
from .errors import InvalidInputError
from .normalize import ApiResult, Evidence

__all__ = [
    "call_api",
    "call_api_async",
    "InvalidInputError",
    "ApiResult",
    "Evidence",
]
