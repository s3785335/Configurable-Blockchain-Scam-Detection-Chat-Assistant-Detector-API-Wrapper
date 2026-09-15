"""
Central configuration for the Detector API Wrapper.

Per the "zero-configure integration" requirement: every value here has a
sensible default, all are overridable, none are required. Credentials are
read from environment variables at import time with a clear error if
missing, rather than lazily failing deep inside a call.
"""

import os
from dataclasses import dataclass, field


ALLOWED_OPTION_VALUES = {
    "mode": {"default", "strict"},
}

ID_MAX_LENGTH = 64


@dataclass(frozen=True)
class WrapperConfig:
    timeout_seconds: float = 5.0
    cache_ttl_seconds: int = 300
    allowed_option_values: dict = field(default_factory=lambda: ALLOWED_OPTION_VALUES)
    id_max_length: int = ID_MAX_LENGTH
    rate_limit_per_second: float = 5.0


def get_api_key() -> str:
    """
    Read the provider API key from the environment.

    Raises immediately and clearly if not configured, per the security
    requirement that credentials are never hardcoded and failures are
    explicit rather than silent.
    """
    api_key = os.environ.get("API_WRAPPER_KEY")
    if not api_key:
        raise RuntimeError(
            "API_WRAPPER_KEY not configured. Set it as an environment "
            "variable or in your secrets manager before calling call_api()."
        )
    return api_key


DEFAULT_CONFIG = WrapperConfig()
