"""
Central configuration for the Detector API Wrapper.

Per the "zero-configure integration" requirement: every value here has a
sensible default, all are overridable, none are required up front.

Container-ready: every setting can be supplied through environment
variables, so the same image runs anywhere without rebuilding. The
provider definitions (which API the client plugs in) can be supplied as a
mounted JSON file (DETECTOR_CONFIG_PATH) or inline JSON
(DETECTOR_CONFIG_JSON).

Credentials are read lazily, at call time, from the environment or from a
mounted secret file (API_WRAPPER_KEY_FILE, e.g. /run/secrets/...). They
are never hardcoded, never stored on the config object, and never logged.
"""

import json
import os
from dataclasses import dataclass, field

ALLOWED_OPTION_VALUES = {
    "mode": {"default", "strict"},
}

# 128 leaves room for common blockchain identifiers, e.g. EVM transaction
# hashes ("0x" + 64 hex = 66 chars), which the previous cap of 64 rejected.
ID_MAX_LENGTH = 128

# Conservative allow-list: alphanumeric, underscore, hyphen. Override via
# DETECTOR_ID_PATTERN if a client's identifiers need more (e.g. ":" for
# "chain:address" formats).
ID_PATTERN = r"^[A-Za-z0-9_\-]+$"


@dataclass(frozen=True)
class WrapperConfig:
    timeout_seconds: float = 5.0
    cache_ttl_seconds: int = 300
    allowed_option_values: dict = field(default_factory=lambda: ALLOWED_OPTION_VALUES)
    id_max_length: int = ID_MAX_LENGTH
    id_pattern: str = ID_PATTERN
    rate_limit_per_second: float = 5.0
    # Name of the provider to use when the caller doesn't pass one.
    default_provider: str | None = None
    # Provider definitions for the generic HTTP adapter (see
    # providers/http_adapter.py). Loaded from file/env by load_config().
    providers: tuple = ()
    # Python modules to import at startup that register custom adapters
    # (the "write your own adapter" route).
    adapter_modules: tuple = ()


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    try:
        return float(raw)
    except ValueError as e:
        raise RuntimeError(f"{name} must be a number, got {raw!r}.") from e


def _load_provider_definitions() -> tuple:
    """Read provider definitions from DETECTOR_CONFIG_PATH or DETECTOR_CONFIG_JSON."""
    path = os.environ.get("DETECTOR_CONFIG_PATH")
    inline = os.environ.get("DETECTOR_CONFIG_JSON")
    if path and inline:
        raise RuntimeError("Set only one of DETECTOR_CONFIG_PATH or DETECTOR_CONFIG_JSON.")
    if not path and not inline:
        return ()
    try:
        if path:
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
        else:
            data = json.loads(inline)
    except (OSError, json.JSONDecodeError) as e:
        raise RuntimeError(f"Could not read provider configuration: {e}") from e

    providers = data.get("providers") if isinstance(data, dict) else None
    if not isinstance(providers, list):
        raise RuntimeError("Provider configuration must be an object with a 'providers' list.")
    return tuple(providers)


def load_config() -> WrapperConfig:
    """Build a WrapperConfig from environment variables, falling back to defaults."""
    modules = os.environ.get("DETECTOR_ADAPTER_MODULES", "")
    return WrapperConfig(
        timeout_seconds=_env_float("DETECTOR_TIMEOUT_SECONDS", 5.0),
        cache_ttl_seconds=int(_env_float("DETECTOR_CACHE_TTL_SECONDS", 300)),
        id_max_length=int(_env_float("DETECTOR_ID_MAX_LENGTH", ID_MAX_LENGTH)),
        id_pattern=os.environ.get("DETECTOR_ID_PATTERN") or ID_PATTERN,
        rate_limit_per_second=_env_float("DETECTOR_RATE_LIMIT_PER_SECOND", 5.0),
        default_provider=os.environ.get("DETECTOR_PROVIDER") or None,
        providers=_load_provider_definitions(),
        adapter_modules=tuple(m.strip() for m in modules.split(",") if m.strip()),
    )


def get_api_key(env_var: str = "API_WRAPPER_KEY") -> str:
    """
    Read a provider API key at call time.

    Checks `<env_var>` first, then `<env_var>_FILE` (a path to a mounted
    secret, the standard Docker secrets pattern). Raises clearly if
    neither is set, so a missing credential fails fast and explicitly.
    """
    api_key = os.environ.get(env_var)
    if not api_key:
        key_file = os.environ.get(f"{env_var}_FILE")
        if key_file:
            try:
                with open(key_file, encoding="utf-8") as f:
                    api_key = f.read().strip()
            except OSError as e:
                raise RuntimeError(f"{env_var}_FILE is set but could not be read.") from e
    if not api_key:
        raise RuntimeError(
            f"{env_var} not configured. Set it as an environment variable, "
            f"or point {env_var}_FILE at a mounted secret, before calling call_api()."
        )
    return api_key


DEFAULT_CONFIG = load_config()
