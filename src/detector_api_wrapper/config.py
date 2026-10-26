import json
import os
from dataclasses import dataclass, field

ALLOWED_OPTION_VALUES = {
    "mode": {"default", "strict"},
}

ID_MAX_LENGTH = 128

ID_PATTERN = r"^[A-Za-z0-9_\-]+$"


@dataclass(frozen=True)
class WrapperConfig:
    timeout_seconds: float = 20.0
    cache_ttl_seconds: int = 300
    allowed_option_values: dict = field(default_factory=lambda: ALLOWED_OPTION_VALUES)
    id_max_length: int = ID_MAX_LENGTH
    id_pattern: str = ID_PATTERN
    rate_limit_per_second: float = 5.0
    default_provider: str | None = None
    providers: tuple = ()
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
    modules = os.environ.get("DETECTOR_ADAPTER_MODULES", "")
    return WrapperConfig(
        timeout_seconds=_env_float("DETECTOR_TIMEOUT_SECONDS", 20.0),
        cache_ttl_seconds=int(_env_float("DETECTOR_CACHE_TTL_SECONDS", 300)),
        id_max_length=int(_env_float("DETECTOR_ID_MAX_LENGTH", ID_MAX_LENGTH)),
        id_pattern=os.environ.get("DETECTOR_ID_PATTERN") or ID_PATTERN,
        rate_limit_per_second=_env_float("DETECTOR_RATE_LIMIT_PER_SECOND", 5.0),
        default_provider=os.environ.get("DETECTOR_PROVIDER") or None,
        providers=_load_provider_definitions(),
        adapter_modules=tuple(m.strip() for m in modules.split(",") if m.strip()),
    )


def get_api_key(env_var: str = "API_WRAPPER_KEY") -> str:
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