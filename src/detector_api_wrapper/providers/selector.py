"""
Provider selection.

Order of precedence:
  1. A manual `provider=` argument to call_api (handled here too, so it is
     checked against the registry like any other choice).
  2. The configured default (DETECTOR_PROVIDER).
  3. The only registered provider, if exactly one exists.
Anything else raises ProviderError, which core.call_api turns into a
status="error" result (fail closed) rather than guessing.
"""

from ..config import DEFAULT_CONFIG, WrapperConfig
from ..errors import ProviderError
from .registry import list_providers


def select_provider(
    options: dict,
    config: WrapperConfig = DEFAULT_CONFIG,
    override: str | None = None,
) -> str:
    registered = list_providers()

    if override is not None:
        if override not in registered:
            raise ProviderError(f"Provider '{override}' is not registered.")
        return override

    if config.default_provider:
        if config.default_provider not in registered:
            raise ProviderError(
                f"Default provider '{config.default_provider}' (DETECTOR_PROVIDER) "
                "is not registered."
            )
        return config.default_provider

    if len(registered) == 1:
        return registered[0]

    if not registered:
        raise ProviderError(
            "No providers registered. Describe your API in the provider config "
            "(DETECTOR_CONFIG_PATH) or register a custom adapter."
        )
    raise ProviderError(
        "Multiple providers are registered; set DETECTOR_PROVIDER or pass "
        "provider= to choose one."
    )
