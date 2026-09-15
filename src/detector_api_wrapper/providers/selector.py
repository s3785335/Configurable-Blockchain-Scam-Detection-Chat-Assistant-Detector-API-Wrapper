"""
Provider selection.

Decides which backend/provider to call, based on the request type or a
manual override (the override itself is handled in core.call_api).
"""

from ..config import WrapperConfig, DEFAULT_CONFIG

# Registry of available provider names. Populate as real adapters are
# added under providers/ (e.g. providers/example_provider.py).
AVAILABLE_PROVIDERS: list[str] = []


def select_provider(options: dict, config: WrapperConfig = DEFAULT_CONFIG) -> str:
    """
    Choose a provider automatically based on sanitized options.

    Intentional stub: real selection logic depends on which providers are
    registered and what routing rules the client wants. Wire this in once
    at least one real provider adapter exists.
    """
    if not AVAILABLE_PROVIDERS:
        raise RuntimeError(
            "No providers registered. Add a provider adapter under "
            "providers/ and register it in AVAILABLE_PROVIDERS."
        )
    return AVAILABLE_PROVIDERS[0]
