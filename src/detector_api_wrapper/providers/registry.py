"""
Provider registry.

Holds the adapters available in this process. Adapters are registered
either from the provider config (generic HTTP adapters) or by custom
modules listed in DETECTOR_ADAPTER_MODULES. Registration is loaded once,
on first use, so importing the package never makes network calls or
fails because of configuration.
"""

import importlib
import threading

from ..config import WrapperConfig
from ..errors import ProviderError
from .base import ProviderAdapter

_adapters: dict[str, ProviderAdapter] = {}
_loaded_for: set[int] = set()
_lock = threading.Lock()


def register_provider(adapter: ProviderAdapter) -> None:
    """Make an adapter available under its `name`."""
    if not isinstance(adapter, ProviderAdapter):
        raise TypeError("adapter must be a ProviderAdapter instance.")
    if not adapter.name or adapter.name == "base":
        raise ValueError("adapter must define a unique `name`.")
    with _lock:
        if adapter.name in _adapters:
            raise ValueError(f"A provider named '{adapter.name}' is already registered.")
        _adapters[adapter.name] = adapter


def unregister_provider(name: str) -> None:
    with _lock:
        _adapters.pop(name, None)


def clear_registry() -> None:
    """Remove every adapter. Mainly for tests."""
    with _lock:
        _adapters.clear()
        _loaded_for.clear()


def load_configured_providers(config: WrapperConfig) -> None:
    """Register adapters described by `config`. Safe to call repeatedly."""
    if id(config) in _loaded_for:
        return
    # Imported here to avoid a circular import (http_adapter uses base).
    from .http_adapter import GenericHttpAdapter

    for definition in config.providers:
        adapter = GenericHttpAdapter.from_definition(definition)
        if adapter.name not in _adapters:
            register_provider(adapter)
    for module_name in config.adapter_modules:
        try:
            importlib.import_module(module_name)
        except ImportError as e:
            raise ProviderError(f"Could not import adapter module '{module_name}'.") from e
    _loaded_for.add(id(config))


def get_adapter(name: str) -> ProviderAdapter:
    try:
        return _adapters[name]
    except KeyError:
        raise ProviderError(f"Provider '{name}' is not registered.") from None


def list_providers() -> list[str]:
    return list(_adapters)
