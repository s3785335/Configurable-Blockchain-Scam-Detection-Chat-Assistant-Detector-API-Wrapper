import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


@pytest.fixture(autouse=True)
def clean_state(monkeypatch):
    """Isolate every test: empty registry and cache, key set."""
    from detector_api_wrapper import core
    from detector_api_wrapper.providers import registry

    registry.clear_registry()
    core._cache._store.clear()
    monkeypatch.setenv("API_WRAPPER_KEY", "test-key")
    yield
    registry.clear_registry()
