"""
Shared detector adapter interface.

Each detector the client plugs in gets one small adapter implementing
this interface, so adding one never touches core.py.

There are two ways to plug one in:
  1. No code: describe the API in the provider config file and the
     generic HTTP adapter (providers/http_adapter.py) handles it.
  2. Custom code: subclass ProviderAdapter, then call
     register_provider(MyAdapter()) in a module listed in
     DETECTOR_ADAPTER_MODULES.

Whichever route is used, the adapter's to_schema() must produce the
fields of the main application's DetectionResult.
"""

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..schema import RequiredInputType


@dataclass(frozen=True)
class DetectorRequest:
    """Everything a detector may need for one lookup (all sanitized)."""

    resource_id: str
    chain: str
    options: dict = field(default_factory=dict)
    # AddressContext as a JSON-ready dict (aliases applied, e.g. "from"),
    # present only for "address_with_context" detectors.
    context: dict | None = None


class ProviderAdapter(ABC):
    """Base class every detector adapter must implement."""

    name: str = "base"
    # Mirrors BusinessAnalyserOutput.required_input_type in the main app.
    required_input_type: RequiredInputType = "address"

    @abstractmethod
    def call(self, request: DetectorRequest, timeout: float) -> dict:
        """
        Perform the real request to this detector and return its raw JSON.

        Implementations must:
          - Apply the given explicit timeout.
          - Never interpolate request values into a URL string directly;
            use parameterized request building.
          - Raise on failure rather than returning a fake "success" shape,
            so the caller can fail closed.
        """
        raise NotImplementedError

    async def acall(self, request: DetectorRequest, timeout: float) -> dict:
        """
        Async version of call(). Adapters with an async-native client
        (e.g. httpx.AsyncClient) should override this. The default runs
        call() in a worker thread so custom sync-only adapters still work.
        """
        return await asyncio.to_thread(self.call, request, timeout)

    def to_schema(self, raw: dict) -> dict:
        """
        Map this detector's raw JSON onto DetectionResult fields:
        label, risk_type, confidence, evidence, explanation,
        reasoning_trace. Default: pass through unchanged, for detectors
        that already respond in that shape.
        """
        return raw

    def validate_resource_id(self, resource_id: str) -> None:
        """
        Optional detector-specific identifier check (e.g. a checksum), run
        after the generic sanitization. Raise InvalidInputError to reject.
        """
        return None

    def is_configured(self) -> bool:
        """
        Whether this detector has what it needs to run (e.g. credentials).
        Feeds BusinessAnalyserOutput.detector_configured. Must never
        expose the credential itself.
        """
        return True
