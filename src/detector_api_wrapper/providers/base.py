"""
Shared provider adapter interface.

Each provider gets one small adapter implementing this same interface,
so adding a new provider later doesn't touch calling code in core.py.
"""

from abc import ABC, abstractmethod


class ProviderAdapter(ABC):
    """Base class every provider adapter must implement."""

    name: str = "base"

    @abstractmethod
    def call(self, resource_id: str, options: dict) -> dict:
        """
        Perform the real request to this provider and return raw JSON.

        Implementations must:
          - Apply an explicit timeout (see config.WrapperConfig.timeout_seconds).
          - Never interpolate resource_id/options into a URL string directly;
            use parameterized request building.
          - Raise on failure rather than returning a fake "success" shape,
            so the caller can fail closed.
        """
        raise NotImplementedError
