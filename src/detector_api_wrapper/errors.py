"""Typed errors for the Detector API Wrapper.

Sanitization failures and provider failures are both converted into
typed, non-crashing results by core.call_api rather than allowed to
propagate as raw exceptions.
"""


class InvalidInputError(ValueError):
    """Raised when resource_id or options fail sanitization/validation."""


class ProviderError(RuntimeError):
    """Raised when a provider call fails, times out, or is misconfigured."""


class NotFoundError(ProviderError):
    """Raised when the provider reports it has no record for the resource."""
