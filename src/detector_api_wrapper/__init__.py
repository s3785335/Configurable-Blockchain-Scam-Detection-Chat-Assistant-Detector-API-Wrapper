"""
Detector API Wrapper

Lets a client plug the detector API of their choice into the scam-detection
bot. Every detector's response is returned as the main application's
DetectionResult, so the bot handles all detectors the same way.

    from detector_api_wrapper import call_api

    outcome = call_api("0x...", chain="ethereum")
    if outcome.status != "error":
        detection = outcome.result  # DetectionResult
"""

from .config import WrapperConfig, load_config
from .core import call_api, call_api_async, detector_status, list_detectors
from .errors import InvalidInputError, NotFoundError, ProviderError
from .normalize import ApiResult
from .providers import DetectorRequest, GenericHttpAdapter, ProviderAdapter, register_provider
from .schema import AddressContext, DetectionResult, Evidence

__all__ = [
    "call_api",
    "call_api_async",
    "detector_status",
    "list_detectors",
    "ApiResult",
    "DetectionResult",
    "Evidence",
    "AddressContext",
    "InvalidInputError",
    "NotFoundError",
    "ProviderError",
    "ProviderAdapter",
    "DetectorRequest",
    "GenericHttpAdapter",
    "register_provider",
    "WrapperConfig",
    "load_config",
]
