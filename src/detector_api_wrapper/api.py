"""
HTTP API layer for the Detector API Wrapper.

Exposes the wrapper over HTTP so it can run in its own container and be
reached by the main application over the network, rather than requiring
the main app to import this package in-process.

Scope note: this module only sets up the service itself. Wiring the main
application to actually call it is a separate, later task.
"""

from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from .core import call_api, detector_status, list_detectors
from .schema import AddressContext

app = FastAPI(
    title="Detector API Wrapper",
    description=(
        "Translates a client's chosen scam-detector API into the "
        "Blockchain Scam Detection Chat Assistant's DetectionResult schema."
    ),
    version="0.1.0",
)


class CallApiRequest(BaseModel):
    resource_id: str
    options: dict[str, Any] | None = None
    provider: str | None = None
    chain: str | None = None
    context: AddressContext | dict | None = None


@app.get("/health")
def health() -> dict:
    """Basic liveness check for container orchestration / compose healthcheck.

    Deliberately does not touch provider config, so it stays healthy even
    if a provider is temporarily misconfigured -- use /status for that.
    """
    return {"status": "ok"}


@app.get("/status")
def status(provider: str | None = None) -> dict:
    """
    Which detector would be used, and whether it's configured.

    Mirrors detector_status(), matching the main app's
    BusinessAnalyserOutput fields (selected_detector, detector_configured,
    required_input_type). Never raises.
    """
    return detector_status(provider=provider)


@app.get("/detectors")
def detectors() -> dict:
    """Names of every detector registered from config or custom modules."""
    return {"detectors": list_detectors()}


@app.post("/call")
def call(request: CallApiRequest) -> dict:
    """
    Run the configured detector for an address and return the ApiResult
    envelope as JSON (status, result, error, etc.) -- see normalize.py.

    This mirrors detector_api_wrapper.core.call_api exactly, just over
    HTTP. It does not raise on a failed detector lookup (that comes back
    as status="error" in the body); it only raises on a malformed
    request body, which FastAPI turns into a 422.
    """
    try:
        result = call_api(
            resource_id=request.resource_id,
            options=request.options,
            provider=request.provider,
            chain=request.chain,
            context=request.context,
        )
    except Exception as e:  # noqa: BLE001 - last-resort guard, fail closed
        # call_api already fails closed internally; this only catches a
        # genuinely unexpected error so the service still responds.
        raise HTTPException(status_code=500, detail=str(e)) from e

    return result.to_dict()
