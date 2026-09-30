"""
Response normalization.

Turns whatever the client's plugged-in detector returns into the main
application's DetectionResult (see schema.py), wrapped in an ApiResult
envelope that records how the call went.

Flow: raw detector JSON -> adapter.to_schema() (mapping) -> fill
defaults -> range checks -> sanitize every string -> DetectionResult.

Why an envelope: DetectionResult has no way to say "the detector failed".
Returning a made-up verdict on failure would be a fake success, so
failures come back as status="error" with result=None, and the bot
decides how to tell the user. Use `api_result.result` wherever the main
app expects a DetectionResult.
"""

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field, ValidationError

from .sanitize import sanitize_output
from .schema import DetectionResult, Evidence

Status = Literal["ok", "not_found", "error"]

# Caps keep a misbehaving detector from flooding the bot or the LLM.
MAX_TEXT_CHARS = 2000
MAX_TRACE_CHARS = 8000
MAX_EVIDENCE_ITEMS = 25
MAX_RISK_TYPE_CHARS = 64


class ApiResult(BaseModel):
    resource_id: str
    provider: str
    status: Status
    result: Optional[DetectionResult] = None
    checked_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    error: Optional[str] = None

    def to_dict(self) -> dict:
        """JSON-ready form, for sending across a container boundary."""
        return self.model_dump(mode="json")


def not_found_result(resource_id: str, provider: str) -> ApiResult:
    return ApiResult(
        resource_id=resource_id,
        provider=provider,
        status="not_found",
        result=DetectionResult(
            label="insufficient_evidence",
            confidence=0.0,
            evidence=[],
            explanation=(
                f"The '{provider}' detector has no record for this address, "
                "so there is not enough evidence to judge it."
            ),
            reasoning_trace=f"Detector '{provider}' reported no record for the resource.",
        ),
    )


def _clean(text: str, limit: int) -> str:
    return sanitize_output(str(text))[:limit]


def _default_explanation(provider: str, label: str, risk_type, confidence: float) -> str:
    verdicts = {
        "scam": "flagged this address as a likely scam",
        "not_scam": "did not flag this address as a scam",
        "insufficient_evidence": "did not have enough evidence to judge this address",
    }
    detail = f" (category: {risk_type})" if risk_type and label == "scam" else ""
    return (
        f"The external '{provider}' detector {verdicts[label]}{detail}, "
        f"with confidence {confidence:.2f}."
    )


def normalize_response(mapped, provider: str, resource_id: str) -> ApiResult:
    """Validate and sanitize mapped detector output into an ApiResult."""

    def fail(message: str) -> ApiResult:
        return ApiResult(resource_id=resource_id, provider=provider, status="error", error=message)

    if not isinstance(mapped, dict):
        return fail("Detector response could not be mapped to DetectionResult.")
    if "label" not in mapped:
        return fail("Detector response did not include a verdict (label) after mapping.")

    data = dict(mapped)
    if data.get("confidence") is None:
        return fail("Detector response did not include a confidence after mapping.")
    needs_explanation = not (
        isinstance(data.get("explanation"), str) and data["explanation"].strip()
    )
    if needs_explanation:
        data["explanation"] = ""  # replaced with a generated default below

    try:
        result = DetectionResult(**{k: data.get(k) for k in DetectionResult.model_fields if k in data})
    except ValidationError as e:
        fields = sorted({".".join(str(p) for p in err["loc"]) for err in e.errors()})
        return fail(f"Detector response does not fit DetectionResult (fields: {', '.join(fields)}).")
    except TypeError:
        return fail("Detector response does not fit DetectionResult.")

    # Range checks the main app's system prompt relies on (0.0-1.0).
    if not 0.0 <= result.confidence <= 1.0:
        return fail("Detector confidence is outside 0.0-1.0; check the mapping's scale.")
    if any(not 0.0 <= ev.weight <= 1.0 for ev in result.evidence):
        return fail("Detector evidence weight is outside 0.0-1.0; check weight_scale.")

    explanation = result.explanation
    if needs_explanation:
        explanation = _default_explanation(provider, result.label, result.risk_type, result.confidence)
    trace = result.reasoning_trace or (
        f"Verdict produced by external detector '{provider}' and mapped to "
        "DetectionResult by the Detector API Wrapper."
    )

    clean = DetectionResult(
        label=result.label,
        risk_type=_clean(result.risk_type, MAX_RISK_TYPE_CHARS) if result.risk_type else None,
        confidence=result.confidence,
        evidence=[
            Evidence(description=_clean(ev.description, MAX_TEXT_CHARS), weight=ev.weight)
            for ev in result.evidence[:MAX_EVIDENCE_ITEMS]
        ],
        explanation=_clean(explanation, MAX_TEXT_CHARS),
        reasoning_trace=_clean(trace, MAX_TRACE_CHARS),
    )
    return ApiResult(resource_id=resource_id, provider=provider, status="ok", result=clean)
