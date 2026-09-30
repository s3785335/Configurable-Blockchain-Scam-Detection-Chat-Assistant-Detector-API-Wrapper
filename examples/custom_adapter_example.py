"""
Example of the "custom code" plug-in route, for detectors the generic HTTP
adapter can't describe (e.g. an SDK, signed requests, or several calls
per lookup).

Put a module like this on the Python path (in a container: copy it into
the image or mount it), then set:
    DETECTOR_ADAPTER_MODULES=custom_adapter_example
"""

from detector_api_wrapper import (
    DetectorRequest,
    InvalidInputError,
    ProviderAdapter,
    register_provider,
)


class ExampleAdapter(ProviderAdapter):
    name = "example"
    required_input_type = "address"  # or "address_with_context"

    def call(self, request: DetectorRequest, timeout: float) -> dict:
        # Call your detector here using request.resource_id / request.chain
        # (and request.context for address_with_context), honouring
        # `timeout`. Return its raw JSON. Raise on failure; never return a
        # fake success.
        raise NotImplementedError

    def to_schema(self, raw: dict) -> dict:
        # Return DetectionResult fields. confidence and weights must be 0-1.
        return {
            "label": "scam" if raw["is_scam"] else "not_scam",
            "risk_type": raw.get("category"),
            "confidence": raw["score"] / 100,
            "evidence": [{"description": r, "weight": 0.5} for r in raw.get("reasons", [])],
            "explanation": raw.get("summary", ""),
        }

    def validate_resource_id(self, resource_id: str) -> None:
        # Optional identifier check, e.g. an EVM address shape check.
        if not (resource_id.startswith("0x") and len(resource_id) == 42):
            raise InvalidInputError("resource_id is not an EVM address.")


register_provider(ExampleAdapter())
