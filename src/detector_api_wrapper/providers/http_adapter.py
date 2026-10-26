import re
from urllib.parse import urlsplit

import httpx

from ..config import get_api_key
from ..errors import NotFoundError, ProviderError
from ..schema import DetectionResult
from .base import DetectorRequest, ProviderAdapter

MAX_RESPONSE_BYTES = 1_000_000
_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_HEADER_RE = re.compile(r"^[A-Za-z0-9\-]{1,64}$")
_ENV_RE = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
_ALLOWED_KEYS = {
    "name", "url", "method", "id_param", "api_key_env", "auth_header",
    "auth_scheme", "static_params", "option_params", "mapping",
    "allow_insecure_http", "not_found_status", "required_input_type",
    "chain_param", "context_param",
}
_MAPPING_FIELDS = set(DetectionResult.model_fields) | {"risk_score"}
_LABELS = {"scam", "not_scam", "insufficient_evidence"}

def _resolve_path(data, path: str):
    current = data
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current

class GenericHttpAdapter(ProviderAdapter):
    def __init__(
        self,
        name: str,
        url: str,
        id_param: str,
        method: str = "GET",
        api_key_env: str | None = "API_WRAPPER_KEY",
        auth_header: str = "Authorization",
        auth_scheme: str = "Bearer",
        static_params: dict | None = None,
        option_params: dict | None = None,
        mapping: dict | None = None,
        required_input_type: str = "address",
        chain_param: str | None = None,
        context_param: str = "context",
        allow_insecure_http: bool = False,
        not_found_status: tuple = (404,),
        transport: httpx.BaseTransport | None = None,
        async_transport: httpx.AsyncBaseTransport | None = None,
    ):
        if not isinstance(name, str) or not _NAME_RE.match(name):
            raise ValueError("Provider 'name' must be 1-64 letters, digits, '_' or '-'.")
        parts = urlsplit(url if isinstance(url, str) else "")
        allowed_schemes = {"https", "http"} if allow_insecure_http else {"https"}
        if parts.scheme not in allowed_schemes or not parts.netloc:
            raise ValueError(
                f"Provider '{name}': url must be an absolute https:// URL "
                "(set allow_insecure_http only for a private container network)."
            )
        if parts.username or parts.password:
            raise ValueError(f"Provider '{name}': credentials must not be embedded in the url.")
        method = str(method).upper()
        if method not in {"GET", "POST"}:
            raise ValueError(f"Provider '{name}': method must be GET or POST.")
        if not isinstance(id_param, str) or not id_param:
            raise ValueError(f"Provider '{name}': id_param is required.")
        if api_key_env is not None and not _ENV_RE.match(api_key_env):
            raise ValueError(f"Provider '{name}': api_key_env must be an environment variable name.")
        if not _HEADER_RE.match(auth_header):
            raise ValueError(f"Provider '{name}': auth_header is not a valid header name.")
        for label, value in (("static_params", static_params),
                             ("option_params", option_params)):
            if value is not None and not (
                isinstance(value, dict) and all(isinstance(k, str) for k in value)
            ):
                raise ValueError(f"Provider '{name}': {label} must be an object.")
        if required_input_type not in {"address", "address_with_context"}:
            raise ValueError(
                f"Provider '{name}': required_input_type must be 'address' or "
                "'address_with_context'."
            )
        if required_input_type == "address_with_context" and method != "POST":
            raise ValueError(
                f"Provider '{name}': 'address_with_context' detectors must use POST, "
                "since the context is sent as a JSON body."
            )
        _validate_mapping(name, mapping or {})

        self.name = name
        self.url = url
        self.method = method
        self.id_param = id_param
        self.api_key_env = api_key_env
        self.auth_header = auth_header
        self.auth_scheme = auth_scheme or ""
        self.static_params = dict(static_params or {})
        self.option_params = dict(option_params or {})
        self.mapping = dict(mapping or {})
        self.required_input_type = required_input_type
        self.chain_param = chain_param
        self.context_param = context_param
        self.not_found_status = tuple(not_found_status)
        self._transport = transport
        self._async_transport = async_transport

    @classmethod
    def from_definition(cls, definition: dict) -> "GenericHttpAdapter":
        if not isinstance(definition, dict):
            raise ValueError("Each provider definition must be an object.")
        unknown = set(definition) - _ALLOWED_KEYS
        if unknown:
            raise ValueError(f"Unknown provider config keys: {sorted(unknown)}")
        kwargs = dict(definition)
        if "not_found_status" in kwargs:
            kwargs["not_found_status"] = tuple(kwargs["not_found_status"])
        return cls(**kwargs)

    def _build_request(self, req: DetectorRequest) -> dict:
        params = dict(self.static_params)
        for option_key, provider_key in self.option_params.items():
            if option_key in req.options:
                params[provider_key] = req.options[option_key]
        if self.chain_param:
            params[self.chain_param] = req.chain
        params[self.id_param] = req.resource_id
        if self.required_input_type == "address_with_context":
            params[self.context_param] = req.context

        headers = {"Accept": "application/json"}
        if self.api_key_env:
            key = get_api_key(self.api_key_env)
            value = f"{self.auth_scheme} {key}" if self.auth_scheme else key
            headers[self.auth_header] = value

        request = {"method": self.method, "url": self.url, "headers": headers}
        if self.method == "GET":
            request["params"] = params
        else:
            request["json"] = params
        return request

    def _parse_response(self, response: httpx.Response) -> dict:
        if response.status_code in self.not_found_status:
            raise NotFoundError(f"Provider '{self.name}' has no record for this resource.")
        if not response.is_success:
            raise ProviderError(
                f"Provider '{self.name}' returned HTTP {response.status_code}."
            )
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise ProviderError(f"Provider '{self.name}' response exceeded size limit.")
        try:
            data = response.json()
        except ValueError:
            raise ProviderError(f"Provider '{self.name}' did not return valid JSON.") from None
        if not isinstance(data, dict):
            raise ProviderError(f"Provider '{self.name}' returned JSON that is not an object.")
        return data

    def is_configured(self) -> bool:
        if not self.api_key_env:
            return True
        try:
            get_api_key(self.api_key_env)
        except RuntimeError:
            return False
        return True

    def call(self, request: DetectorRequest, timeout: float) -> dict:
        request = self._build_request(request)
        try:
            with httpx.Client(
                timeout=timeout, follow_redirects=False, transport=self._transport
            ) as client:
                response = client.request(**request)
        except httpx.TimeoutException:
            raise ProviderError(f"Provider '{self.name}' timed out after {timeout}s.") from None
        except httpx.HTTPError as e:
            raise ProviderError(
                f"Provider '{self.name}' request failed ({type(e).__name__})."
            ) from None
        return self._parse_response(response)

    async def acall(self, request: DetectorRequest, timeout: float) -> dict:
        request = self._build_request(request)
        try:
            async with httpx.AsyncClient(
                timeout=timeout, follow_redirects=False, transport=self._async_transport
            ) as client:
                response = await client.request(**request)
        except httpx.TimeoutException:
            raise ProviderError(f"Provider '{self.name}' timed out after {timeout}s.") from None
        except httpx.HTTPError as e:
            raise ProviderError(
                f"Provider '{self.name}' request failed ({type(e).__name__})."
            ) from None
        return self._parse_response(response)

    def to_schema(self, raw: dict) -> dict:
        if not self.mapping:
            return raw
        m = self.mapping
        out: dict = {}

        risk = None
        if "risk_score" in m:
            risk = _number(raw, m["risk_score"], "risk_score")

        label_spec = m.get("label", {})
        if label_spec.get("from_score"):
            if risk is None:
                raise ProviderError("Mapping: label.from_score needs risk_score, which was missing.")
            threshold = float(label_spec.get("scam_threshold", 0.5))
            out["label"] = "scam" if risk >= threshold else "not_scam"
            out["confidence"] = risk if out["label"] == "scam" else 1.0 - risk
        elif label_spec:
            found, value = _resolve_path(raw, label_spec["path"])
            if found:
                out["label"] = _translate(value, label_spec.get("values"), "label")

        if "confidence" in m:
            value = _number(raw, m["confidence"], "confidence")
            if value is not None:
                out["confidence"] = value

        for rule in label_spec.get("overrides", []):
            found, value = _resolve_path(raw, rule["path"])
            if found and _matches(value, rule["equals"]):
                out["label"] = rule["label"]
                if rule["label"] == "insufficient_evidence":
                    out["confidence"] = 0.0
                break

        for text_field in ("risk_type", "explanation", "reasoning_trace"):
            if text_field in m:
                found, value = _resolve_path(raw, m[text_field]["path"])
                if found and value is not None:
                    values = m[text_field].get("values")
                    out[text_field] = _translate(value, values, text_field) if values else str(value)

        if "evidence" in m:
            out["evidence"] = _map_evidence(raw, m["evidence"])
        return out

def _validate_mapping(name: str, mapping) -> None:
    if not isinstance(mapping, dict):
        raise ValueError(f"Provider '{name}': mapping must be an object.")
    unknown = set(mapping) - _MAPPING_FIELDS
    if unknown:
        raise ValueError(f"Provider '{name}': unknown mapping fields {sorted(unknown)}.")
    for key, spec in mapping.items():
        if not isinstance(spec, dict):
            raise ValueError(f"Provider '{name}': mapping.{key} must be an object.")
        if "path" not in spec and not (key == "label" and spec.get("from_score")):
            raise ValueError(f"Provider '{name}': mapping.{key} needs a 'path'.")
    label = mapping.get("label", {})
    for provider_value, our_value in (label.get("values") or {}).items():
        if our_value not in _LABELS:
            raise ValueError(
                f"Provider '{name}': mapping.label.values maps {provider_value!r} to "
                f"{our_value!r}; must be one of {sorted(_LABELS)}."
            )
    if label.get("from_score") and "risk_score" not in mapping:
        raise ValueError(f"Provider '{name}': label.from_score requires a risk_score mapping.")
    overrides = label.get("overrides", [])
    if not isinstance(overrides, list):
        raise ValueError(f"Provider '{name}': mapping.label.overrides must be a list.")
    for i, rule in enumerate(overrides):
        if not isinstance(rule, dict) or "path" not in rule or "equals" not in rule:
            raise ValueError(
                f"Provider '{name}': mapping.label.overrides[{i}] needs 'path', 'equals' and 'label'."
            )
        if rule.get("label") not in _LABELS:
            raise ValueError(
                f"Provider '{name}': mapping.label.overrides[{i}].label must be one of {sorted(_LABELS)}."
            )

def _matches(value, expected) -> bool:
    if isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(value) == float(expected)
        except (TypeError, ValueError):
            return False
    if isinstance(expected, str) and isinstance(value, str):
        return value.strip().lower() == expected.strip().lower()
    return value == expected

def _translate(value, values: dict | None, field_name: str):
    if values is None:
        return value
    for provider_value, ours in values.items():
        if str(value).strip().lower() == str(provider_value).strip().lower():
            return ours
    raise ProviderError(f"Mapping: unrecognised {field_name} value from detector.")

def _number(raw, spec: dict, field_name: str):
    found, value = _resolve_path(raw, spec["path"])
    if not found or value is None:
        return None
    if isinstance(value, bool):
        raise ProviderError(f"Mapping: {field_name} is not a number.")
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ProviderError(f"Mapping: {field_name} is not a number.") from None
    scale = float(spec.get("scale", 1))
    if scale <= 0:
        raise ProviderError(f"Mapping: {field_name}.scale must be positive.")
    return number / scale


def _map_evidence(raw, spec: dict) -> list:
    found, items = _resolve_path(raw, spec["path"])
    if not found or items is None:
        return []
    if not isinstance(items, list):
        raise ProviderError("Mapping: evidence path does not point to a list.")
    default_weight = spec.get("default_weight")
    weight_scale = float(spec.get("weight_scale", 1))
    evidence = []
    for item in items:
        if isinstance(item, str) and "description" not in spec:
            description = item
        else:
            ok, description = _resolve_path(item, spec.get("description", "description"))
            if not ok or description is None:
                continue
        weight = default_weight
        if "weight" in spec:
            ok, w = _resolve_path(item, spec["weight"])
            if ok and w is not None and not isinstance(w, bool):
                try:
                    weight = float(w) / weight_scale
                except (TypeError, ValueError):
                    raise ProviderError("Mapping: evidence weight is not a number.") from None
        if weight is None:
            raise ProviderError("Mapping: evidence item has no weight and no default_weight is set.")
        evidence.append({"description": str(description), "weight": weight})
    return evidence