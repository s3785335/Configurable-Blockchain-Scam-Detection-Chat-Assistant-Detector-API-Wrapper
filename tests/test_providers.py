import asyncio
import json

import httpx
import pytest

from detector_api_wrapper import (
    GenericHttpAdapter,
    InvalidInputError,
    ProviderAdapter,
    WrapperConfig,
    call_api,
    call_api_async,
    detector_status,
    load_config,
    register_provider,
)
from detector_api_wrapper.config import get_api_key
from detector_api_wrapper.sanitize import sanitize_output_tree

CFG = WrapperConfig(rate_limit_per_second=0)
ADDR = "0x" + "ab" * 20

MAPPING = {
    "label": {"path": "result.verdict",
              "values": {"malicious": "scam", "clean": "not_scam", "unknown": "insufficient_evidence"}},
    "confidence": {"path": "result.confidence", "scale": 100},
    "risk_type": {"path": "result.category"},
    "evidence": {"path": "result.findings", "description": "message",
                 "weight": "severity", "weight_scale": 10},
    "explanation": {"path": "result.summary"},
}

GOOD = {"result": {
    "verdict": "MALICIOUS", "confidence": 85, "category": "rug_pull",
    "findings": [{"message": "Liquidity removed <b>fast</b>", "severity": 9}],
    "summary": "Liquidity was pulled shortly after launch.",
}}

def make_adapter(handler, **overrides):
    kwargs = dict(
        name="mock",
        url="https://detector.example/v1/check",
        id_param="address",
        mapping=MAPPING,
        transport=httpx.MockTransport(handler),
        async_transport=httpx.MockTransport(handler),
    )
    kwargs.update(overrides)
    return GenericHttpAdapter(**kwargs)

def ok_handler(request):
    return httpx.Response(200, json=GOOD)

def json_handler(payload):
    return lambda request: httpx.Response(200, json=payload)

def test_no_providers_returns_error_instead_of_crashing():
    result = call_api(ADDR, config=CFG)
    assert result.status == "error" and result.result is None
    assert "No providers registered" in result.error

def test_unknown_override_returns_error():
    register_provider(make_adapter(ok_handler))
    assert call_api(ADDR, provider="nope", config=CFG).status == "error"

def test_multiple_providers_without_default_returns_error():
    register_provider(make_adapter(ok_handler))
    register_provider(make_adapter(ok_handler, name="mock2"))
    assert call_api(ADDR, config=CFG).status == "error"

def test_default_provider_is_used():
    register_provider(make_adapter(ok_handler))
    register_provider(make_adapter(ok_handler, name="mock2"))
    cfg = WrapperConfig(rate_limit_per_second=0, default_provider="mock2")
    assert call_api(ADDR, config=cfg).provider == "mock2"

def test_missing_key_returns_error(monkeypatch):
    monkeypatch.delenv("API_WRAPPER_KEY")
    register_provider(make_adapter(ok_handler))
    result = call_api(ADDR, config=CFG)
    assert result.status == "error" and "API_WRAPPER_KEY" in result.error

def test_full_mapping_produces_detection_result():
    register_provider(make_adapter(ok_handler))
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "ok"
    r = outcome.result
    assert r.label == "scam"
    assert r.confidence == 0.85
    assert r.risk_type == "rug_pull"
    assert r.evidence[0].weight == 0.9
    assert r.evidence[0].description == "Liquidity removed &lt;b&gt;fast&lt;/b&gt;"
    assert r.explanation == "Liquidity was pulled shortly after launch."
    assert r.reasoning_trace

def test_unknown_label_value_fails_closed():
    payload = json.loads(json.dumps(GOOD))
    payload["result"]["verdict"] = "spicy"
    register_provider(make_adapter(json_handler(payload)))
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "error" and outcome.result is None

def test_missing_label_fails_closed():
    register_provider(make_adapter(json_handler({"result": {"confidence": 50}})))
    assert call_api(ADDR, config=CFG).status == "error"

def test_out_of_range_confidence_fails_closed():
    mapping = {**MAPPING, "confidence": {"path": "result.confidence"}}
    register_provider(make_adapter(ok_handler, mapping=mapping))
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "error" and "scale" in outcome.error

def test_missing_explanation_gets_default():
    payload = json.loads(json.dumps(GOOD))
    del payload["result"]["summary"]
    register_provider(make_adapter(json_handler(payload)))
    r = call_api(ADDR, config=CFG).result
    assert "mock" in r.explanation and "scam" in r.explanation

def test_label_from_risk_score():
    mapping = {
        "risk_score": {"path": "risk", "scale": 100},
        "label": {"from_score": True, "scam_threshold": 0.7},
        "evidence": {"path": "reasons", "default_weight": 0.5},
    }
    register_provider(make_adapter(json_handler({"risk": 20, "reasons": ["Verified source"]}),
                                   mapping=mapping))
    r = call_api(ADDR, config=CFG).result
    assert r.label == "not_scam"
    assert r.confidence == pytest.approx(0.8)
    assert r.evidence[0].description == "Verified source" and r.evidence[0].weight == 0.5

def test_passthrough_when_detector_already_speaks_schema():
    native = {"label": "not_scam", "confidence": 0.7, "explanation": "Looks fine.",
              "evidence": [{"description": "Verified", "weight": 0.6}]}
    register_provider(make_adapter(json_handler(native), mapping=None))
    r = call_api(ADDR, config=CFG).result
    assert r.label == "not_scam" and r.evidence[0].weight == 0.6

def test_404_returns_insufficient_evidence():
    register_provider(make_adapter(lambda r: httpx.Response(404)))
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "not_found"
    assert outcome.result.label == "insufficient_evidence"

def test_result_passes_main_app_validation():
    """What the main app does: DetectionResult(**data)."""
    from detector_api_wrapper.schema import DetectionResult
    register_provider(make_adapter(ok_handler))
    data = call_api(ADDR, config=CFG).to_dict()["result"]
    assert DetectionResult(**data).label == "scam"

def test_request_params_and_auth():
    seen = {}

    def handler(request):
        seen["request"] = request
        return ok_handler(request)

    register_provider(make_adapter(handler, chain_param="network",
                                   option_params={"mode": "strictness"}))
    call_api(ADDR, options={"mode": "strict"}, chain="BSC", config=CFG)
    req = seen["request"]
    assert req.url.path == "/v1/check"
    assert req.url.params["address"] == ADDR
    assert req.url.params["network"] == "bsc"
    assert req.url.params["strictness"] == "strict"
    assert req.headers["Authorization"] == "Bearer test-key"

def test_invalid_chain_rejected():
    register_provider(make_adapter(ok_handler))
    assert call_api(ADDR, chain="eth/../x", config=CFG).status == "error"

def context_for(address, chain="ethereum"):
    return {
        "chain": chain, "address": address, "queried_at": "2026-09-30T00:00:00Z",
        "tx_history": [{"hash": "0x1", "from": "0xa", "to": "0xb", "value": "1",
                        "timestamp": "2026-09-01T00:00:00Z"}],
    }

def test_context_detector_receives_context_with_aliases():
    seen = {}

    def handler(request):
        seen["body"] = json.loads(request.content)
        return ok_handler(request)

    register_provider(make_adapter(handler, method="POST",
                                   required_input_type="address_with_context"))
    outcome = call_api(ADDR, context=context_for(ADDR), config=CFG)
    assert outcome.status == "ok"
    assert seen["body"]["context"]["tx_history"][0]["from"] == "0xa"

def test_context_detector_without_context_errors():
    register_provider(make_adapter(ok_handler, method="POST",
                                   required_input_type="address_with_context"))
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "error" and "AddressContext" in outcome.error

def test_context_for_other_address_rejected():
    register_provider(make_adapter(ok_handler, method="POST",
                                   required_input_type="address_with_context"))
    other = "0x" + "cd" * 20
    assert call_api(ADDR, context=context_for(other), config=CFG).status == "error"

def test_context_detector_must_use_post():
    with pytest.raises(ValueError):
        make_adapter(ok_handler, required_input_type="address_with_context")

def test_http_error_returns_error_without_body():
    register_provider(make_adapter(lambda r: httpx.Response(500, text="secret internal detail")))
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "error"
    assert "500" in outcome.error and "secret" not in outcome.error

def test_non_json_returns_error():
    register_provider(make_adapter(lambda r: httpx.Response(200, text="<html>")))
    assert call_api(ADDR, config=CFG).status == "error"

def test_timeout_returns_error():
    def handler(request):
        raise httpx.ReadTimeout("slow", request=request)

    register_provider(make_adapter(handler))
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "error" and "timed out" in outcome.error

def test_redirects_are_not_followed():
    register_provider(make_adapter(
        lambda r: httpx.Response(302, headers={"Location": "https://evil.example/"})))
    assert call_api(ADDR, config=CFG).status == "error"

def test_results_are_cached_and_copied():
    calls = []

    def handler(request):
        calls.append(1)
        return ok_handler(request)

    register_provider(make_adapter(handler))
    call_api(ADDR, config=CFG)
    call_api(ADDR, config=CFG).result.confidence = 0.0
    assert call_api(ADDR, config=CFG).result.confidence == 0.85
    assert len(calls) == 1

def test_async_path():
    register_provider(make_adapter(ok_handler))
    outcome = asyncio.run(call_api_async(ADDR, config=CFG))
    assert outcome.status == "ok" and outcome.result.label == "scam"

@pytest.mark.parametrize("url", ["http://detector.example", "ftp://x", "not a url",
                                 "https://user:pw@detector.example"])
def test_rejects_unsafe_urls(url):
    with pytest.raises(ValueError):
        GenericHttpAdapter(name="x", url=url, id_param="id")

def test_allows_http_only_when_explicit():
    GenericHttpAdapter(name="x", url="http://detector:8000/check", id_param="id",
                       allow_insecure_http=True)

@pytest.mark.parametrize("definition", [
    {"urll": "typo"},
    {"mapping": {"lable": {"path": "x"}}},
    {"mapping": {"label": {"path": "v", "values": {"bad": "definitely_scam"}}}},
    {"mapping": {"label": {"from_score": True}}},
])
def test_rejects_bad_config(definition):
    base = {"name": "x", "url": "https://a.example", "id_param": "id"}
    with pytest.raises(ValueError):
        GenericHttpAdapter.from_definition({**base, **definition})

class EvmOnly(ProviderAdapter):
    name = "evm"

    def call(self, request, timeout):
        return {"score": 5}

    def to_schema(self, raw):
        return {"label": "not_scam", "confidence": 0.95 - raw["score"] / 100,
                "explanation": "Clean history."}

    def validate_resource_id(self, resource_id):
        if not resource_id.startswith("0x"):
            raise InvalidInputError("not an EVM address")

def test_custom_adapter_and_validation_hook():
    register_provider(EvmOnly())
    assert call_api(ADDR, config=CFG).result.confidence == pytest.approx(0.9)
    bad = call_api("abc", config=CFG)
    assert bad.status == "error" and "EVM" in bad.error

def test_custom_adapter_unexpected_exception_is_hidden():
    class Broken(EvmOnly):
        name = "broken"

        def call(self, request, timeout):
            raise KeyError("internal secret")

    register_provider(Broken())
    outcome = call_api(ADDR, config=CFG)
    assert outcome.status == "error" and "secret" not in outcome.error

def test_detector_status_reports_configured(monkeypatch):
    register_provider(make_adapter(ok_handler, method="POST",
                                   required_input_type="address_with_context"))
    assert detector_status(config=CFG) == {
        "selected_detector": "mock", "detector_configured": True,
        "required_input_type": "address_with_context"}
    monkeypatch.delenv("API_WRAPPER_KEY")
    assert detector_status(config=CFG)["detector_configured"] is False

def test_detector_status_with_nothing_registered():
    assert detector_status(config=CFG)["detector_configured"] is False

def test_config_file_registers_provider(tmp_path, monkeypatch):
    path = tmp_path / "providers.json"
    path.write_text(json.dumps({"providers": [
        {"name": "fromfile", "url": "https://a.example/check", "id_param": "id"}
    ]}))
    monkeypatch.setenv("DETECTOR_CONFIG_PATH", str(path))
    monkeypatch.setenv("DETECTOR_TIMEOUT_SECONDS", "2.5")
    cfg = load_config()
    assert cfg.timeout_seconds == 2.5 and cfg.providers[0]["name"] == "fromfile"

def test_key_from_secret_file(tmp_path, monkeypatch):
    monkeypatch.delenv("API_WRAPPER_KEY")
    secret = tmp_path / "key"
    secret.write_text("from-file\n")
    monkeypatch.setenv("API_WRAPPER_KEY_FILE", str(secret))
    assert get_api_key() == "from-file"

def test_accepts_evm_tx_hash_length():
    register_provider(make_adapter(ok_handler))
    assert call_api("0x" + "a" * 64, config=CFG).status == "ok"

def test_output_tree_rejects_deep_nesting():
    deep = current = {}
    for _ in range(20):
        current["x"] = {}
        current = current["x"]
    with pytest.raises(ValueError):
        sanitize_output_tree(deep)

from types import SimpleNamespace

import pytest

from detector_api_wrapper.providers.http_adapter import GenericHttpAdapter, _validate_mapping

OVERRIDE_MAPPING = {
    "risk_score": {"path": "riskScore", "scale": 100},
    "label": {
        "from_score": True,
        "scam_threshold": 0.7,
        "overrides": [
            {"path": "addressInfo.txCount", "equals": 0, "label": "insufficient_evidence"},
            {"path": "riskLevel", "equals": "unknown", "label": "insufficient_evidence"},
        ],
    },
}

def _map(raw):
    return GenericHttpAdapter.to_schema(SimpleNamespace(mapping=OVERRIDE_MAPPING), raw)

def test_override_forces_insufficient_evidence_for_unused_address():
    out = _map({"riskLevel": "low", "riskScore": 0, "addressInfo": {"txCount": 0}})
    assert out["label"] == "insufficient_evidence" and out["confidence"] == 0.0

def test_override_matches_string_case_insensitively():
    out = _map({"riskLevel": "Unknown", "riskScore": 0, "addressInfo": {"txCount": 5}})
    assert out["label"] == "insufficient_evidence"

def test_no_override_match_keeps_score_label():
    out = _map({"riskLevel": "low", "riskScore": 0, "addressInfo": {"txCount": 120}})
    assert out["label"] == "not_scam"

def test_missing_override_path_is_skipped():
    out = _map({"riskLevel": "low", "riskScore": 90})
    assert out["label"] == "scam"

@pytest.mark.parametrize("overrides", [
    {"path": "x", "equals": 0, "label": "x"},
    [{"path": "x", "label": "insufficient_evidence"}],
    [{"path": "x", "equals": 0, "label": "definitely_scam"}],
])
def test_bad_overrides_rejected(overrides):
    mapping = {"label": {"path": "v", "overrides": overrides}}
    with pytest.raises(ValueError):
        _validate_mapping("p", mapping)