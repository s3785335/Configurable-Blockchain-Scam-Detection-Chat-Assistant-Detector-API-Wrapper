"""
Guards the contract with the main application. If this fails after a
change to schema.py, the main repo's schema.py must be updated to match
(or vice versa) before release.
"""

from detector_api_wrapper.schema import AddressContext, DetectionResult, Evidence


def test_detection_result_fields():
    assert list(DetectionResult.model_fields) == [
        "label", "risk_type", "confidence", "evidence", "explanation", "reasoning_trace"]
    assert list(Evidence.model_fields) == ["description", "weight"]


def test_address_context_fields():
    assert list(AddressContext.model_fields) == [
        "chain", "address", "queried_at", "contract", "tx_history", "tokens",
        "liquidity", "fetcher_provenance"]


def test_tx_record_alias_round_trip():
    ctx = AddressContext.model_validate({
        "chain": "ethereum", "address": "0x1", "queried_at": "t",
        "tx_history": [{"hash": "h", "from": "a", "to": "b", "value": "1", "timestamp": "t"}],
    })
    assert ctx.model_dump(by_alias=True)["tx_history"][0]["from"] == "a"
