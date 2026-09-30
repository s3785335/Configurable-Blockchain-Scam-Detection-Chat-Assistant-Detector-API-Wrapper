import pytest

from detector_api_wrapper import call_api
from detector_api_wrapper.errors import InvalidInputError
from detector_api_wrapper.sanitize import sanitize_options, sanitize_resource_id


def test_sanitize_resource_id_accepts_valid():
    assert sanitize_resource_id("abc-123_XYZ") == "abc-123_XYZ"


def test_sanitize_resource_id_rejects_bad_characters():
    with pytest.raises(InvalidInputError):
        sanitize_resource_id("abc/123; DROP TABLE")


def test_sanitize_resource_id_rejects_too_long():
    with pytest.raises(InvalidInputError):
        sanitize_resource_id("a" * 200)


def test_sanitize_options_allow_list():
    assert sanitize_options({"mode": "strict"}) == {"mode": "strict"}
    with pytest.raises(InvalidInputError):
        sanitize_options({"mode": "not-a-real-mode"})


def test_call_api_fails_closed_on_bad_input():
    result = call_api("bad id with spaces")
    assert result.status == "error"
    assert result.error is not None
