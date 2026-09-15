"""
Input & output sanitization.

This is the highest-priority component per the stakeholder ask: input
sanitization is treated as a first-class requirement, not an afterthought.

Rules implemented here (see draft, Section 3 - Security Considerations):
  - Reject early rather than trying to "clean" a malformed value.
  - Cap length and reject unexpected characters before deeper validation.
  - Validate identifier format with a strict pattern (checksum/structural
    validation should be added here if the real provider defines one).
  - Any option with a known set of valid values is checked against an
    explicit allow-list -- never passed through freely.
  - Never interpolate raw input into a URL or subprocess call; callers
    must go through these functions first.
"""

import re

from .config import DEFAULT_CONFIG, WrapperConfig
from .errors import InvalidInputError

# Conservative allow-list pattern: alphanumeric, underscore, hyphen only.
ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")


def sanitize_resource_id(resource_id: str, config: WrapperConfig = DEFAULT_CONFIG) -> str:
    """Validate and return a clean resource_id, or raise InvalidInputError."""
    if not isinstance(resource_id, str):
        raise InvalidInputError("resource_id must be a string.")

    # Cheap first line of defense: length check before pattern matching.
    if not (1 <= len(resource_id) <= config.id_max_length):
        raise InvalidInputError(
            f"resource_id must be between 1 and {config.id_max_length} characters."
        )

    if not ID_PATTERN.match(resource_id):
        raise InvalidInputError("resource_id does not match the expected format.")

    # TODO: if the real provider defines a checksum or structural rule
    # (e.g. a check digit), apply it here -- this catches values that are
    # technically valid-looking but still wrong. Left as a stub pending
    # confirmation of the real provider's identifier scheme.

    return resource_id


def sanitize_options(options: dict, config: WrapperConfig = DEFAULT_CONFIG) -> dict:
    """Validate options against an explicit allow-list of values.

    Any key not in the allow-list is silently dropped rather than passed
    through -- this also prevents accidental requests to unintended
    destinations via unexpected option keys.
    """
    if not isinstance(options, dict):
        raise InvalidInputError("options must be a dict.")

    clean: dict = {}
    for key, allowed_values in config.allowed_option_values.items():
        if key in options:
            if options[key] not in allowed_values:
                raise InvalidInputError(f"Invalid value for option '{key}'.")
            clean[key] = options[key]
    return clean


def sanitize_output(value: str) -> str:
    """
    Strip/escape a raw provider-returned string before it is rendered in a
    UI or passed to another system downstream.

    This is intentionally conservative: it strips control characters and
    HTML-significant characters. Replace with a proper escaping function
    (e.g. your templating engine's autoescape) at the point of use if the
    destination is HTML/SQL/shell -- this is a baseline, not a substitute
    for context-aware escaping.
    """
    if not isinstance(value, str):
        return value

    # Remove control characters.
    value = re.sub(r"[\x00-\x1f\x7f]", "", value)
    # Neutralize the most common HTML-injection characters.
    value = (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
    return value
