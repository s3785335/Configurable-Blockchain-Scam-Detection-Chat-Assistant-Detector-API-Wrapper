"""
Input & output sanitization.

This is the highest-priority component per the stakeholder ask: input
sanitization is treated as a first-class requirement, not an afterthought.

Rules implemented here (see draft, Section 3 - Security Considerations):
  - Reject early rather than trying to "clean" a malformed value.
  - Cap length and reject unexpected characters before deeper validation.
  - Validate identifier format with a strict, configurable pattern.
    Provider-specific checksum/structural checks run afterwards through
    the adapter's validate_resource_id() hook, because each client plugs
    in a different API with its own identifier scheme.
  - Any option with a known set of valid values is checked against an
    explicit allow-list -- never passed through freely.
  - Never interpolate raw input into a URL or subprocess call; callers
    must go through these functions first.
"""

import re
from functools import lru_cache

from .config import DEFAULT_CONFIG, WrapperConfig
from .errors import InvalidInputError


@lru_cache(maxsize=8)
def _compiled(pattern: str) -> re.Pattern:
    return re.compile(pattern)


def sanitize_resource_id(resource_id: str, config: WrapperConfig = DEFAULT_CONFIG) -> str:
    """Validate and return a clean resource_id, or raise InvalidInputError."""
    if not isinstance(resource_id, str):
        raise InvalidInputError("resource_id must be a string.")

    # Cheap first line of defense: length check before pattern matching.
    if not (1 <= len(resource_id) <= config.id_max_length):
        raise InvalidInputError(
            f"resource_id must be between 1 and {config.id_max_length} characters."
        )

    # fullmatch, so a trailing newline can't slip past a "$" anchor.
    if not _compiled(config.id_pattern).fullmatch(resource_id):
        raise InvalidInputError("resource_id does not match the expected format.")

    # Provider-specific checks (checksums, check digits, address formats)
    # are applied by core.call_api via adapter.validate_resource_id() once
    # the provider is known.

    return resource_id


CHAIN_PATTERN = re.compile(r"[a-z0-9][a-z0-9_\-]{0,31}")


def sanitize_chain(chain, default: str = "ethereum") -> str:
    """
    Validate a chain name such as "ethereum" or "bsc" (lowercased).
    Mirrors BusinessAnalyserOutput.chain, which defaults to "ethereum".
    """
    if chain is None:
        return default
    if not isinstance(chain, str):
        raise InvalidInputError("chain must be a string.")
    chain = chain.strip().lower()
    if not CHAIN_PATTERN.fullmatch(chain):
        raise InvalidInputError("chain does not match the expected format.")
    return chain


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


MAX_OUTPUT_DEPTH = 10


def sanitize_output_tree(value, _depth: int = 0):
    """
    Apply sanitize_output to every string in a provider response, including
    dict keys and nested lists/dicts. Non-JSON types are dropped, and
    nesting beyond MAX_OUTPUT_DEPTH is rejected, so nothing unexpected
    reaches the bot.
    """
    if _depth > MAX_OUTPUT_DEPTH:
        raise ValueError("Provider response is nested too deeply.")
    if isinstance(value, str):
        return sanitize_output(value)
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, dict):
        return {
            sanitize_output(str(k)): sanitize_output_tree(v, _depth + 1)
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [sanitize_output_tree(v, _depth + 1) for v in value]
    return None
