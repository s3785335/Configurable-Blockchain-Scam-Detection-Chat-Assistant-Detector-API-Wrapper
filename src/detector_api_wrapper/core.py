"""
Core entry point.

The wrapper exposes one primary entry point (call_api / call_api_async).
Everything else -- provider selection, sanitization, response parsing --
is a private helper called from inside it, so the rest of the system only
ever talks to this one function. See draft Section 1.

Every path fails closed: bad input, missing configuration, an unknown
provider, a timeout or an unexpected provider response all come back as
an ApiResult with status="error" (or "not_found"), never as a raised
exception or a fake success.
"""

import copy
import logging

from .cache import SimpleCache
from .config import DEFAULT_CONFIG, WrapperConfig
from .errors import InvalidInputError, NotFoundError, ProviderError
from .logging_audit import log_call
from .normalize import ApiResult, normalize_response, not_found_result
from .providers.base import DetectorRequest, ProviderAdapter
from .providers.registry import get_adapter, list_providers, load_configured_providers
from .providers.selector import select_provider
from .ratelimit import RateLimiter
from .sanitize import sanitize_chain, sanitize_options, sanitize_resource_id
from .schema import AddressContext

_logger = logging.getLogger("detector_api_wrapper")
_cache = SimpleCache(ttl_seconds=DEFAULT_CONFIG.cache_ttl_seconds)
_rate_limiter = RateLimiter()


def _error(resource_id, provider: str, message: str, status: str = "error") -> ApiResult:
    return ApiResult(resource_id=str(resource_id), provider=provider, status=status, error=message)


def _validate_context(context, clean_id: str, chain: str) -> dict:
    """Validate an AddressContext (model or dict) and return it JSON-ready."""
    try:
        model = context if isinstance(context, AddressContext) else AddressContext.model_validate(context)
    except Exception:  # noqa: BLE001 - pydantic ValidationError or bad type
        raise InvalidInputError("context is not a valid AddressContext.") from None
    if model.address.lower() != clean_id.lower():
        raise InvalidInputError("context.address does not match resource_id.")
    if model.chain.strip().lower() != chain:
        raise InvalidInputError("context.chain does not match chain.")
    return model.model_dump(mode="json", by_alias=True)


def _prepare(resource_id, options, provider, config, chain, context):
    """
    Steps shared by the sync and async paths: sanitize, select, validate,
    check the cache. Returns (ApiResult, None, None, None) when finished
    early, or (None, adapter, DetectorRequest, cache_key) to proceed.
    """
    done = lambda result: (result, None, None, None)  # noqa: E731

    # 1. Sanitize input first. Reject early rather than trying to "clean"
    #    a malformed value.
    try:
        clean_id = sanitize_resource_id(resource_id, config)
        clean_options = sanitize_options(options or {}, config)
        clean_chain = sanitize_chain(chain)
    except InvalidInputError as e:
        return done(_error(resource_id, "none", str(e)))

    # 2. Load configured providers and select one (manual override first).
    try:
        load_configured_providers(config)
        selected = select_provider(clean_options, config, override=provider)
        adapter = get_adapter(selected)
    except (ProviderError, ValueError, RuntimeError) as e:
        return done(_error(clean_id, provider or "none", str(e)))

    # 3. Detector-specific identifier checks (e.g. checksums), and the
    #    AddressContext for detectors that need it.
    try:
        adapter.validate_resource_id(clean_id)
        clean_context = None
        if adapter.required_input_type == "address_with_context":
            if context is None:
                raise InvalidInputError(
                    f"Detector '{adapter.name}' requires an AddressContext (address_with_context)."
                )
            clean_context = _validate_context(context, clean_id, clean_chain)
    except InvalidInputError as e:
        return done(_error(clean_id, adapter.name, str(e)))

    request = DetectorRequest(
        resource_id=clean_id, chain=clean_chain, options=clean_options, context=clean_context
    )

    # 4. Cache (address-only lookups; a context changes on every fetch).
    #    Return copies so callers can't mutate the cached result.
    cache_key = None
    if clean_context is None:
        cache_key = SimpleCache.make_key(
            clean_id, {**clean_options, "_chain": clean_chain}, adapter.name
        )
        cached = _cache.get(cache_key)
        if cached is not None:
            return done(copy.deepcopy(cached))

    return None, adapter, request, cache_key


def _store(cache_key, result: ApiResult) -> ApiResult:
    if cache_key is not None:
        _cache.set(cache_key, result)
    return copy.deepcopy(result)


def _finish(adapter: ProviderAdapter, request: DetectorRequest, cache_key, raw=None, exc=None) -> ApiResult:
    """Turn a detector response (or failure) into the final ApiResult."""
    clean_id, clean_options = request.resource_id, request.options
    if isinstance(exc, NotFoundError):
        log_call(clean_id, adapter.name, clean_options, None, error=str(exc))
        return _store(cache_key, not_found_result(clean_id, adapter.name))
    if isinstance(exc, (ProviderError, RuntimeError)):
        # Our own adapters and config raise these with safe messages.
        log_call(clean_id, adapter.name, clean_options, None, error=str(exc))
        return _error(clean_id, adapter.name, str(exc))
    if exc is not None:
        # Unexpected exception, possibly from a custom adapter: keep the
        # detail in the audit log only, return a generic message.
        log_call(clean_id, adapter.name, clean_options, None, error=repr(exc))
        return _error(clean_id, adapter.name, "Provider call failed unexpectedly.")

    log_call(clean_id, adapter.name, clean_options, raw)

    # 5. Map to the schema and normalize (sanitizes all output).
    try:
        mapped = adapter.to_schema(raw)
    except Exception as e:  # noqa: BLE001 - fail closed on bad mappings
        _logger.warning("to_schema failed for provider %s: %r", adapter.name, e)
        return _error(clean_id, adapter.name, "Provider response could not be mapped.")
    result = normalize_response(mapped, adapter.name, clean_id)
    if result.status == "ok":
        return _store(cache_key, result)
    return result


def call_api(
    resource_id: str,
    options: dict | None = None,
    provider: str | None = None,
    config: WrapperConfig = DEFAULT_CONFIG,
    *,
    chain: str | None = None,
    context: AddressContext | dict | None = None,
) -> ApiResult:
    """
    Run the configured detector for an address and return its verdict.

    `result.result` is a DetectionResult matching the main application's
    schema when status is "ok" or "not_found"; it is None on "error".
    Pass `context` (an AddressContext) for detectors whose
    required_input_type is "address_with_context". Fails closed.
    """
    early, adapter, request, cache_key = _prepare(
        resource_id, options, provider, config, chain, context
    )
    if early is not None:
        return early
    try:
        _rate_limiter.wait(adapter.name, config.rate_limit_per_second)
        raw = adapter.call(request, config.timeout_seconds)
    except Exception as e:  # noqa: BLE001 - deliberately broad: fail closed
        return _finish(adapter, request, cache_key, exc=e)
    return _finish(adapter, request, cache_key, raw=raw)


async def call_api_async(
    resource_id: str,
    options: dict | None = None,
    provider: str | None = None,
    config: WrapperConfig = DEFAULT_CONFIG,
    *,
    chain: str | None = None,
    context: AddressContext | dict | None = None,
) -> ApiResult:
    """Async mirror of call_api, for concurrent lookups."""
    early, adapter, request, cache_key = _prepare(
        resource_id, options, provider, config, chain, context
    )
    if early is not None:
        return early
    try:
        await _rate_limiter.await_slot(adapter.name, config.rate_limit_per_second)
        raw = await adapter.acall(request, config.timeout_seconds)
    except Exception as e:  # noqa: BLE001 - deliberately broad: fail closed
        return _finish(adapter, request, cache_key, exc=e)
    return _finish(adapter, request, cache_key, raw=raw)


def detector_status(provider: str | None = None, config: WrapperConfig = DEFAULT_CONFIG) -> dict:
    """
    Report which detector would be used, in the shape of the matching
    BusinessAnalyserOutput fields, so the main app can fill in
    selected_detector, detector_configured and required_input_type.
    Never raises; never exposes credentials.
    """
    try:
        load_configured_providers(config)
        name = select_provider({}, config, override=provider)
        adapter = get_adapter(name)
    except Exception:  # noqa: BLE001
        return {"selected_detector": provider, "detector_configured": False,
                "required_input_type": None}
    return {
        "selected_detector": adapter.name,
        "detector_configured": bool(adapter.is_configured()),
        "required_input_type": adapter.required_input_type,
    }


def list_detectors(config: WrapperConfig = DEFAULT_CONFIG) -> list[str]:
    """Names of every detector registered from config or custom modules."""
    try:
        load_configured_providers(config)
    except Exception:  # noqa: BLE001
        return []
    return list_providers()
