"""
Core entry point.

The wrapper exposes one primary entry point (call_api / call_api_async).
Everything else -- provider selection, sanitization, response parsing --
is a private helper called from inside it, so the rest of the system only
ever talks to this one function. See draft Section 1.
"""

from .cache import SimpleCache
from .config import DEFAULT_CONFIG, WrapperConfig, get_api_key
from .errors import InvalidInputError, ProviderError
from .logging_audit import log_call
from .normalize import ApiResult, normalize_response
from .providers.selector import select_provider
from .sanitize import sanitize_options, sanitize_resource_id

_cache = SimpleCache(ttl_seconds=DEFAULT_CONFIG.cache_ttl_seconds)


def call_api(
    resource_id: str,
    options: dict | None = None,
    provider: str | None = None,
    config: WrapperConfig = DEFAULT_CONFIG,
) -> ApiResult:
    """
    Call the detector API for a given resource_id.

    Zero-configure: works with just API_WRAPPER_KEY set in the
    environment. Fails closed -- any sanitization or provider failure
    returns a typed ApiResult with status="error" rather than raising or
    returning a fake success.
    """
    # 1. Sanitize input first. Reject early rather than trying to "clean"
    #    a malformed value.
    try:
        clean_id = sanitize_resource_id(resource_id, config)
        clean_options = sanitize_options(options or {}, config)
    except InvalidInputError as e:
        return ApiResult(
            resource_id=str(resource_id),
            provider="none",
            status="error",
            error=str(e),
        )

    # 2. Select provider (manual override takes precedence).
    selected_provider = provider or select_provider(clean_options, config)

    # 3. Check cache.
    cache_key = SimpleCache.make_key(clean_id, clean_options, selected_provider)
    cached = _cache.get(cache_key)
    if cached is not None:
        return cached

    # 4. Call provider, with timeout/credential handling, failing closed.
    try:
        raw_response = _call_provider(selected_provider, clean_id, clean_options, config)
    except Exception as e:  # noqa: BLE001 - deliberately broad: fail closed
        log_call(clean_id, selected_provider, clean_options, None, error=str(e))
        return ApiResult(
            resource_id=clean_id,
            provider=selected_provider,
            status="error",
            error=str(e),
        )

    log_call(clean_id, selected_provider, clean_options, raw_response)

    # 5. Normalize into the standard schema.
    result = normalize_response(raw_response, selected_provider, clean_id)
    _cache.set(cache_key, result)
    return result


async def call_api_async(
    resource_id: str,
    options: dict | None = None,
    provider: str | None = None,
    config: WrapperConfig = DEFAULT_CONFIG,
) -> ApiResult:
    """Async mirror of call_api, for concurrent lookups."""
    # Intentional stub: swap the synchronous _call_provider below for an
    # async-native provider call once a real provider adapter exists
    # (e.g. httpx.AsyncClient), rather than wrapping the sync call in a
    # thread executor.
    return call_api(resource_id, options, provider, config)


def _call_provider(
    provider: str,
    resource_id: str,
    options: dict,
    config: WrapperConfig,
) -> dict:
    """
    Dispatch to the named provider's adapter.

    Intentional stub: the actual provider HTTP call and response mapping
    depend on confirming the real provider's response schema first (per
    the draft's closing note). Credentials are validated here so a
    missing key fails fast and explicitly.
    """
    get_api_key()  # raises RuntimeError with a clear message if missing

    # TODO: look up the registered adapter for `provider` and call:
    #     adapter.call(resource_id, options)
    # with config.timeout_seconds applied, and rate limiting/backoff per
    # config.rate_limit_per_second.
    raise ProviderError(
        f"No adapter implementation wired for provider '{provider}' yet."
    )
