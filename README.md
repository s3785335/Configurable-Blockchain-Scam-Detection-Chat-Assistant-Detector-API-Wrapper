# Detector API Wrapper

Lets a client plug the scam-detector API of their choice into the
Blockchain Scam Detection Chat Assistant. Whatever the detector returns is
translated into the main application's `DetectionResult`, so the bot
treats every detector the same way. Includes input/output sanitization,
caching, rate limiting and fail-closed error handling.

## Zero-configure usage

```python
from detector_api_wrapper import call_api

outcome = call_api("0x1234...", chain="ethereum")
if outcome.status == "error":
    ...                      # detector unavailable: outcome.error says why
else:
    detection = outcome.result   # main app's DetectionResult
```

`outcome.status` is `"ok"`, `"not_found"` (returned as a
`DetectionResult` with `label="insufficient_evidence"`) or `"error"`
(`result` is `None`; the wrapper never invents a verdict).

For detectors whose `required_input_type` is `"address_with_context"`,
pass the fetched `AddressContext` too: `call_api(address, context=ctx)`.

`detector_status()` returns `selected_detector`, `detector_configured`
and `required_input_type`, matching the `BusinessAnalyserOutput` fields.

Requirements: describe your detector API in a provider config file and
set its key in the environment (see `.env.example`). No client
instantiation or manual setup needed.

## Plugging in your detector API

The wrapper is provider-agnostic: the client connects the detector API of
their choice. There are two routes.

**No code (most REST APIs).** Describe the API in a JSON file and point
`DETECTOR_CONFIG_PATH` at it (or put the JSON in `DETECTOR_CONFIG_JSON`).
See `examples/providers.example.json`. The `mapping` section translates
the detector's response into `DetectionResult` using dot paths, including
translating verdict values onto the three labels, scaling scores to
0-1, and mapping evidence lists. A label can also be derived from a risk
score and threshold. Unrecognised verdicts, missing required fields and
out-of-range numbers return `status="error"` rather than a guess. Missing
`explanation` / `reasoning_trace` get plain-language defaults.

**Custom code.** Subclass `ProviderAdapter`, call `register_provider()`,
and list the module in `DETECTOR_ADAPTER_MODULES`. See
`examples/custom_adapter_example.py`. Adapters can also add
provider-specific identifier checks via `validate_resource_id()`.

Provider selection order: `provider=` argument, then `DETECTOR_PROVIDER`,
then the only registered provider. Anything ambiguous returns
`status="error"`.

## Running in containers

All configuration comes from environment variables, the provider config
can be a mounted file, and the API key can be read from a mounted secret
via `API_WRAPPER_KEY_FILE` (Docker secrets). Audit records go through the
standard `logging` module, so route them to stdout in the host container.
The cache and rate limit are per process, so each replica keeps its own.

### Docker image setup

The wrapper can be hosted on its own as a standalone container, exposing
itself over a small HTTP API (`src/detector_api_wrapper/api.py`) so other
services can reach it over the network rather than importing it as a
Python library. **This container is not yet wired up to the main
application** — this step only sets up the environment in isolation.

**Prerequisites**

- Docker and Docker Compose.
- A `.env` file in the repo root (copy `.env.example`), with a real
  `API_WRAPPER_KEY` or `API_WRAPPER_KEY_FILE` — never commit `.env`.
- A provider config — `docker-compose.yml` mounts
  `examples/providers.example.json` by default; swap in your own via the
  `DETECTOR_CONFIG_PATH` volume mount or `DETECTOR_CONFIG_JSON`.

**Build and run**

```bash
cp .env.example .env
# edit .env: set API_WRAPPER_KEY (or API_WRAPPER_KEY_FILE)

docker compose up --build
```

Exposes the service on `http://localhost:8000`.

**Image details**

- **Base image:** `python:3.12-slim`
- **Installed as:** the package plus its `api` extra (`fastapi`,
  `uvicorn`), via `pip install ".[api]"`
- **Runs as:** a non-root user (`appuser`)
- **Entry point:** `uvicorn detector_api_wrapper.api:app --host 0.0.0.0 --port 8000`
- **Exposed port:** `8000`
- **Healthcheck:** `GET /health`, polled every 30s

**Endpoints**

| Method | Path         | Description |
|--------|--------------|--------------|
| GET    | `/health`    | Liveness check, returns `{"status": "ok"}` |
| GET    | `/status`    | Which detector is selected/configured (`?provider=` optional); mirrors `detector_status()` |
| GET    | `/detectors` | Names of all registered detectors |
| POST   | `/call`      | Body: `{"resource_id": "...", "options": {}, "provider": null, "chain": null, "context": null}`. Returns the `ApiResult` envelope as JSON. |
| GET    | `/docs`      | Interactive Swagger UI (FastAPI auto-generated) |

**Verifying it locally**

```bash
curl http://localhost:8000/health
curl http://localhost:8000/detectors
curl -X POST http://localhost:8000/call \
  -H "Content-Type: application/json" \
  -d '{"resource_id": "0x1234567890abcdef1234567890abcdef12345678", "provider": "acme", "chain": "ethereum"}'
```

**Stopping / rebuilding**

```bash
docker compose down          # stop and remove the container
docker compose up --build    # rebuild after code changes
```

## Project layout

```
src/detector_api_wrapper/
├── core.py              # single public entry point: call_api / call_api_async
├── sanitize.py           # input & output sanitization (see Security below)
├── providers/
│   ├── base.py           # shared adapter interface
│   ├── http_adapter.py   # generic, config-driven HTTP adapter
│   ├── registry.py       # registered adapters
│   └── selector.py       # provider selection
├── schema.py             # mirror of the main app's DetectionResult / AddressContext
├── normalize.py          # ApiResult envelope, mapping validation
├── errors.py              # typed errors
├── cache.py               # lightweight in-session cache
├── config.py              # single config object with defaults
├── ratelimit.py           # per-provider rate limiting
└── logging_audit.py       # raw request/response audit trail
examples/                  # provider config + custom adapter examples
tests/
docs/
```

## Security

Input sanitization is treated as a first-class requirement (stakeholder
priority), not an afterthought:

- Identifiers are validated against a strict allow-list pattern and length
  cap before anything else happens.
- Options are checked against an explicit allow-list of valid values.
- Provider output is sanitized before being passed downstream.
- Credentials are read from environment variables only, never hardcoded
  or logged.
- Every external call has an explicit timeout.
- Client-configured endpoints must be HTTPS (plain HTTP only when
  explicitly allowed for a private container network), redirects are not
  followed, and identifiers are sent as parameters, never pasted into URLs.
- Failures return an explicit `status="error"` result (fail closed) rather
  than a fake success.

## Status

Provider adapters, provider selection, response-to-schema mapping onto
the main application's `DetectionResult`, rate limiting and the async
path are implemented and tested. `schema.py` mirrors the main repo's
schema and must be kept in sync with it
(`tests/test_schema_contract.py` guards the shape).

## Branching

This repo follows Gitflow: `main` → `develop` → `feature/*` → release
branch → `main`.
See: https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow
