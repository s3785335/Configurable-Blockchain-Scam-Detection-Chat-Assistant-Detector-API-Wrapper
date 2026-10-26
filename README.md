# Detector API Wrapper

A standalone service that lets the **Configurable Blockchain Scam Detection Chat Assistant** use any external scam-detection API.

Every detector API returns results in its own format. The wrapper calls the detector you configure and converts its reply into the chat assistant's standard result (label, confidence, evidence), so the chat app never needs provider-specific code. Adding a new detector means editing a JSON file, not writing code.

```
Chat assistant  --POST /call-->  Detector API Wrapper  --HTTPS-->  External detector API
                <--standard result--                   <--raw JSON--
```

## Features

- **Config-driven providers.** Each detector is one JSON entry: its URL, how to authenticate, and how to map its reply.
- **Strict input checks.** Addresses and options are validated against allow-lists. Bad input is rejected, never "cleaned".
- **Fails closed.** Bad input, a timeout, a missing key or a provider error returns `status: "error"` with a reason. The wrapper never returns a made-up verdict.
- **Keys stay out of the code.** API keys are read from environment variables (or a mounted secret file) and are never logged or returned.
- **Label overrides.** A mapping can force `insufficient_evidence` based on another field, for example when a detector has never seen an address.
- **Timeouts, rate limiting and a short-lived cache** for every provider call.
- **Runs in Docker** as its own HTTP service, or can be imported as a Python library.

## Quick start (Docker)

Requirements: Docker Desktop (or Docker Engine with Compose).

```bash
git clone https://github.com/s3785335/Configurable-Blockchain-Scam-Detection-Chat-Assistant-Detector-API-Wrapper.git
cd Configurable-Blockchain-Scam-Detection-Chat-Assistant-Detector-API-Wrapper

cp .env.example .env        # Windows PowerShell: Copy-Item .env.example .env
# edit .env and set your provider API key(s)

docker compose up --build -d
```

The service runs on **http://localhost:8002**. (It listens on 8000 inside the container; it is published on host port 8002 so it doesn't clash with the chat app, which uses 8000.)

Check it's running:

```bash
curl http://localhost:8002/health        # {"status":"ok"}
curl http://localhost:8002/detectors     # names of the loaded providers
```

Interactive API docs are at **http://localhost:8002/docs**.

To stop it: `docker compose down`. To rebuild after code changes: `docker compose up --build -d`.

> Out of the box, the wrapper loads `examples/providers.example.json`, which contains two **placeholder** providers (`acme` and `scorer`). Their URLs don't exist, so a `/call` to them returns `status: "error"`. Add your own provider to get real results (see [Configuring a provider](#configuring-a-provider)).

## Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/health` | Liveness check. Returns `{"status": "ok"}`. Does not read provider config, so it stays healthy even if a provider is misconfigured. |
| GET | `/status` | Which detector would be used and whether it's configured. Optional `?provider=` query. Returns `selected_detector`, `detector_configured` and `required_input_type` (the same fields the chat assistant uses). |
| GET | `/detectors` | Names of every loaded provider. |
| POST | `/call` | Runs a check. See below. |
| GET | `/docs` | Swagger UI (auto-generated). |

### `POST /call`

Request body:

```json
{
  "resource_id": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "provider": "onchainrisk",
  "chain": "ethereum",
  "options": {},
  "context": null
}
```

| Field | Required | Description |
|---|---|---|
| `resource_id` | Yes | The address to check. |
| `provider` | No | Which provider to use. If omitted, the wrapper selects one. |
| `chain` | No | Chain name, passed to the provider if its config defines `chain_param`. |
| `options` | No | Extra options. Only allow-listed keys and values are accepted. |
| `context` | No | Address context, for providers with `required_input_type: "address_with_context"`. |

Response:

```json
{
  "resource_id": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
  "provider": "onchainrisk",
  "status": "ok",
  "result": {
    "label": "not_scam",
    "confidence": 0.6,
    "risk_type": null,
    "evidence": [
      { "description": "No risky contract functions found", "weight": 0.3 }
    ],
    "explanation": "..."
  },
  "checked_at": "2026-10-23T13:58:45.685795+00:00",
  "error": null
}
```

- `status` is `ok`, `not_found` or `error`.
- `result` holds the standard verdict. It is `null` when `status` is `error`.
- `label` is always one of `scam`, `not_scam` or `insufficient_evidence`.
- `confidence` and evidence `weight` are between 0 and 1.

On failure:

```json
{
  "resource_id": "0x1234567890abcdef1234567890abcdef12345678",
  "provider": "acme",
  "status": "error",
  "result": null,
  "checked_at": "2026-10-23T13:58:45.685795+00:00",
  "error": "Provider 'acme' request failed (ConnectError)."
}
```

## Configuring a provider

Providers are defined in a JSON file. `docker-compose.yml` mounts it into the container at `/config/providers.json`:

```yaml
volumes:
  - ./examples/providers.example.json:/config/providers.json:ro
```

To use your own providers, create your own file (e.g. `config/providers.json`, which is not committed) and change **only the left-hand side** of that line:

```yaml
  - ./config/providers.json:/config/providers.json:ro
```

Then restart: `docker compose up -d --force-recreate`.

> Make sure the file exists before starting the container. If it doesn't, Docker silently creates an empty folder with that name and the wrapper loads no providers (`/detectors` returns `{}`).

### Provider fields

```json
{
  "providers": [
    {
      "name": "acme",
      "url": "https://api.acme.example/v1/address-risk",
      "method": "GET",
      "id_param": "address",
      "chain_param": "network",
      "api_key_env": "API_WRAPPER_KEY",
      "auth_header": "Authorization",
      "auth_scheme": "Bearer",
      "option_params": { "mode": "strictness" },
      "mapping": { "...": "see below" }
    }
  ]
}
```

| Field | Description |
|---|---|
| `name` | Name used in `/call` and listed by `/detectors`. |
| `url` | The provider's endpoint. Must be HTTPS, unless plain HTTP has been explicitly allowed for private networks (see `providers/http_adapter.py`). |
| `method` | `GET` or `POST`. |
| `id_param` | Name of the parameter the provider expects for the address. |
| `chain_param` | Optional. Name of the provider's chain/network parameter. |
| `required_input_type` | `address` (default) or `address_with_context`. |
| `context_param` | Name of the parameter that carries the context, when `address_with_context` is used. |
| `api_key_env` | Name of the environment variable that holds this provider's key. The key itself never goes in this file. |
| `auth_header` | Header the key is sent in, e.g. `Authorization` or `X-Api-Key`. |
| `auth_scheme` | Prefix before the key, e.g. `Bearer`. Use `""` to send the key on its own. |
| `option_params` | Maps allowed `options` keys to the provider's parameter names. |
| `mapping` | How to read the provider's reply. See below. |

### Mapping the reply

Paths use dot notation into the provider's JSON reply, e.g. `result.verdict`.

**Label from a field value:**

```json
"label": {
  "path": "result.verdict",
  "values": {
    "malicious": "scam",
    "suspicious": "scam",
    "clean": "not_scam",
    "unknown": "insufficient_evidence"
  }
}
```

**Label from a risk score** (score at or above the threshold means `scam`):

```json
"risk_score": { "path": "risk", "scale": 100 },
"label": { "from_score": true, "scam_threshold": 0.7 }
```

**Label overrides.** Checked last; the first match wins. Forcing `insufficient_evidence` also sets confidence to 0. Matching is loose, so `0` matches `"0"` and `"unknown"` matches `"Unknown"`.

```json
"label": {
  "from_score": true,
  "scam_threshold": 0.7,
  "overrides": [
    { "path": "addressInfo.txCount", "equals": 0, "label": "insufficient_evidence" },
    { "path": "riskLevel", "equals": "unknown", "label": "insufficient_evidence" }
  ]
}
```

Use overrides when a detector returns a low risk score for addresses it has never seen, so "no data" isn't reported as "not scam".

**Other fields:**

```json
"confidence":  { "path": "result.confidence", "scale": 100 },
"risk_type":   { "path": "result.category" },
"evidence":    { "path": "result.findings", "description": "message", "weight": "severity", "weight_scale": 10 },
"explanation": { "path": "result.summary" }
```

- `scale` divides the raw value to get 0–1 (e.g. `100` for a percentage).
- For evidence, `path` points at a list; `description` and `weight` name the fields inside each item. If items are plain strings, use `default_weight` instead.

The mapping is validated when the service starts. An unknown field, a label value that isn't one of the three allowed labels, or a malformed override stops the service with a clear error.

### Custom adapters

If a provider can't be described with the JSON config (e.g. it needs several requests), write a Python adapter. See `examples/custom_adapter_example.py`, and load it with the `DETECTOR_ADAPTER_MODULES` environment variable.

## Environment variables

Set these in `.env` (copy `.env.example`). **Never commit `.env`.**

| Variable | Description |
|---|---|
| `API_WRAPPER_KEY` | Default provider API key (used by providers whose `api_key_env` is `API_WRAPPER_KEY`). |
| `API_WRAPPER_KEY_FILE` | Alternative to `API_WRAPPER_KEY`: path to a mounted secret file containing the key (e.g. Docker secrets). |
| *Provider-specific keys* | Any variable named in a provider's `api_key_env`, e.g. `SCORER_API_KEY`. |
| `DETECTOR_CONFIG_PATH` | Path to the providers JSON file. Set to `/config/providers.json` in `docker-compose.yml`. |
| `DETECTOR_CONFIG_JSON` | Alternative to `DETECTOR_CONFIG_PATH`: the providers config as a JSON string. |
| `DETECTOR_ADAPTER_MODULES` | Comma-separated Python modules that register custom adapters. |
| `DETECTOR_TIMEOUT_SECONDS` | Timeout for each provider call. Default `20`. |

## Connecting the chat assistant

The chat assistant treats the wrapper like any other external detector. Add a detector entry to the chat app's `config/app_config.json` (or use **+ add source** on its Admin page), then select it on the Admin page or with `ACTIVE_DETECTOR`.

```json
{
  "id": "api_wrapper",
  "name": "Detector API Wrapper",
  "status": "live",
  "mode": "generic",
  "endpoint": "http://localhost:8002/call",
  "method": "POST",
  "required_input_type": "address",
  "is_llm_based": false,
  "timeout_seconds": 30,
  "request": {
    "body_template": {
      "resource_id": "{{ address }}",
      "provider": "acme",
      "chain": "ethereum"
    }
  },
  "response_mapping": {
    "label": { "path": "$.result.label", "fallback": "insufficient_evidence" },
    "confidence": { "path": "$.result.confidence", "scale": 1, "default": 0, "measures": "label" },
    "evidence": {
      "mode": "list",
      "list_path": "$.result.evidence",
      "item": { "description": "$.description", "weight": "$.weight" },
      "default_weight": 0.3
    }
  }
}
```

Notes:

- Set `provider` to a name listed by `/detectors`.
- If the chat app runs **in Docker**, use `http://host.docker.internal:8002/call`, because `localhost` inside its container is the container itself.
- Keep `timeout_seconds` above the wrapper's own timeout (20 s), so the wrapper's timeout error reaches the bot first.
- `is_llm_based: false` means the chat app's Forensic Investigator explains the result in plain language.
- If the wrapper returns `status: "error"`, there is no label, and the chat app replies that it couldn't get a verdict rather than guessing.

Test it:

```powershell
$env:ACTIVE_DETECTOR = "api_wrapper"
python cli.py
```

Ask `Is 0x1234567890abcdef1234567890abcdef12345678 a scam?` and answer the profile question. The detection details should show **Source: Configured detector (Detector API Wrapper)**.

## Running without Docker

Requires Python 3.10 or later.

```bash
python -m venv .venv
# Windows: .\.venv\Scripts\Activate.ps1   macOS/Linux: source .venv/bin/activate
pip install -e ".[api,dev]"

export DETECTOR_CONFIG_PATH=examples/providers.example.json
# Windows: $env:DETECTOR_CONFIG_PATH = "examples\providers.example.json"

uvicorn detector_api_wrapper.api:app --app-dir src --port 8002
```

### As a Python library

```python
from detector_api_wrapper import call_api

result = call_api(
    "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
    provider="acme",
    chain="ethereum",
)
print(result.status, result.to_dict())
```

`call_api` never raises on a failed lookup. It returns a result with `status="error"` and a reason.

## Tests

```bash
pip install -e ".[api,dev]"
python -m pytest -q
```

All 58 tests should pass. They cover input sanitising, provider config validation, response mapping, label overrides and fail-closed behaviour.

## Project structure

```
src/detector_api_wrapper/
  api.py              HTTP layer (FastAPI): /health, /status, /detectors, /call
  core.py             Single entry point: call_api, detector_status, list_detectors
  sanitize.py         Input validation (addresses, option allow-lists, length caps)
  config.py           WrapperConfig: timeouts, rate limit, cache TTL, allow-lists
  schema.py           Result and evidence data structures
  normalize.py        Converts provider replies into the standard result
  errors.py           Typed errors
  cache.py            Short-lived in-memory cache
  ratelimit.py        Per-provider rate limiting
  logging_audit.py    Audit log of raw requests and responses (never returned to callers)
  providers/
    base.py           Adapter interface
    http_adapter.py   Generic config-driven HTTP adapter and mapping
    registry.py       Loads providers from config and custom modules
    selector.py       Chooses a provider when none is given
examples/
  providers.example.json       Placeholder providers showing the config format
  custom_adapter_example.py    How to write a custom adapter
tests/                         Unit tests
Dockerfile                     python:3.12-slim, runs as a non-root user, healthcheck on /health
docker-compose.yml             Runs the service on host port 8002
.env.example                   Documents the environment variables (no real values)
```

## Troubleshooting

| Problem | Cause and fix |
|---|---|
| `failed to connect to the docker API` | Docker Desktop isn't running. Start it and wait for **Engine running**. |
| `Unable to connect` on port 8002 | The container isn't running (`docker compose ps`), or you're on an old version that publishes port 8000. Pull the latest `develop`. |
| `/detectors` returns `{}` | The providers file in the volume mount doesn't exist (Docker created a folder instead), or it failed validation. Check `docker compose logs`. |
| `/detectors` shows only `acme` and `scorer` | The volume still points at `examples/providers.example.json`. Point it at your own file. |
| `status: error`, `ConnectError` | The provider URL can't be reached. Expected for the placeholder providers. |
| `status: error` mentioning a key | The variable named in the provider's `api_key_env` isn't set in `.env`. Restart after editing `.env`. |
| Checks time out | Raise `DETECTOR_TIMEOUT_SECONDS` in `.env`. Some providers take 5–8 seconds. |

## Security notes

- Never commit `.env` or a providers file containing real endpoints you want kept private. `.env` is in `.gitignore` and `.dockerignore`.
- Keys are only ever read from environment variables or a mounted secret file, and are never written to logs or responses.
- Provider endpoints must use HTTPS unless HTTP has been explicitly allowed for private networks.
- The container runs as a non-root user.

## Branching

This repo follows Gitflow: `feature/*` and `fix/*` branches go into `develop`, then a release branch, then `main`.
