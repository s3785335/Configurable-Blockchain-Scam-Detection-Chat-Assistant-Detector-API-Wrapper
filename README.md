# Detector API Wrapper

Internal library that wraps one or more external detector API providers
behind a single function call, with input/output sanitization, caching,
error handling, and a normalized result schema.

## Zero-configure usage

```python
from detector_api_wrapper import call_api

result = call_api("some-resource-id")
print(result.status, result.data)
```

Only requirement: the `API_WRAPPER_KEY` environment variable must be set
(see `.env.example`). No client instantiation or manual setup needed.

## Project layout

```
src/detector_api_wrapper/
├── core.py              # single public entry point: call_api / call_api_async
├── sanitize.py           # input & output sanitization (see Security below)
├── providers/
│   ├── base.py           # shared adapter interface
│   └── selector.py       # provider selection
├── normalize.py          # ApiResult / Evidence schema, response normalization
├── errors.py              # typed errors
├── cache.py               # lightweight in-session cache
├── config.py              # single config object with defaults
└── logging_audit.py       # raw request/response audit trail
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
- Failures return an explicit `status="error"` result (fail closed) rather
  than a fake success.

## Status

This is an early scaffold. Provider adapters, provider selection logic,
and response-to-schema mapping are intentional stubs pending confirmation
of the real provider's response schema. Validation, error handling, and
the output schema are complete and ready for review.

## Branching

This repo follows Gitflow: `main` → `develop` → `feature/*` → release
branch → `main`.
See: https://www.atlassian.com/git/tutorials/comparing-workflows/gitflow-workflow
