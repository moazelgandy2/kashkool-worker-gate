# Kashkool Wrangler Gate

Edge worker for protected video playback.

## Routes

- `GET /health`
- `GET /v/:assetId/master.m3u8?token=...`
- `GET /v/:assetId/:rendition/index.m3u8?token=...`
- `GET /v/:assetId/:rendition/:segment?token=...`
- `GET /k/:assetId?kid=...&token=...`

## Security checks

- HMAC token signature verification (`VIDEO_PLAYBACK_TOKEN_SECRET`)
- expiry check (`exp`)
- scope checks (`sid`, `assetId`)
- optional soft-bind check (`ua`, `/24 ip prefix`)
- optional session introspection against Convex (derived from `CONTROL_PLANE_BASE_URL` or explicit `VIDEO_GATE_VALIDATION_URL`)
- key material fetch from Convex (derived from `CONTROL_PLANE_BASE_URL` or explicit `VIDEO_GATE_KEY_URL`) and worker-side key unwrap (`VIDEO_KEY_ENCRYPTION_SECRET`)
- endpoint-level rate limiting by session ID (`manifest`, `playlist`, `segment`, `key`)
- optional telemetry push to control plane (derived from `CONTROL_PLANE_BASE_URL` or explicit `VIDEO_GATE_EVENT_URL`)
- optional strict request-context validation (`VIDEO_GATE_STRICT_REQUEST_CONTEXT`, `VIDEO_GATE_ALLOWED_ORIGINS`)

## Optional bindings

- `VIDEO_GATE_KV` (KV namespace) for cross-instance rate-limit counters.
- If omitted, in-memory counters are used (best-effort only).

## Local env

Copy `.dev.vars.example` to `.dev.vars` and fill secrets.

Canonical env contract lives in root `ENV_CATALOG.md`.

## Commands

```bash
npm run lint
npm run type-check
```
