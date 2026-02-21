const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const inMemoryRateWindow = new Map();
const inMemoryJtiWindow = new Map();
const inMemorySessionValidationWindow = new Map();
const inMemoryAbuseBlockWindow = new Map();
const inMemoryAbuseIpBlockWindow = new Map();
const SWEEP_INTERVAL = 250;
let inMemorySweepCounter = 0;
let hasLoggedPlaybackEventMissingConfig = false;
const CONTROL_PLANE_TIMEOUT_MS = 5_000;
const CONTROL_PLANE_RETRY_DELAY_MS = 250;
const CONTROL_PLANE_MAX_ATTEMPTS = 2;
const DEFAULT_SESSION_VALIDATION_CACHE_TTL_SECONDS = 10;
const DEFAULT_ABUSE_BLOCK_TTL_SECONDS = 10 * 60;

const DEFAULT_RATE_CONFIG = {
  manifestPerMinute: 60,
  playlistPerMinute: 120,
  segmentPerMinute: 1600,
  keyPerMinute: 30,
  keyReplayTtlSeconds: 15 * 60,
  keyJtiMaxReuse: 20,
};

function parsePositiveInt(raw, fallback) {
  const parsed = Number(raw);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return Math.floor(parsed);
}

function getAllowedOrigins(env) {
  const raw = String(env.VIDEO_GATE_ALLOWED_ORIGINS || "").trim();
  if (!raw) return [];
  return raw
    .split(",")
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function parseBoolean(raw, fallback) {
  if (raw === undefined || raw === null || raw === "") {
    return fallback;
  }

  const normalized = String(raw).trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  return fallback;
}

function parseAllowedOriginRule(originValue) {
  let parsed;
  try {
    parsed = new URL(originValue);
  } catch {
    return null;
  }

  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== "https:" && protocol !== "http:") {
    return null;
  }

  const hostname = parsed.hostname.toLowerCase();
  const port = parsed.port || "";
  const isWildcard = hostname.startsWith("*.");

  if (!isWildcard) {
    return {
      type: "exact",
      protocol,
      hostname,
      port,
    };
  }

  const baseHostname = hostname.slice(2);
  if (!baseHostname || baseHostname.includes("*")) {
    return null;
  }

  const baseLabels = baseHostname.split(".").filter(Boolean);
  if (baseLabels.length < 2) {
    return null;
  }

  return {
    type: "wildcard_single",
    protocol,
    baseHostname,
    port,
  };
}

function getAllowedOriginRules(env) {
  return getAllowedOrigins(env)
    .map(parseAllowedOriginRule)
    .filter(Boolean);
}

function parseOriginCandidate(originValue) {
  try {
    const parsed = new URL(originValue);
    return {
      protocol: parsed.protocol.toLowerCase(),
      hostname: parsed.hostname.toLowerCase(),
      port: parsed.port || "",
    };
  } catch {
    return null;
  }
}

function matchesAllowedOrigin(originValue, rules) {
  const candidate = parseOriginCandidate(originValue);
  if (!candidate) return false;

  for (const rule of rules) {
    if (rule.protocol !== candidate.protocol || rule.port !== candidate.port) {
      continue;
    }

    if (rule.type === "exact") {
      if (rule.hostname === candidate.hostname) {
        return true;
      }
      continue;
    }

    const suffix = `.${rule.baseHostname}`;
    if (!candidate.hostname.endsWith(suffix)) {
      continue;
    }

    const prefix = candidate.hostname.slice(0, -suffix.length);
    if (!prefix || prefix.includes(".")) {
      continue;
    }

    return true;
  }

  return false;
}

function getCorsAllowOrigin(request, env) {
  const allowedOriginRules = getAllowedOriginRules(env);
  const origin = request.headers.get("Origin");
  if (!origin) return null;
  if (!matchesAllowedOrigin(origin, allowedOriginRules)) return null;
  return origin;
}

function applyResponseHeaders(response, request, env, requestId) {
  const allowOrigin = getCorsAllowOrigin(request, env);
  const headers = new Headers(response.headers);
  headers.set("x-kashkool-request-id", requestId);

  if (!allowOrigin) {
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  }

  headers.set("Access-Control-Allow-Origin", allowOrigin);
  headers.set("Vary", "Origin");
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

function buildCorsPreflightResponse(request, env, requestId) {
  const allowOrigin = getCorsAllowOrigin(request, env);
  if (!allowOrigin) {
    return applyResponseHeaders(
      json({ error: "Origin not allowed" }, 403, {
        "Cache-Control": "no-store",
      }),
      request,
      env,
      requestId,
    );
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": allowOrigin,
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "600",
      "x-kashkool-request-id": requestId,
      Vary: "Origin",
    },
  });
}

function isPlaybackRoute(path) {
  return (
    /^\/v\/[^/]+\/master\.m3u8$/.test(path) ||
    /^\/v\/[^/]+\/[^/]+\/index\.m3u8$/.test(path) ||
    /^\/v\/[^/]+\/[^/]+\/[^/]+$/.test(path) ||
    /^\/k\/[^/]+$/.test(path)
  );
}

function sanitizeEnvString(value) {
  return String(value || "")
    .replace(/^\uFEFF/, "")
    .trim();
}

function normalizeBaseUrl(baseUrl) {
  return sanitizeEnvString(baseUrl).replace(/\/$/, "");
}

function resolveControlPlaneEndpoint(env, specificKey, pathSuffix) {
  if (env[specificKey]) {
    return sanitizeEnvString(env[specificKey]);
  }

  if (!env.CONTROL_PLANE_BASE_URL) {
    return "";
  }

  return `${normalizeBaseUrl(env.CONTROL_PLANE_BASE_URL)}${pathSuffix}`;
}

function validateRequestContext(request, env) {
  const strict = env.VIDEO_GATE_STRICT_REQUEST_CONTEXT === "true";
  if (!strict) {
    return { ok: true };
  }

  const allowedOriginRules = getAllowedOriginRules(env);
  if (allowedOriginRules.length === 0) {
    return {
      ok: false,
      reason: "strict_context_no_allowed_origins",
    };
  }

  const origin = request.headers.get("Origin");
  const referer = request.headers.get("Referer");
  const secFetchSite = request.headers.get("Sec-Fetch-Site");

  if (!origin && !referer && !secFetchSite) {
    return { ok: false, reason: "missing_browser_context_headers" };
  }

  if (origin && !matchesAllowedOrigin(origin, allowedOriginRules)) {
    return { ok: false, reason: "origin_not_allowed" };
  }

  if (referer) {
    const refererCandidate = parseOriginCandidate(referer);
    if (
      !refererCandidate ||
      !matchesAllowedOrigin(referer, allowedOriginRules)
    ) {
      return { ok: false, reason: "referer_not_allowed" };
    }
  }

  if (secFetchSite && !["same-origin", "same-site", "cross-site", "none"].includes(secFetchSite)) {
    return { ok: false, reason: "invalid_sec_fetch_site" };
  }

  return { ok: true };
}

function getRateConfig(env) {
  return {
    manifestPerMinute: parsePositiveInt(
      env.VIDEO_GATE_MANIFEST_PER_MINUTE,
      DEFAULT_RATE_CONFIG.manifestPerMinute,
    ),
    playlistPerMinute: parsePositiveInt(
      env.VIDEO_GATE_PLAYLIST_PER_MINUTE,
      DEFAULT_RATE_CONFIG.playlistPerMinute,
    ),
    segmentPerMinute: parsePositiveInt(
      env.VIDEO_GATE_SEGMENT_PER_MINUTE,
      DEFAULT_RATE_CONFIG.segmentPerMinute,
    ),
    keyPerMinute: parsePositiveInt(
      env.VIDEO_GATE_KEY_PER_MINUTE,
      DEFAULT_RATE_CONFIG.keyPerMinute,
    ),
    keyReplayTtlSeconds: parsePositiveInt(
      env.VIDEO_GATE_KEY_REPLAY_TTL_SECONDS,
      DEFAULT_RATE_CONFIG.keyReplayTtlSeconds,
    ),
    keyJtiMaxReuse: parsePositiveInt(
      env.VIDEO_GATE_KEY_JTI_MAX_REUSE,
      DEFAULT_RATE_CONFIG.keyJtiMaxReuse,
    ),
  };
}

function getAbuseAutoBlockEnabled(env) {
  return parseBoolean(env.VIDEO_GATE_ABUSE_AUTOBLOCK_ENABLED, true);
}

function getAbuseIpBlockEnabled(env) {
  return parseBoolean(env.VIDEO_GATE_ABUSE_IP_BLOCK_ENABLED, true);
}

function getAbuseBlockTtlSeconds(env) {
  return parsePositiveInt(
    env.VIDEO_GATE_ABUSE_BLOCK_TTL_SECONDS,
    DEFAULT_ABUSE_BLOCK_TTL_SECONDS,
  );
}

function getSessionValidationCacheTtlSeconds(env) {
  const parsed = parsePositiveInt(
    env.VIDEO_GATE_SESSION_VALIDATION_CACHE_TTL_SECONDS,
    DEFAULT_SESSION_VALIDATION_CACHE_TTL_SECONDS,
  );

  if (env.VIDEO_GATE_KV) {
    return Math.max(60, parsed);
  }

  return parsed;
}

function sessionValidationCacheKey(tokenPayload) {
  return `sv:${tokenPayload.sid}:${tokenPayload.v ?? 0}`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function getRequestId(request) {
  const fromHeader = request.headers.get("x-kashkool-request-id")?.trim();
  if (fromHeader) {
    return fromHeader;
  }
  return crypto.randomUUID();
}

function logMissingEnvConfig(code, requestId, fields) {
  console.error(
    code,
    JSON.stringify({
      requestId,
      ...fields,
    }),
  );
}

function json(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

function toBase64(value) {
  const bytes = TEXT_ENCODER.encode(value);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function parseToken(token) {
  const [payloadPart, signaturePart] = (token || "").split(".");
  if (!payloadPart || !signaturePart) {
    return null;
  }

  try {
    const padded = payloadPart.replace(/-/g, "+").replace(/_/g, "/");
    const raw = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    const payloadText = new TextDecoder().decode(
      Uint8Array.from(raw, (char) => char.charCodeAt(0)),
    );
    const payload = JSON.parse(payloadText);
    return {
      payloadPart,
      signaturePart: signaturePart.trim().toLowerCase(),
      payload,
    };
  } catch {
    return null;
  }
}

async function signPayload(payloadPart, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    TEXT_ENCODER.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    TEXT_ENCODER.encode(payloadPart),
  );

  return Array.from(new Uint8Array(signature))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

function fromBase64(base64) {
  const raw = atob(base64);
  return Uint8Array.from(raw, (char) => char.charCodeAt(0));
}

function toBase64UrlBytes(value) {
  return TEXT_ENCODER.encode(value);
}

async function getAesKeyFromSecret(secret) {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    toBase64UrlBytes(secret),
  );
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
}

async function unwrapContentKey(wrappedContentKey, secret) {
  const [version, ivBase64, payloadBase64] = (wrappedContentKey || "").split(
    ":",
  );
  if (version !== "v1" || !ivBase64 || !payloadBase64) {
    throw new Error("Unsupported wrapped content key format");
  }

  const iv = fromBase64(ivBase64);
  const encryptedWithTag = fromBase64(payloadBase64);

  const aesKey = await getAesKeyFromSecret(secret);
  const rawKeyBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    encryptedWithTag,
  );

  return new Uint8Array(rawKeyBuffer);
}

async function fetchPlaybackKeyMaterial(env, tokenPayload, requestId) {
  const keyUrl = resolveControlPlaneEndpoint(
    env,
    "VIDEO_GATE_KEY_URL",
    "/video-playback-key",
  );

  if (!keyUrl || !env.VIDEO_GATE_VALIDATION_SECRET) {
    logMissingEnvConfig("gate_key_material_missing_config", requestId, {
      hasKeyUrl: Boolean(keyUrl),
      hasValidationSecret: Boolean(env.VIDEO_GATE_VALIDATION_SECRET),
    });
    return null;
  }

  for (let attempt = 1; attempt <= CONTROL_PLANE_MAX_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetch(keyUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-kashkool-gate-secret": env.VIDEO_GATE_VALIDATION_SECRET,
          "x-kashkool-request-id": requestId,
        },
        body: JSON.stringify({
          sessionId: tokenPayload.sid,
          userId: tokenPayload.uid,
          lessonId: tokenPayload.lessonId,
          assetId: tokenPayload.assetId,
          tokenVersion: tokenPayload.v,
        }),
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      });

      if (!response.ok) {
        const canRetry = response.status >= 500 && attempt < CONTROL_PLANE_MAX_ATTEMPTS;
        if (canRetry) {
          await sleep(CONTROL_PLANE_RETRY_DELAY_MS);
          continue;
        }
        return null;
      }

      return await response.json().catch(() => null);
    } catch (error) {
      if (attempt < CONTROL_PLANE_MAX_ATTEMPTS) {
        await sleep(CONTROL_PLANE_RETRY_DELAY_MS);
        continue;
      }
      console.error(
        "gate_key_material_fetch_failed",
        error instanceof Error ? error.message : String(error),
      );
      return null;
    }
  }

  return null;
}

function timingSafeEqualHex(actual, expected) {
  if (actual.length !== expected.length) return false;
  let diff = 0;
  for (let i = 0; i < actual.length; i += 1) {
    diff |= actual.charCodeAt(i) ^ expected.charCodeAt(i);
  }
  return diff === 0;
}

function extractIpPrefix(ip) {
  const parts = (ip || "").split(".");
  if (parts.length !== 4) return undefined;
  return `${parts[0]}.${parts[1]}.${parts[2]}`;
}

function getClientIp(request) {
  const fromHeader = request.headers.get("cf-connecting-ip");
  return fromHeader || undefined;
}

function getClientIpPrefix(request) {
  return extractIpPrefix(getClientIp(request));
}

async function validateSessionWithControlPlane(env, tokenPayload, requestId) {
  const validationUrl = resolveControlPlaneEndpoint(
    env,
    "VIDEO_GATE_VALIDATION_URL",
    "/video-playback-validate",
  );

  if (!validationUrl || !env.VIDEO_GATE_VALIDATION_SECRET) {
    logMissingEnvConfig("gate_session_validation_missing_config", requestId, {
      hasValidationUrl: Boolean(validationUrl),
      hasValidationSecret: Boolean(env.VIDEO_GATE_VALIDATION_SECRET),
    });
    return false;
  }

  const now = Date.now();
  const cacheTtlSeconds = getSessionValidationCacheTtlSeconds(env);
  const cacheKey = sessionValidationCacheKey(tokenPayload);

  if (env.VIDEO_GATE_KV) {
    const raw = await env.VIDEO_GATE_KV.get(cacheKey);
    if (raw) {
      try {
        const cached = JSON.parse(raw);
        if (
          cached &&
          typeof cached.ok === "boolean" &&
          typeof cached.expiresAt === "number" &&
          cached.expiresAt > now
        ) {
          return cached.ok;
        }
      } catch {
        // Ignore cache parse errors and fall through to control-plane call.
      }
    }
  } else {
    const cached = inMemorySessionValidationWindow.get(cacheKey);
    if (cached && cached.expiresAt > now) {
      return cached.ok;
    }
  }

  let result = false;
  for (let attempt = 1; attempt <= CONTROL_PLANE_MAX_ATTEMPTS; attempt += 1) {
    try {
      const response = await fetch(validationUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "x-kashkool-gate-secret": env.VIDEO_GATE_VALIDATION_SECRET,
          "x-kashkool-request-id": requestId,
        },
        body: JSON.stringify({
          sessionId: tokenPayload.sid,
          userId: tokenPayload.uid,
          lessonId: tokenPayload.lessonId,
          assetId: tokenPayload.assetId,
          tokenVersion: tokenPayload.v,
        }),
        signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
      });

      if (!response.ok) {
        const canRetry = response.status >= 500 && attempt < CONTROL_PLANE_MAX_ATTEMPTS;
        if (canRetry) {
          await sleep(CONTROL_PLANE_RETRY_DELAY_MS);
          continue;
        }
        result = false;
        break;
      }

      const body = await response.json().catch(() => ({ ok: false }));
      result = body.ok === true;
      break;
    } catch {
      if (attempt < CONTROL_PLANE_MAX_ATTEMPTS) {
        await sleep(CONTROL_PLANE_RETRY_DELAY_MS);
        continue;
      }
      result = false;
    }
  }

  const expiresAt = now + cacheTtlSeconds * 1000;
  if (env.VIDEO_GATE_KV) {
    await env.VIDEO_GATE_KV.put(
      cacheKey,
      JSON.stringify({ ok: result, expiresAt }),
      { expirationTtl: cacheTtlSeconds },
    );
  } else {
    inMemorySessionValidationWindow.set(cacheKey, { ok: result, expiresAt });
  }

  return result;
}

async function emitPlaybackEvent(env, payload, requestId) {
  const eventUrl = resolveControlPlaneEndpoint(
    env,
    "VIDEO_GATE_EVENT_URL",
    "/video-playback-event",
  );

  if (!eventUrl || !env.VIDEO_GATE_VALIDATION_SECRET) {
    if (!hasLoggedPlaybackEventMissingConfig) {
      hasLoggedPlaybackEventMissingConfig = true;
      console.warn(
        "gate_playback_event_missing_config",
        JSON.stringify({
          hasEventUrl: Boolean(eventUrl),
          hasValidationSecret: Boolean(env.VIDEO_GATE_VALIDATION_SECRET),
          requestId,
        }),
      );
    }
    return;
  }

  try {
    await fetch(eventUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-kashkool-gate-secret": env.VIDEO_GATE_VALIDATION_SECRET,
        "x-kashkool-request-id": requestId,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(CONTROL_PLANE_TIMEOUT_MS),
    });
  } catch (error) {
    console.error(
      "gate_playback_event_emit_failed",
      error instanceof Error ? error.message : String(error),
    );
    // Do not fail playback if telemetry fails.
  }
}

export function __resetForTests() {
  inMemoryRateWindow.clear();
  inMemoryJtiWindow.clear();
  inMemorySessionValidationWindow.clear();
  inMemoryAbuseBlockWindow.clear();
  inMemoryAbuseIpBlockWindow.clear();
  inMemorySweepCounter = 0;
  hasLoggedPlaybackEventMissingConfig = false;
}

function queuePlaybackEvent(executionCtx, env, payload, requestId) {
  const promise = emitPlaybackEvent(env, payload, requestId);
  if (executionCtx && typeof executionCtx.waitUntil === "function") {
    executionCtx.waitUntil(promise);
  }
}

function memoryRateLimitKey(scope, sessionId) {
  return `${scope}:${sessionId}`;
}

async function incrementRateCounter(env, scope, sessionId, windowSeconds) {
  const key = memoryRateLimitKey(scope, sessionId);
  const now = Date.now();
  const expiresAt = now + windowSeconds * 1000;

  if (env.VIDEO_GATE_KV) {
    // NOTE: KV updates are eventually consistent and this read-modify-write
    // can undercount under high concurrency. This trade-off is accepted for
    // low-cost edge rate limiting.
    const current = await env.VIDEO_GATE_KV.get(key);
    const nextCount = Number(current || "0") + 1;
    await env.VIDEO_GATE_KV.put(key, String(nextCount), {
      expirationTtl: windowSeconds,
    });
    return nextCount;
  }

  const current = inMemoryRateWindow.get(key);
  if (!current || current.expiresAt <= now) {
    inMemoryRateWindow.set(key, { count: 1, expiresAt });
    sweepInMemoryWindows(now);
    return 1;
  }

  current.count += 1;
  inMemoryRateWindow.set(key, current);
  sweepInMemoryWindows(now);
  return current.count;
}

async function enforceRateLimit(env, scope, sessionId, limit, windowSeconds) {
  const count = await incrementRateCounter(
    env,
    scope,
    sessionId,
    windowSeconds,
  );
  return count <= limit;
}

async function rememberJti(env, sessionId, jti, windowSeconds) {
  const key = `jti:${sessionId}:${jti}`;
  const now = Date.now();
  const expiresAt = now + windowSeconds * 1000;

  if (env.VIDEO_GATE_KV) {
    // NOTE: KV updates are eventually consistent and this read-modify-write
    // can undercount under high concurrency. This trade-off is accepted for
    // low-cost edge replay tracking.
    const existing = await env.VIDEO_GATE_KV.get(key);
    const nextCount = Number(existing || "0") + 1;
    await env.VIDEO_GATE_KV.put(key, String(nextCount), {
      expirationTtl: windowSeconds,
    });
    return nextCount;
  }

  const existing = inMemoryJtiWindow.get(key);
  if (existing && existing.expiresAt > now) {
    existing.count += 1;
    inMemoryJtiWindow.set(key, existing);
    sweepInMemoryWindows(now);
    return existing.count;
  }

  inMemoryJtiWindow.set(key, { expiresAt, count: 1 });
  sweepInMemoryWindows(now);
  return 1;
}

function sweepExpiredEntries(windowMap, now) {
  for (const [key, value] of windowMap) {
    if (
      !value ||
      typeof value.expiresAt !== "number" ||
      value.expiresAt <= now
    ) {
      windowMap.delete(key);
    }
  }
}

function sweepInMemoryWindows(now) {
  inMemorySweepCounter += 1;
  if (inMemorySweepCounter % SWEEP_INTERVAL !== 0) {
    return;
  }

  sweepExpiredEntries(inMemoryRateWindow, now);
  sweepExpiredEntries(inMemoryJtiWindow, now);
  sweepExpiredEntries(inMemorySessionValidationWindow, now);
  sweepExpiredEntries(inMemoryAbuseBlockWindow, now);
  sweepExpiredEntries(inMemoryAbuseIpBlockWindow, now);
}

async function blockSessionForAbuse(env, sessionId, ttlSeconds) {
  const now = Date.now();
  const expiresAt = now + ttlSeconds * 1000;
  const key = `abuse:block:session:${sessionId}`;

  if (env.VIDEO_GATE_KV) {
    await env.VIDEO_GATE_KV.put(key, "1", {
      expirationTtl: Math.max(60, ttlSeconds),
    });
    return;
  }

  inMemoryAbuseBlockWindow.set(key, { expiresAt, blocked: true });
}

async function blockIpPrefixForAbuse(env, ipPrefix, ttlSeconds) {
  if (!ipPrefix) return;

  const now = Date.now();
  const expiresAt = now + ttlSeconds * 1000;
  const key = `abuse:block:ip:${ipPrefix}`;

  if (env.VIDEO_GATE_KV) {
    await env.VIDEO_GATE_KV.put(key, "1", {
      expirationTtl: Math.max(60, ttlSeconds),
    });
    return;
  }

  inMemoryAbuseIpBlockWindow.set(key, { expiresAt, blocked: true });
}

async function isSessionBlockedForAbuse(env, sessionId) {
  const key = `abuse:block:session:${sessionId}`;
  const now = Date.now();

  if (env.VIDEO_GATE_KV) {
    const blocked = await env.VIDEO_GATE_KV.get(key);
    return blocked === "1";
  }

  const blocked = inMemoryAbuseBlockWindow.get(key);
  if (!blocked || blocked.expiresAt <= now) {
    return false;
  }
  return blocked.blocked === true;
}

async function isIpPrefixBlockedForAbuse(env, ipPrefix) {
  if (!ipPrefix) return false;

  const key = `abuse:block:ip:${ipPrefix}`;
  const now = Date.now();

  if (env.VIDEO_GATE_KV) {
    const blocked = await env.VIDEO_GATE_KV.get(key);
    return blocked === "1";
  }

  const blocked = inMemoryAbuseIpBlockWindow.get(key);
  if (!blocked || blocked.expiresAt <= now) {
    return false;
  }
  return blocked.blocked === true;
}

async function authorizeRequest(
  request,
  env,
  expectedAssetId,
  expectedSessionId,
  requestId,
) {
  const token = new URL(request.url).searchParams.get("token") || "";
  const parsed = parseToken(token);
  if (!parsed) {
    return { ok: false, status: 401, message: "Invalid token format" };
  }

  if (!env.VIDEO_PLAYBACK_TOKEN_SECRET) {
    logMissingEnvConfig("gate_missing_playback_token_secret", requestId, {});
    return { ok: false, status: 500, message: "Missing playback token secret" };
  }

  const expectedSig = await signPayload(
    parsed.payloadPart,
    env.VIDEO_PLAYBACK_TOKEN_SECRET,
  );
  if (!timingSafeEqualHex(parsed.signaturePart, expectedSig)) {
    return { ok: false, status: 401, message: "Invalid token signature" };
  }

  const now = Date.now();
  if (typeof parsed.payload?.exp !== "number" || parsed.payload.exp <= now) {
    return { ok: false, status: 401, message: "Expired token" };
  }

  if (
    typeof parsed.payload?.sid !== "string" ||
    parsed.payload.sid.length === 0
  ) {
    return { ok: false, status: 401, message: "Missing token session scope" };
  }

  const sessionBlocked = await isSessionBlockedForAbuse(env, parsed.payload.sid);
  if (sessionBlocked) {
    return {
      ok: false,
      status: 403,
      message: "Session blocked due to abuse",
    };
  }

  if (parsed.payload.assetId !== expectedAssetId) {
    return { ok: false, status: 403, message: "Token asset mismatch" };
  }

  if (expectedSessionId && parsed.payload.sid !== expectedSessionId) {
    return { ok: false, status: 403, message: "Token session mismatch" };
  }

  const ua = request.headers.get("user-agent") || "";
  if (parsed.payload.ua && toBase64(ua).slice(0, 32) !== parsed.payload.ua) {
    return { ok: false, status: 401, message: "User agent mismatch" };
  }

  const ipPrefix = extractIpPrefix(getClientIp(request));
  if (parsed.payload.ip && ipPrefix && parsed.payload.ip !== ipPrefix) {
    return { ok: false, status: 401, message: "IP prefix mismatch" };
  }

  const sessionValid = await validateSessionWithControlPlane(
    env,
    parsed.payload,
    requestId,
  );
  if (!sessionValid) {
    return { ok: false, status: 401, message: "Session validation failed" };
  }

  return { ok: true, tokenPayload: parsed.payload, token };
}

function rewriteManifest(content, token) {
  const lines = content.split("\n");
  const rewritten = lines.map((line) => {
    const trimmed = line.trim();
    if (!trimmed) return line;

    if (trimmed.startsWith("#EXT-X-KEY") && trimmed.includes('URI="')) {
      const uriMatch = trimmed.match(/URI="([^"]+)"/);
      if (!uriMatch) return line;
      const uri = uriMatch[1];
      if (uri.includes("token=")) return line;
      const separator = uri.includes("?") ? "&" : "?";
      const updatedUri = `${uri}${separator}token=${encodeURIComponent(token)}`;
      return line.replace(uriMatch[0], `URI="${updatedUri}"`);
    }

    if (trimmed.startsWith("#")) return line;
    if (trimmed.includes("token=")) return line;

    const separator = trimmed.includes("?") ? "&" : "?";
    return `${trimmed}${separator}token=${encodeURIComponent(token)}`;
  });
  return rewritten.join("\n");
}

function manifestHeaders() {
  return {
    "Content-Type": "application/vnd.apple.mpegurl",
    "Cache-Control": "private, no-store",
  };
}

function segmentHeaders(object) {
  return {
    "Content-Type": object.httpMetadata?.contentType || "video/mp2t",
    "Cache-Control": "private, max-age=30",
  };
}

function keyHeaders() {
  return {
    "Content-Type": "application/octet-stream",
    "Cache-Control": "private, no-store",
  };
}

function isSafePathPart(value) {
  return typeof value === "string" && /^[A-Za-z0-9._-]{1,128}$/.test(value);
}

async function handleMasterManifest(request, env, executionCtx, assetId, requestId) {
  const startedAt = Date.now();
  if (!env.VIDEO_DELIVERY_BUCKET) {
    logMissingEnvConfig("gate_missing_delivery_bucket_binding", requestId, {
      route: "master_manifest",
    });
    return json({ error: "Missing delivery bucket binding" }, 500);
  }

  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId, undefined, requestId);
  if (!auth.ok) return json({ error: auth.message }, auth.status);

  const allowed = await enforceRateLimit(
    env,
    "manifest",
    auth.tokenPayload.sid,
    rateConfig.manifestPerMinute,
    60,
  );
  if (!allowed) {
    queuePlaybackEvent(executionCtx, env, {
      sessionId: auth.tokenPayload.sid,
      eventType: "error",
      path: new URL(request.url).pathname,
      method: request.method,
      httpStatus: 429,
      ipPrefix: extractIpPrefix(getClientIp(request)),
      uaHash: auth.tokenPayload.ua,
      jti: auth.tokenPayload.jti,
      detail: "MANIFEST_RATE_LIMIT",
      latencyMs: Date.now() - startedAt,
    }, requestId);
    return json({ error: "Rate limit exceeded" }, 429);
  }

  const key = `org/${auth.tokenPayload.oid}/lesson/${auth.tokenPayload.lessonId}/asset/${assetId}/master.m3u8`;
  const object = await env.VIDEO_DELIVERY_BUCKET.get(key);
  if (!object) return new Response("Not found", { status: 404 });

  const content = await object.text();
  queuePlaybackEvent(executionCtx, env, {
    sessionId: auth.tokenPayload.sid,
    eventType: "manifest",
    path: new URL(request.url).pathname,
    method: request.method,
    httpStatus: 200,
    ipPrefix: extractIpPrefix(getClientIp(request)),
    uaHash: auth.tokenPayload.ua,
    jti: auth.tokenPayload.jti,
    latencyMs: Date.now() - startedAt,
  }, requestId);
  return new Response(rewriteManifest(content, auth.token), {
    status: 200,
    headers: manifestHeaders(),
  });
}

async function handleRenditionManifest(
  request,
  env,
  executionCtx,
  assetId,
  rendition,
  requestId,
) {
  const startedAt = Date.now();
  if (!env.VIDEO_DELIVERY_BUCKET) {
    logMissingEnvConfig("gate_missing_delivery_bucket_binding", requestId, {
      route: "rendition_manifest",
    });
    return json({ error: "Missing delivery bucket binding" }, 500);
  }

  if (!isSafePathPart(rendition)) {
    return json({ error: "Invalid rendition" }, 400);
  }

  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId, undefined, requestId);
  if (!auth.ok) return json({ error: auth.message }, auth.status);

  const allowed = await enforceRateLimit(
    env,
    "playlist",
    auth.tokenPayload.sid,
    rateConfig.playlistPerMinute,
    60,
  );
  if (!allowed) {
    queuePlaybackEvent(executionCtx, env, {
      sessionId: auth.tokenPayload.sid,
      eventType: "error",
      path: new URL(request.url).pathname,
      method: request.method,
      httpStatus: 429,
      ipPrefix: extractIpPrefix(getClientIp(request)),
      uaHash: auth.tokenPayload.ua,
      jti: auth.tokenPayload.jti,
      detail: "PLAYLIST_RATE_LIMIT",
      latencyMs: Date.now() - startedAt,
    }, requestId);
    return json({ error: "Rate limit exceeded" }, 429);
  }

  const key = `org/${auth.tokenPayload.oid}/lesson/${auth.tokenPayload.lessonId}/asset/${assetId}/${rendition}/index.m3u8`;
  const object = await env.VIDEO_DELIVERY_BUCKET.get(key);
  if (!object) return new Response("Not found", { status: 404 });

  const content = await object.text();
  queuePlaybackEvent(executionCtx, env, {
    sessionId: auth.tokenPayload.sid,
    eventType: "playlist",
    path: new URL(request.url).pathname,
    method: request.method,
    httpStatus: 200,
    ipPrefix: extractIpPrefix(getClientIp(request)),
    uaHash: auth.tokenPayload.ua,
    jti: auth.tokenPayload.jti,
    latencyMs: Date.now() - startedAt,
  }, requestId);
  return new Response(rewriteManifest(content, auth.token), {
    status: 200,
    headers: manifestHeaders(),
  });
}

async function handleSegment(
  request,
  env,
  executionCtx,
  assetId,
  rendition,
  segmentName,
  requestId,
) {
  const startedAt = Date.now();
  if (!env.VIDEO_DELIVERY_BUCKET) {
    logMissingEnvConfig("gate_missing_delivery_bucket_binding", requestId, {
      route: "segment",
    });
    return json({ error: "Missing delivery bucket binding" }, 500);
  }

  if (!isSafePathPart(rendition)) {
    return json({ error: "Invalid rendition" }, 400);
  }
  if (!isSafePathPart(segmentName)) {
    return json({ error: "Invalid segment" }, 400);
  }

  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId, undefined, requestId);
  if (!auth.ok) return json({ error: auth.message }, auth.status);

  const allowed = await enforceRateLimit(
    env,
    "segment",
    auth.tokenPayload.sid,
    rateConfig.segmentPerMinute,
    60,
  );
  if (!allowed) {
    queuePlaybackEvent(executionCtx, env, {
      sessionId: auth.tokenPayload.sid,
      eventType: "error",
      path: new URL(request.url).pathname,
      method: request.method,
      httpStatus: 429,
      ipPrefix: extractIpPrefix(getClientIp(request)),
      uaHash: auth.tokenPayload.ua,
      jti: auth.tokenPayload.jti,
      detail: "SEGMENT_RATE_LIMIT",
      latencyMs: Date.now() - startedAt,
    }, requestId);
    return json({ error: "Rate limit exceeded" }, 429);
  }

  const key = `org/${auth.tokenPayload.oid}/lesson/${auth.tokenPayload.lessonId}/asset/${assetId}/${rendition}/${segmentName}`;
  const object = await env.VIDEO_DELIVERY_BUCKET.get(key);
  if (!object) return new Response("Not found", { status: 404 });

  queuePlaybackEvent(executionCtx, env, {
    sessionId: auth.tokenPayload.sid,
    eventType: "segment",
    path: new URL(request.url).pathname,
    method: request.method,
    httpStatus: 200,
    ipPrefix: extractIpPrefix(getClientIp(request)),
    uaHash: auth.tokenPayload.ua,
    jti: auth.tokenPayload.jti,
    latencyMs: Date.now() - startedAt,
  }, requestId);

  return new Response(object.body, {
    status: 200,
    headers: segmentHeaders(object),
  });
}

async function handleKeyRequest(request, env, executionCtx, assetId, requestId) {
  const startedAt = Date.now();
  const abuseAutoBlockEnabled = getAbuseAutoBlockEnabled(env);
  const abuseIpBlockEnabled = getAbuseIpBlockEnabled(env);
  const abuseBlockTtlSeconds = getAbuseBlockTtlSeconds(env);
  const ipPrefix = getClientIpPrefix(request);
  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId, undefined, requestId);
  if (!auth.ok) return json({ error: auth.message }, auth.status);

  const allowed = await enforceRateLimit(
    env,
    "key",
    auth.tokenPayload.sid,
    rateConfig.keyPerMinute,
    60,
  );
  if (!allowed) {
    queuePlaybackEvent(executionCtx, env, {
        sessionId: auth.tokenPayload.sid,
        eventType: "error",
        path: new URL(request.url).pathname,
        method: request.method,
        httpStatus: 429,
        ipPrefix,
        uaHash: auth.tokenPayload.ua,
        jti: auth.tokenPayload.jti,
        latencyMs: Date.now() - startedAt,
      }, requestId);
    if (abuseAutoBlockEnabled) {
      await blockSessionForAbuse(env, auth.tokenPayload.sid, abuseBlockTtlSeconds);
      if (abuseIpBlockEnabled) {
        await blockIpPrefixForAbuse(env, ipPrefix, abuseBlockTtlSeconds);
      }
      queuePlaybackEvent(executionCtx, env, {
        sessionId: auth.tokenPayload.sid,
        eventType: "revoked",
        path: new URL(request.url).pathname,
        method: request.method,
        httpStatus: 403,
        ipPrefix,
        uaHash: auth.tokenPayload.ua,
        jti: auth.tokenPayload.jti,
        detail: "ABUSE_AUTOBLOCK_KEY_RATE_LIMIT",
        latencyMs: Date.now() - startedAt,
      }, requestId);
    }
    return json({ error: "Rate limit exceeded" }, 429);
  }

  if (!auth.tokenPayload.jti) {
    queuePlaybackEvent(executionCtx, env, {
        sessionId: auth.tokenPayload.sid,
        eventType: "error",
        path: new URL(request.url).pathname,
        method: request.method,
        httpStatus: 401,
        ipPrefix,
        uaHash: auth.tokenPayload.ua,
        latencyMs: Date.now() - startedAt,
      }, requestId);
    return json({ error: "Missing token nonce" }, 401);
  }

  const jtiReuseCount = await rememberJti(
    env,
    auth.tokenPayload.sid,
    auth.tokenPayload.jti,
    rateConfig.keyReplayTtlSeconds,
  );

  if (jtiReuseCount > rateConfig.keyJtiMaxReuse) {
    queuePlaybackEvent(executionCtx, env, {
        sessionId: auth.tokenPayload.sid,
        eventType: "error",
        path: new URL(request.url).pathname,
        method: request.method,
        httpStatus: 429,
        ipPrefix,
        uaHash: auth.tokenPayload.ua,
        jti: auth.tokenPayload.jti,
        detail: "KEY_JTI_REUSE_LIMIT",
        latencyMs: Date.now() - startedAt,
      }, requestId);
    if (abuseAutoBlockEnabled) {
      await blockSessionForAbuse(env, auth.tokenPayload.sid, abuseBlockTtlSeconds);
      if (abuseIpBlockEnabled) {
        await blockIpPrefixForAbuse(env, ipPrefix, abuseBlockTtlSeconds);
      }
      queuePlaybackEvent(executionCtx, env, {
        sessionId: auth.tokenPayload.sid,
        eventType: "revoked",
        path: new URL(request.url).pathname,
        method: request.method,
        httpStatus: 403,
        ipPrefix,
        uaHash: auth.tokenPayload.ua,
        jti: auth.tokenPayload.jti,
        detail: "ABUSE_AUTOBLOCK_KEY_JTI_REUSE",
        latencyMs: Date.now() - startedAt,
      }, requestId);
    }
    return json({ error: "Key token reuse limit exceeded" }, 429);
  }

  const kid = new URL(request.url).searchParams.get("kid");
  if (!kid) return new Response("Missing kid", { status: 400 });
  const safeKid = kid.replace(/\.\./g, "");
  if (safeKid !== "main") {
    return new Response("Not found", { status: 404 });
  }

  if (!env.VIDEO_KEY_ENCRYPTION_SECRET) {
    logMissingEnvConfig("gate_missing_key_encryption_secret", requestId, {});
    return json({ error: "Missing key encryption secret" }, 500);
  }

  const keyMaterial = await fetchPlaybackKeyMaterial(
    env,
    auth.tokenPayload,
    requestId,
  );
  if (!keyMaterial?.wrappedContentKey) {
    return new Response("Not found", { status: 404 });
  }

  const rawKey = await unwrapContentKey(
    keyMaterial.wrappedContentKey,
    env.VIDEO_KEY_ENCRYPTION_SECRET,
  ).catch((error) => {
    console.error(
      "gate_unwrap_content_key_failed",
      error instanceof Error ? error.message : String(error),
    );
    return null;
  });
  if (!rawKey) {
    return new Response("Not found", { status: 404 });
  }

  queuePlaybackEvent(executionCtx, env, {
    sessionId: auth.tokenPayload.sid,
    eventType: "key",
    path: new URL(request.url).pathname,
    method: request.method,
    httpStatus: 200,
    ipPrefix,
    uaHash: auth.tokenPayload.ua,
    jti: auth.tokenPayload.jti,
    latencyMs: Date.now() - startedAt,
  }, requestId);

  return new Response(rawKey, {
    status: 200,
    headers: keyHeaders(),
  });
}

export default {
  async fetch(request, env, executionCtx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const requestId = getRequestId(request);
    const clientIpPrefix = getClientIpPrefix(request);

    if (request.method === "OPTIONS" && isPlaybackRoute(path)) {
      return buildCorsPreflightResponse(request, env, requestId);
    }

    if (isPlaybackRoute(path) && (await isIpPrefixBlockedForAbuse(env, clientIpPrefix))) {
      return applyResponseHeaders(
        json(
          {
            error: "Blocked due to abuse policy",
            detail: "ip_prefix_blocked_abuse",
          },
          403,
          {
            "Cache-Control": "no-store",
          },
        ),
        request,
        env,
        requestId,
      );
    }

    if (isPlaybackRoute(path) && request.method !== "GET") {
      return applyResponseHeaders(
        json({ error: "Method Not Allowed" }, 405, {
          Allow: "GET, OPTIONS",
          "Cache-Control": "no-store",
        }),
        request,
        env,
        requestId,
      );
    }

    if (env.VIDEO_GATE_MAINTENANCE_MODE === "true" && path !== "/health") {
      return applyResponseHeaders(
        json(
        { error: "Playback is temporarily unavailable", code: "MAINTENANCE" },
        503,
        {
          "Cache-Control": "no-store",
        },
        ),
        request,
        env,
        requestId,
      );
    }

    if (path === "/health") {
      return applyResponseHeaders(
        json({ ok: true, service: "kashkool-video-gate" }),
        request,
        env,
        requestId,
      );
    }

    const contextValidation = validateRequestContext(request, env);
    if (!contextValidation.ok) {
      return applyResponseHeaders(
        json(
        {
          error: "Request context validation failed",
          detail: contextValidation.reason,
        },
        403,
        {
          "Cache-Control": "no-store",
        },
        ),
        request,
        env,
        requestId,
      );
    }

    const masterMatch = path.match(/^\/v\/([^/]+)\/master\.m3u8$/);
    if (masterMatch) {
      const response = await handleMasterManifest(
        request,
        env,
        executionCtx,
        masterMatch[1],
        requestId,
      );
      return applyResponseHeaders(response, request, env, requestId);
    }

    const renditionMatch = path.match(/^\/v\/([^/]+)\/([^/]+)\/index\.m3u8$/);
    if (renditionMatch) {
      const response = await handleRenditionManifest(
        request,
        env,
        executionCtx,
        renditionMatch[1],
        renditionMatch[2],
        requestId,
      );
      return applyResponseHeaders(response, request, env, requestId);
    }

    const segmentMatch = path.match(/^\/v\/([^/]+)\/([^/]+)\/([^/]+)$/);
    if (segmentMatch) {
      const response = await handleSegment(
        request,
        env,
        executionCtx,
        segmentMatch[1],
        segmentMatch[2],
        segmentMatch[3],
        requestId,
      );
      return applyResponseHeaders(response, request, env, requestId);
    }

    const keyMatch = path.match(/^\/k\/([^/]+)$/);
    if (keyMatch) {
      const response = await handleKeyRequest(
        request,
        env,
        executionCtx,
        keyMatch[1],
        requestId,
      );
      return applyResponseHeaders(response, request, env, requestId);
    }

    return applyResponseHeaders(
      new Response("Not found", { status: 404 }),
      request,
      env,
      requestId,
    );
  },
};
