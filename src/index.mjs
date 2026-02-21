const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();
const inMemoryRateWindow = new Map();
const inMemoryJtiWindow = new Map();

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

function sanitizeEnvString(value) {
  return String(value || "").replace(/^\uFEFF/, "").trim();
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

  const allowedOrigins = getAllowedOrigins(env);
  if (allowedOrigins.length === 0) {
    return { ok: false, reason: "Strict request context enabled without allowed origins" };
  }

  const origin = request.headers.get("Origin");
  const referer = request.headers.get("Referer");
  const secFetchSite = request.headers.get("Sec-Fetch-Site");

  if (origin && !allowedOrigins.includes(origin)) {
    return { ok: false, reason: "Origin not allowed" };
  }

  if (
    referer &&
    !allowedOrigins.some((allowedOrigin) => referer.startsWith(`${allowedOrigin}/`) || referer === allowedOrigin)
  ) {
    return { ok: false, reason: "Referer not allowed" };
  }

  if (secFetchSite && secFetchSite === "cross-site") {
    return { ok: false, reason: "Cross-site fetch blocked" };
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
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
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
  const digest = await crypto.subtle.digest("SHA-256", toBase64UrlBytes(secret));
  return crypto.subtle.importKey("raw", digest, { name: "AES-GCM" }, false, [
    "decrypt",
  ]);
}

async function unwrapContentKey(wrappedContentKey, secret) {
  const [version, ivBase64, payloadBase64] = (wrappedContentKey || "").split(":");
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

async function fetchPlaybackKeyMaterial(env, tokenPayload) {
  const keyUrl = resolveControlPlaneEndpoint(
    env,
    "VIDEO_GATE_KEY_URL",
    "/video-playback-key",
  );

  if (!keyUrl || !env.VIDEO_GATE_VALIDATION_SECRET) {
    return null;
  }

  const response = await fetch(keyUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-kashkool-gate-secret": env.VIDEO_GATE_VALIDATION_SECRET,
    },
    body: JSON.stringify({
      sessionId: tokenPayload.sid,
      userId: tokenPayload.uid,
      lessonId: tokenPayload.lessonId,
      assetId: tokenPayload.assetId,
      tokenVersion: tokenPayload.v,
    }),
  });

  if (!response.ok) {
    return null;
  }

  return response.json();
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

async function validateSessionWithControlPlane(env, tokenPayload) {
  const validationUrl = resolveControlPlaneEndpoint(
    env,
    "VIDEO_GATE_VALIDATION_URL",
    "/video-playback-validate",
  );

  if (!validationUrl || !env.VIDEO_GATE_VALIDATION_SECRET) {
    return true;
  }

  const response = await fetch(validationUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-kashkool-gate-secret": env.VIDEO_GATE_VALIDATION_SECRET,
    },
    body: JSON.stringify({
      sessionId: tokenPayload.sid,
      userId: tokenPayload.uid,
      lessonId: tokenPayload.lessonId,
      assetId: tokenPayload.assetId,
      tokenVersion: tokenPayload.v,
    }),
  });

  if (!response.ok) return false;
  const body = await response.json().catch(() => ({ ok: false }));
  return body.ok === true;
}

async function emitPlaybackEvent(env, payload) {
  const eventUrl = resolveControlPlaneEndpoint(
    env,
    "VIDEO_GATE_EVENT_URL",
    "/video-playback-event",
  );

  if (!eventUrl || !env.VIDEO_GATE_VALIDATION_SECRET) {
    return;
  }

  try {
    await fetch(eventUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-kashkool-gate-secret": env.VIDEO_GATE_VALIDATION_SECRET,
      },
      body: JSON.stringify(payload),
    });
  } catch {
    // Do not fail playback if telemetry fails.
  }
}

function queuePlaybackEvent(executionCtx, env, payload) {
  const promise = emitPlaybackEvent(env, payload);
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
    return 1;
  }

  current.count += 1;
  inMemoryRateWindow.set(key, current);
  return current.count;
}

async function enforceRateLimit(
  env,
  scope,
  sessionId,
  limit,
  windowSeconds,
) {
  const count = await incrementRateCounter(env, scope, sessionId, windowSeconds);
  return count <= limit;
}

async function rememberJti(env, sessionId, jti, windowSeconds) {
  const key = `jti:${sessionId}:${jti}`;
  const now = Date.now();
  const expiresAt = now + windowSeconds * 1000;

  if (env.VIDEO_GATE_KV) {
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
    return existing.count;
  }

  inMemoryJtiWindow.set(key, { expiresAt, count: 1 });
  return 1;
}

async function authorizeRequest(request, env, expectedAssetId, expectedSessionId) {
  const token = new URL(request.url).searchParams.get("token") || "";
  const parsed = parseToken(token);
  if (!parsed) {
    return { ok: false, status: 401, message: "Invalid token format" };
  }

  if (!env.VIDEO_PLAYBACK_TOKEN_SECRET) {
    return { ok: false, status: 500, message: "Missing playback token secret" };
  }

  const expectedSig = await signPayload(
    parsed.payloadPart,
    env.VIDEO_PLAYBACK_TOKEN_SECRET,
  );
  if (!timingSafeEqualHex(parsed.signaturePart, expectedSig)) {
    return { ok: false, status: 401, message: "Invalid token signature" };
  }

  const hasControlPlaneValidation =
    !!resolveControlPlaneEndpoint(
      env,
      "VIDEO_GATE_VALIDATION_URL",
      "/video-playback-validate",
    ) && !!env.VIDEO_GATE_VALIDATION_SECRET;

  if (!hasControlPlaneValidation) {
    const now = Date.now();
    if (typeof parsed.payload?.exp !== "number" || parsed.payload.exp <= now) {
      return { ok: false, status: 401, message: "Expired token" };
    }
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

  const sessionValid = await validateSessionWithControlPlane(env, parsed.payload);
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

async function handleMasterManifest(request, env, executionCtx, assetId) {
  const startedAt = Date.now();
  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId);
  if (!auth.ok) return json({ error: auth.message }, auth.status);

  const allowed = await enforceRateLimit(
    env,
    "manifest",
    auth.tokenPayload.sid,
    rateConfig.manifestPerMinute,
    60,
  );
  if (!allowed) {
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
  });
  return new Response(rewriteManifest(content, auth.token), {
    status: 200,
    headers: manifestHeaders(),
  });
}

async function handleRenditionManifest(request, env, executionCtx, assetId, rendition) {
  const startedAt = Date.now();
  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId);
  if (!auth.ok) return json({ error: auth.message }, auth.status);

  const allowed = await enforceRateLimit(
    env,
    "playlist",
    auth.tokenPayload.sid,
    rateConfig.playlistPerMinute,
    60,
  );
  if (!allowed) {
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
  });
  return new Response(rewriteManifest(content, auth.token), {
    status: 200,
    headers: manifestHeaders(),
  });
}

async function handleSegment(request, env, executionCtx, assetId, rendition, segmentName) {
  const startedAt = Date.now();
  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId);
  if (!auth.ok) return json({ error: auth.message }, auth.status);

  const allowed = await enforceRateLimit(
    env,
    "segment",
    auth.tokenPayload.sid,
    rateConfig.segmentPerMinute,
    60,
  );
  if (!allowed) {
    return json({ error: "Rate limit exceeded" }, 429);
  }

  const safeSegmentName = segmentName.replace(/\.\./g, "");
  const key = `org/${auth.tokenPayload.oid}/lesson/${auth.tokenPayload.lessonId}/asset/${assetId}/${rendition}/${safeSegmentName}`;
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
  });

  return new Response(object.body, {
    status: 200,
    headers: segmentHeaders(object),
  });
}

async function handleKeyRequest(request, env, executionCtx, assetId) {
  const startedAt = Date.now();
  const rateConfig = getRateConfig(env);
  const auth = await authorizeRequest(request, env, assetId);
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
      ipPrefix: extractIpPrefix(getClientIp(request)),
      uaHash: auth.tokenPayload.ua,
      jti: auth.tokenPayload.jti,
      latencyMs: Date.now() - startedAt,
    });
    return json({ error: "Rate limit exceeded" }, 429);
  }

  if (!auth.tokenPayload.jti) {
    queuePlaybackEvent(executionCtx, env, {
      sessionId: auth.tokenPayload.sid,
      eventType: "error",
      path: new URL(request.url).pathname,
      method: request.method,
      httpStatus: 401,
      ipPrefix: extractIpPrefix(getClientIp(request)),
      uaHash: auth.tokenPayload.ua,
      latencyMs: Date.now() - startedAt,
    });
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
      ipPrefix: extractIpPrefix(getClientIp(request)),
      uaHash: auth.tokenPayload.ua,
      jti: auth.tokenPayload.jti,
      detail: "KEY_JTI_REUSE_LIMIT",
      latencyMs: Date.now() - startedAt,
    });
    return json({ error: "Key token reuse limit exceeded" }, 429);
  }

  const kid = new URL(request.url).searchParams.get("kid");
  if (!kid) return new Response("Missing kid", { status: 400 });
  const safeKid = kid.replace(/\.\./g, "");
  if (safeKid !== "main") {
    return new Response("Not found", { status: 404 });
  }

  if (!env.VIDEO_KEY_ENCRYPTION_SECRET) {
    return json({ error: "Missing key encryption secret" }, 500);
  }

  const keyMaterial = await fetchPlaybackKeyMaterial(env, auth.tokenPayload);
  if (!keyMaterial?.wrappedContentKey) {
    return new Response("Not found", { status: 404 });
  }

  const rawKey = await unwrapContentKey(
    keyMaterial.wrappedContentKey,
    env.VIDEO_KEY_ENCRYPTION_SECRET,
  );

  queuePlaybackEvent(executionCtx, env, {
    sessionId: auth.tokenPayload.sid,
    eventType: "key",
    path: new URL(request.url).pathname,
    method: request.method,
    httpStatus: 200,
    ipPrefix: extractIpPrefix(getClientIp(request)),
    uaHash: auth.tokenPayload.ua,
    jti: auth.tokenPayload.jti,
    latencyMs: Date.now() - startedAt,
  });

  return new Response(rawKey, {
    status: 200,
    headers: keyHeaders(),
  });
}

export default {
  async fetch(request, env, executionCtx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (env.VIDEO_GATE_MAINTENANCE_MODE === "true" && path !== "/health") {
      return json(
        { error: "Playback is temporarily unavailable", code: "MAINTENANCE" },
        503,
        {
          "Cache-Control": "no-store",
        },
      );
    }

    if (path === "/health") {
      return json({ ok: true, service: "kashkool-video-gate" });
    }

    const contextValidation = validateRequestContext(request, env);
    if (!contextValidation.ok) {
      return json(
        {
          error: "Request context validation failed",
          detail: contextValidation.reason,
        },
        403,
        {
          "Cache-Control": "no-store",
        },
      );
    }

    const masterMatch = path.match(/^\/v\/([^/]+)\/master\.m3u8$/);
    if (masterMatch) {
      return handleMasterManifest(request, env, executionCtx, masterMatch[1]);
    }

    const renditionMatch = path.match(/^\/v\/([^/]+)\/([^/]+)\/index\.m3u8$/);
    if (renditionMatch) {
      return handleRenditionManifest(
        request,
        env,
        executionCtx,
        renditionMatch[1],
        renditionMatch[2],
      );
    }

    const segmentMatch = path.match(/^\/v\/([^/]+)\/([^/]+)\/([^/]+)$/);
    if (segmentMatch) {
      return handleSegment(
        request,
        env,
        executionCtx,
        segmentMatch[1],
        segmentMatch[2],
        segmentMatch[3],
      );
    }

    const keyMatch = path.match(/^\/k\/([^/]+)$/);
    if (keyMatch) {
      return handleKeyRequest(request, env, executionCtx, keyMatch[1]);
    }

    return new Response("Not found", { status: 404 });
  },
};
