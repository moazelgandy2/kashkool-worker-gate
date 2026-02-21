import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import test from "node:test";

import worker, { __resetForTests } from "./index.mjs";

function base64UrlEncode(value) {
  return Buffer.from(value, "utf8")
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function signTokenPayload(encodedPayload, secret) {
  return createHmac("sha256", secret).update(encodedPayload).digest("hex");
}

function makeToken(payload, secret) {
  const encoded = base64UrlEncode(JSON.stringify(payload));
  const signature = signTokenPayload(encoded, secret);
  return `${encoded}.${signature}`;
}

function wrapKey(rawKeyBuffer, secret) {
  const key = createHash("sha256").update(secret, "utf8").digest();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(rawKeyBuffer), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return `v1:${iv.toString("base64")}:${Buffer.concat([encrypted, authTag]).toString("base64")}`;
}

function createEnv(overrides = {}) {
  return {
    VIDEO_PLAYBACK_TOKEN_SECRET: "token_secret",
    VIDEO_KEY_ENCRYPTION_SECRET: "key_secret",
    VIDEO_GATE_VALIDATION_SECRET: "gate_secret",
    VIDEO_GATE_VALIDATION_URL: "https://main.local/video-playback-validate",
    VIDEO_GATE_KEY_URL: "https://main.local/video-playback-key",
    VIDEO_GATE_MAINTENANCE_MODE: "false",
    VIDEO_GATE_KEY_PER_MINUTE: "5",
    VIDEO_DELIVERY_BUCKET: {
      async get() {
        return {
          async text() {
            return "#EXTM3U\n";
          },
          body: new Uint8Array([1, 2, 3]),
          httpMetadata: { contentType: "application/vnd.apple.mpegurl" },
        };
      },
    },
    ...overrides,
  };
}

test.beforeEach(() => {
  __resetForTests();
});

test("returns maintenance response when enabled", async () => {
  const env = createEnv({ VIDEO_GATE_MAINTENANCE_MODE: "true" });
  const request = new Request("https://gate.local/v/asset_1/master.m3u8");
  const response = await worker.fetch(request, env);

  assert.equal(response.status, 503);
});

test("strict request context blocks requests without browser context headers", async () => {
  const payload = {
    sid: "session_strict_context",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "strict_context_jti",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv({
    VIDEO_GATE_STRICT_REQUEST_CONTEXT: "true",
    VIDEO_GATE_ALLOWED_ORIGINS: "https://app.local",
  });
  const request = new Request(
    `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
  );

  const response = await worker.fetch(request, env);
  assert.equal(response.status, 403);
});

test("strict request context allows cross-site when origin is allowlisted", async () => {
  const payload = {
    sid: "session_strict_context_allowed",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "strict_context_allowed_jti",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv({
    VIDEO_GATE_STRICT_REQUEST_CONTEXT: "true",
    VIDEO_GATE_ALLOWED_ORIGINS: "https://app.local",
  });

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const request = new Request(
      `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
      {
        headers: {
          Origin: "https://app.local",
          Referer: "https://app.local/watch",
          "Sec-Fetch-Site": "cross-site",
        },
      },
    );

    const response = await worker.fetch(request, env);
    assert.equal(response.status, 200);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("strict request context blocks cross-site when referer is not allowlisted", async () => {
  const payload = {
    sid: "session_strict_context_blocked",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "strict_context_blocked_jti",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv({
    VIDEO_GATE_STRICT_REQUEST_CONTEXT: "true",
    VIDEO_GATE_ALLOWED_ORIGINS: "https://app.local",
  });

  const request = new Request(
    `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
    {
      headers: {
        Referer: "https://evil.example/watch",
        "Sec-Fetch-Site": "cross-site",
      },
    },
  );

  const response = await worker.fetch(request, env);
  assert.equal(response.status, 403);
});

test("rejects tampered token signature", async () => {
  const payload = {
    sid: "session_1",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "jti_1",
  };

  const token = `${makeToken(payload, "wrong_secret")}`;
  const env = createEnv();
  const request = new Request(
    `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
  );

  const response = await worker.fetch(request, env);
  assert.equal(response.status, 401);
});

test("includes request id header on auth failures", async () => {
  const requestId = "req_auth_fail_1";
  const env = createEnv();
  const request = new Request("https://gate.local/v/asset_1/master.m3u8?token=bad_token", {
    headers: {
      "x-kashkool-request-id": requestId,
    },
  });

  const response = await worker.fetch(request, env);
  assert.equal(response.status, 401);
  assert.equal(response.headers.get("x-kashkool-request-id"), requestId);
});

test("rejects token scope mismatch", async () => {
  const payload = {
    sid: "session_2",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_2",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "jti_2",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv();
  const request = new Request(
    `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
  );

  const response = await worker.fetch(request, env);
  assert.equal(response.status, 403);
});

test("allows limited key jti reuse for seek stability", async () => {
  const payload = {
    sid: "session_replay",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "replay_jti",
  };

  const token = makeToken(payload, "token_secret");
  const wrappedContentKey = wrapKey(Buffer.from("0123456789abcdef"), "key_secret");

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(url).includes("/video-playback-key")) {
      return new Response(
        JSON.stringify({ wrappedContentKey, contentKeyVersion: "v1" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv();
    const first = await worker.fetch(
      new Request(`https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(first.status, 200);

    const second = await worker.fetch(
      new Request(`https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(second.status, 200);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("blocks excessive key jti reuse", async () => {
  const payload = {
    sid: "session_reuse_limit",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "reuse_limit_jti",
  };

  const token = makeToken(payload, "token_secret");
  const wrappedContentKey = wrapKey(Buffer.from("0123456789abcdef"), "key_secret");

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(url).includes("/video-playback-key")) {
      return new Response(
        JSON.stringify({ wrappedContentKey, contentKeyVersion: "v1" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv({ VIDEO_GATE_KEY_JTI_MAX_REUSE: "2" });
    const first = await worker.fetch(
      new Request(`https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(first.status, 200);

    const second = await worker.fetch(
      new Request(`https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(second.status, 200);

    const third = await worker.fetch(
      new Request(`https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(third.status, 429);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("enforces key endpoint rate limit", async () => {
  const env = createEnv({ VIDEO_GATE_KEY_PER_MINUTE: "1" });

  const wrappedContentKey = wrapKey(Buffer.from("0123456789abcdef"), "key_secret");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(url).includes("/video-playback-key")) {
      return new Response(
        JSON.stringify({ wrappedContentKey, contentKeyVersion: "v1" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const firstToken = makeToken(
      {
        sid: "session_limit",
        uid: "user_1",
        oid: "org_1",
        lessonId: "lesson_1",
        assetId: "asset_1",
        exp: Date.now() + 60_000,
        v: 1,
        jti: "limit_jti_1",
      },
      "token_secret",
    );

    const secondToken = makeToken(
      {
        sid: "session_limit",
        uid: "user_1",
        oid: "org_1",
        lessonId: "lesson_1",
        assetId: "asset_1",
        exp: Date.now() + 60_000,
        v: 1,
        jti: "limit_jti_2",
      },
      "token_secret",
    );

    const first = await worker.fetch(
      new Request(
        `https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(firstToken)}`,
      ),
      env,
    );
    assert.equal(first.status, 200);

    const second = await worker.fetch(
      new Request(
        `https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(secondToken)}`,
      ),
      env,
    );
    assert.equal(second.status, 429);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("sanitizes BOM-prefixed control-plane URLs", async () => {
  const payload = {
    sid: "session_bom",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "bom_jti",
  };

  const token = makeToken(payload, "token_secret");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url) === "https://main.local/video-playback-validate") {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv({
      VIDEO_GATE_KEY_URL: undefined,
      CONTROL_PLANE_BASE_URL: "\uFEFFhttps://main.local",
      VIDEO_GATE_VALIDATION_URL: "\uFEFFhttps://main.local/video-playback-validate",
    });

    const response = await worker.fetch(
      new Request(`https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(response.status, 200);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("enforces token expiry even when control-plane validation is enabled", async () => {
  const payload = {
    sid: "session_expired",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() - 1_000,
    v: 1,
    jti: "expired_jti",
  };

  const token = makeToken(payload, "token_secret");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv({
      VIDEO_GATE_VALIDATION_URL: "https://main.local/video-playback-validate",
    });
    const response = await worker.fetch(
      new Request(`https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(response.status, 401);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("fails closed when control-plane validation request throws", async () => {
  const payload = {
    sid: "session_validation_throw",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "validation_throw_jti",
  };

  const token = makeToken(payload, "token_secret");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      throw new Error("upstream timeout");
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv({
      VIDEO_GATE_VALIDATION_URL: "https://main.local/video-playback-validate",
    });
    const response = await worker.fetch(
      new Request(
        `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
      ),
      env,
    );
    assert.equal(response.status, 401);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("fails closed when validation config is missing", async () => {
  const payload = {
    sid: "session_missing_config",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "missing_config_jti",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv({
    VIDEO_GATE_VALIDATION_URL: undefined,
    CONTROL_PLANE_BASE_URL: undefined,
  });

  const response = await worker.fetch(
    new Request(`https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`),
    env,
  );

  assert.equal(response.status, 401);
});

test("adds CORS header for allowed origins", async () => {
  const payload = {
    sid: "session_cors",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "cors_jti",
  };

  const token = makeToken(payload, "token_secret");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const origin = "https://app.local";
    const env = createEnv({ VIDEO_GATE_ALLOWED_ORIGINS: origin });
    const response = await worker.fetch(
      new Request(
        `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
        { headers: { Origin: origin } },
      ),
      env,
    );
    assert.equal(response.status, 200);
    assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("handles CORS preflight for playback routes", async () => {
  const origin = "https://app.local";
  const env = createEnv({ VIDEO_GATE_ALLOWED_ORIGINS: origin });

  const response = await worker.fetch(
    new Request("https://gate.local/v/asset_1/master.m3u8", {
      method: "OPTIONS",
      headers: { Origin: origin },
    }),
    env,
  );

  assert.equal(response.status, 204);
  assert.equal(response.headers.get("Access-Control-Allow-Origin"), origin);
  assert.equal(response.headers.get("Access-Control-Allow-Methods"), "GET, OPTIONS");
  assert.ok(response.headers.get("x-kashkool-request-id"));
});

test("rejects non-GET methods on playback routes", async () => {
  const env = createEnv();
  const response = await worker.fetch(
    new Request("https://gate.local/v/asset_1/master.m3u8", {
      method: "POST",
    }),
    env,
  );

  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, OPTIONS");
});

test("rejects invalid rendition path part", async () => {
  const payload = {
    sid: "session_invalid_rendition",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "invalid_rendition_jti",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv();
  const response = await worker.fetch(
    new Request(
      `https://gate.local/v/asset_1/bad%24rendition/index.m3u8?token=${encodeURIComponent(token)}`,
    ),
    env,
  );

  assert.equal(response.status, 400);
});

test("rejects invalid segment path part", async () => {
  const payload = {
    sid: "session_invalid_segment",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "invalid_segment_jti",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv();
  const response = await worker.fetch(
    new Request(
      `https://gate.local/v/asset_1/720p/%2e%2e%2fsecret.ts?token=${encodeURIComponent(token)}`,
    ),
    env,
  );

  assert.equal(response.status, 400);
});

test("caches session validation result for repeated requests", async () => {
  const payload = {
    sid: "session_cache",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "cache_jti",
  };

  const token = makeToken(payload, "token_secret");
  let validationCalls = 0;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      validationCalls += 1;
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv({
      VIDEO_GATE_VALIDATION_URL: "https://main.local/video-playback-validate",
      VIDEO_GATE_SESSION_VALIDATION_CACHE_TTL_SECONDS: "30",
    });
    const url = `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`;

    const first = await worker.fetch(new Request(url), env);
    assert.equal(first.status, 200);

    const second = await worker.fetch(new Request(url), env);
    assert.equal(second.status, 200);
    assert.equal(validationCalls, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("propagates request id to control-plane validation call", async () => {
  const payload = {
    sid: "session_request_id",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "request_id_jti",
  };

  const token = makeToken(payload, "token_secret");
  const requestId = "req_test_123";
  let seenRequestId = null;

  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    if (String(url).includes("/video-playback-validate")) {
      const headers = new Headers(init.headers || {});
      seenRequestId = headers.get("x-kashkool-request-id");
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv();
    const response = await worker.fetch(
      new Request(
        `https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`,
        { headers: { "x-kashkool-request-id": requestId } },
      ),
      env,
    );
    assert.equal(response.status, 200);
    assert.equal(seenRequestId, requestId);
    assert.equal(response.headers.get("x-kashkool-request-id"), requestId);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("returns 404 when wrapped content key cannot be unwrapped", async () => {
  const payload = {
    sid: "session_bad_wrapped_key",
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "bad_wrapped_key_jti",
  };

  const token = makeToken(payload, "token_secret");
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    if (String(url).includes("/video-playback-validate")) {
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (String(url).includes("/video-playback-key")) {
      return new Response(
        JSON.stringify({ wrappedContentKey: "invalid-format", contentKeyVersion: "v1" }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    }
    return new Response("Not found", { status: 404 });
  };

  try {
    const env = createEnv();
    const response = await worker.fetch(
      new Request(`https://gate.local/k/asset_1?kid=main&token=${encodeURIComponent(token)}`),
      env,
    );
    assert.equal(response.status, 404);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("rejects token without required session scope", async () => {
  const payload = {
    uid: "user_1",
    oid: "org_1",
    lessonId: "lesson_1",
    assetId: "asset_1",
    exp: Date.now() + 60_000,
    v: 1,
    jti: "no_sid_jti",
  };

  const token = makeToken(payload, "token_secret");
  const env = createEnv();
  const response = await worker.fetch(
    new Request(`https://gate.local/v/asset_1/master.m3u8?token=${encodeURIComponent(token)}`),
    env,
  );
  assert.equal(response.status, 401);
});
