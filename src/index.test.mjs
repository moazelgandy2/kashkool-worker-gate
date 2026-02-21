import assert from "node:assert/strict";
import { createCipheriv, createHash, createHmac, randomBytes } from "node:crypto";
import test from "node:test";

import worker from "./index.mjs";

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

test("returns maintenance response when enabled", async () => {
  const env = createEnv({ VIDEO_GATE_MAINTENANCE_MODE: "true" });
  const request = new Request("https://gate.local/v/asset_1/master.m3u8");
  const response = await worker.fetch(request, env);

  assert.equal(response.status, 503);
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
