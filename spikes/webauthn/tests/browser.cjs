// Executes the shipped script with test doubles, not a browser or authenticator.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { resolve } = require("node:path");
const vm = require("node:vm");
const sourcePath = resolve(__dirname, "../web/app.js");
const source = readFileSync(sourcePath, "utf8");
const token = "a".repeat(64);
const buffer = Uint8Array.of(251, 255, 0).buffer;
const encoded = "-_8A";
const deferred = () => {
  let resolve;
  const promise = new Promise((r) => { resolve = r; });
  return { promise, resolve };
};

function setup({ credentials, finish, rejection } = {}) {
  const elements = Object.fromEntries(["token", "unlock", "register", "authenticate", "cancel", "status"].map((id) => [id, {
    value: "", disabled: false, textContent: "", addEventListener(_, fn) { this.click = fn; },
  }]));
  const requests = [];
  const calls = [];
  const defaultCredential = {
    id: encoded, rawId: buffer, type: "public-key",
    response: { clientDataJSON: buffer, attestationObject: buffer, authenticatorData: buffer, signature: buffer, userHandle: null, getTransports: () => ["internal"] },
    getClientExtensionResults: () => ({}),
  };
  vm.runInNewContext(source, {
    document: { getElementById: (id) => elements[id] },
    window: { isSecureContext: true, PublicKeyCredential: function () {} },
    navigator: { credentials: Object.fromEntries(["create", "get"].map((method) => [method, async (options) => {
      calls.push({ method, options });
      return credentials ? credentials(options) : defaultCredential;
    }])) },
    AbortController, AbortSignal, DOMException, Uint8Array, atob, btoa,
    fetch: async (url, options) => {
      const body = JSON.parse(options.body);
      requests.push({ url, options, body });
      if (rejection) return rejection;
      if (body.operation.startsWith("finish") && finish) await finish();
      return { ok: true, json: async () => ({ id: "ceremony", options: { publicKey: {
        challenge: encoded, user: { id: encoded },
        ...(body.operation === "register" ? { excludeCredentials: [{ id: encoded }] } : { allowCredentials: [{ id: encoded }] }),
      } } }) };
    },
  }, { filename: sourcePath });
  elements.token.value = token;
  elements.unlock.click();
  return { elements, requests, calls };
}

test("registration and assertion preserve binary data and isolate the token", async () => {
  for (const action of ["register", "authenticate"]) {
    const f = setup();
    assert.equal(f.elements.token.value, "");
    await f.elements[action].click();
    const submitted = f.requests.find((r) => r.body.operation.startsWith("finish"));
    assert.equal(submitted.body.credential.rawId, encoded);
    assert.equal(submitted.body.credential.response.clientDataJSON, encoded);
    assert.equal(submitted.body.credential.response[action === "register" ? "attestationObject" : "signature"], encoded);
    assert.deepEqual(Array.from(f.calls[0].options.publicKey.challenge), [251, 255, 0]);
    const list = f.calls[0].options.publicKey[action === "register" ? "excludeCredentials" : "allowCredentials"];
    assert.deepEqual(Array.from(list[0].id), [251, 255, 0]);
    for (const req of f.requests) {
      assert.equal(req.url, "/api");
      assert.equal(req.options.headers.Authorization, `Bearer ${token}`);
      assert.equal(req.options.credentials, "omit");
      assert.ok(!req.options.body.includes(token));
    }
    assert.equal(f.elements.cancel.disabled, true);
  }
});

test("cancelling the platform prompt cancels server state and never submits", async () => {
  const entered = deferred();
  const f = setup({ credentials: ({ signal }) => new Promise((_, reject) => {
    signal.addEventListener("abort", () => reject(new DOMException("Cancelled", "AbortError")));
    entered.resolve();
  }) });
  const running = f.elements.register.click();
  await entered.promise;
  assert.equal(f.elements.cancel.disabled, false);
  f.elements.cancel.click();
  await running;
  assert.deepEqual(f.requests.map((r) => r.body.operation), ["register", "cancel"]);
  assert.match(f.elements.status.textContent, /AbortError/);
});

test("cancel is disabled once submission starts and cannot abort the authenticator", async () => {
  const entered = deferred();
  const finish = deferred();
  const f = setup({ finish: () => { entered.resolve(); return finish.promise; } });
  const running = f.elements.authenticate.click();
  await entered.promise;
  assert.equal(f.elements.cancel.disabled, true);
  assert.match(f.elements.status.textContent, /Cancellation is no longer available/);
  f.elements.cancel.click();
  assert.equal(f.calls[0].options.signal.aborted, false);
  finish.resolve();
  await running;
  assert.match(f.elements.status.textContent, /Verified: user verification/);
});

test("platform rejection cancels pending state without submitting", async () => {
  const f = setup({ credentials: async () => { throw new DOMException("Private device message", "NotAllowedError"); } });
  await f.elements.register.click();
  assert.deepEqual(f.requests.map((r) => r.body.operation), ["register", "cancel"]);
  assert.ok(!f.elements.status.textContent.includes("Private device message"));
  assert.equal(f.elements.register.disabled, false);
});

test("known conflict codes give specific recovery instructions without invoking the authenticator", async () => {
  for (const [code, expected] of [
    ["already_registered", /already has a passkey.*Select Verify/],
    ["not_registered", /Register a test passkey/],
    ["ceremony_pending", /Another ceremony is pending/],
    ["missing_or_expired_ceremony", /completed, cancelled, or expired/],
  ]) {
    const f = setup({ rejection: { ok: false, status: 409, json: async () => ({ error: code }) } });
    await f.elements.register.click();
    assert.match(f.elements.status.textContent, expected);
    assert.equal(f.calls.length, 0);
    assert.equal(f.requests.length, 1);
    assert.equal(f.elements.register.disabled, false);
    if (code === "already_registered") assert.ok(!f.elements.status.textContent.includes("wait 120"));
  }
});

test("untrusted malformed and unknown rejection bodies are never reflected", async () => {
  for (const payload of [null, {}, { error: "SECRET" }, { error: "__proto__" }, { error: { value: "SECRET" } }]) {
    const f = setup({ rejection: { ok: false, status: 409, json: async () => payload } });
    await f.elements.register.click();
    assert.match(f.elements.status.textContent, /^Request rejected \(409\)/);
    assert.ok(!f.elements.status.textContent.includes("SECRET"));
  }
});

test("non-JSON and mismatched-status rejections use generic local messages", async () => {
  for (const rejection of [
    { ok: false, status: 403, json: async () => { throw new Error("SECRET response"); } },
    { ok: false, status: 500, json: async () => ({ error: "already_registered" }) },
  ]) {
    const f = setup({ rejection });
    await f.elements.register.click();
    assert.match(f.elements.status.textContent, /^Request rejected/);
    assert.ok(!f.elements.status.textContent.includes("SECRET"));
    assert.ok(!f.elements.status.textContent.includes("already has a passkey"));
  }
});
