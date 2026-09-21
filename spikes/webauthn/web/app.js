"use strict";

const element = (id) => document.getElementById(id);
let token = "";
let active = null;
let busy = false;

function controls() {
  element("register").disabled = busy || !token;
  element("authenticate").disabled = busy || !token;
  element("unlock").disabled = busy;
  element("cancel").disabled = !active || active.submitting;
}

function decode(value) {
  return Uint8Array.from(atob(value.replaceAll("-", "+").replaceAll("_", "/")), (c) => c.charCodeAt(0));
}

function encode(value) {
  return btoa(String.fromCharCode(...new Uint8Array(value))).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function api(body) {
  const response = await fetch("/api", {
    method: "POST", credentials: "omit", cache: "no-store", redirect: "error",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${token}` },
    body: JSON.stringify(body), signal: AbortSignal.timeout(7000),
  });
  if (!response.ok) {
    // Only local, allowlisted messages reach the UI. Never reflect response text.
    const messages = new Map([
      ["already_registered", "This server already has a passkey. Select Verify passkey, or restart the server to test a new registration."],
      ["not_registered", "Register a test passkey in this server session before verifying."],
      ["ceremony_pending", "Another ceremony is pending. Cancel its prompt or wait 120 seconds before starting again."],
      ["missing_or_expired_ceremony", "This ceremony was completed, cancelled, or expired. Start a new verification."],
    ]);
    let code;
    try { code = (await response.json())?.error; } catch { /* Empty or non-JSON rejection. */ }
    const message = response.status === 409 && typeof code === "string" ? messages.get(code) : undefined;
    throw new Error(message || `Request rejected (${response.status}). Check the server session and token; no success was confirmed.`);
  }
  return response.json();
}

element("unlock").addEventListener("click", () => {
  const candidate = element("token").value.trim();
  element("token").value = "";
  if (!/^[a-f0-9]{64}$/.test(candidate)) {
    element("status").textContent = "Paste the 64-character token printed by this server.";
    return;
  }
  token = candidate;
  element("status").textContent = "Token loaded locally. Register a test passkey, or verify an existing enrollment in this server session.";
  controls();
});

async function ceremony(register) {
  busy = true;
  controls();
  let current;
  try {
    const start = await api({ operation: register ? "register" : "authenticate" });
    current = { id: start.id, controller: new AbortController(), submitting: false };
    active = current;
    controls();
    const options = start.options.publicKey;
    options.challenge = decode(options.challenge);
    options.timeout = 120000;
    if (register) options.user.id = decode(options.user.id);
    for (const item of options.excludeCredentials || options.allowCredentials || []) item.id = decode(item.id);
    element("status").textContent = "Complete the platform prompt. No GitHub action will be performed.";
    const credential = register
      ? await navigator.credentials.create({ publicKey: options, signal: current.controller.signal })
      : await navigator.credentials.get({ publicKey: options, signal: current.controller.signal });
    if (!credential || current.controller.signal.aborted) throw new Error("Ceremony cancelled.");
    current.submitting = true;
    controls();
    element("status").textContent = "Submitting verification. Cancellation is no longer available.";
    const response = { clientDataJSON: encode(credential.response.clientDataJSON) };
    if (register) {
      response.attestationObject = encode(credential.response.attestationObject);
      response.transports = credential.response.getTransports?.() || [];
    } else {
      response.authenticatorData = encode(credential.response.authenticatorData);
      response.signature = encode(credential.response.signature);
      response.userHandle = credential.response.userHandle ? encode(credential.response.userHandle) : null;
    }
    await api({ operation: register ? "finish_registration" : "finish_authentication", id: current.id,
      credential: { id: credential.id, rawId: encode(credential.rawId), type: credential.type, response, extensions: credential.getClientExtensionResults() } });
    element("status").textContent = register ? "Test passkey registered. Now select Verify passkey." : "Verified: user verification was present. This is not a Human Mandate or proof of biometric identity.";
  } catch (error) {
    // Never display raw assertion data or untrusted server error bodies.
    element("status").textContent = error instanceof DOMException ? `Platform ceremony stopped (${error.name}).` : error.message;
  } finally {
    if (current) {
      try { await api({ operation: "cancel", id: current.id }); } catch { /* Consumed, expired, or temporarily unavailable. */ }
    }
    active = null;
    busy = false;
    controls();
  }
}

element("register").addEventListener("click", () => ceremony(true));
element("authenticate").addEventListener("click", () => ceremony(false));
element("cancel").addEventListener("click", () => {
  if (active && !active.submitting) active.controller.abort();
});
if (!window.isSecureContext || !window.PublicKeyCredential) {
  element("unlock").disabled = true;
  element("status").textContent = "WebAuthn is unavailable. Use a supported browser at http://localhost:8374.";
}
