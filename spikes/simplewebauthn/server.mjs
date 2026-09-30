import { createServer } from 'node:http';
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { Session, OPERATION } from './session.mjs';

const HEADERS = {
  'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
  'Content-Security-Policy': "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
  'Permissions-Policy': 'publickey-credentials-create=(self), publickey-credentials-get=(self)',
};
const page = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Vollmacht binding experiment</title><link rel="stylesheet" href="/style.css"><script src="/app.js" defer></script></head><body><main>
<h1>Passkey operation-binding experiment</h1>
<p>Experimental, local and in-memory. No GitHub connection or real merge. This is not a Human Mandate.</p>
<h2>Exact fixed test operation</h2><pre>${OPERATION}</pre>
<p>“Approve” tests a fingerprint binding these exact bytes and fresh server randomness. It does not prove you read this page.</p>
<label for="token">Session token from your terminal</label><input id="token" type="password" autocomplete="off" maxlength="64"><button id="unlock">Use token</button>
<p><button id="register" disabled>1. Register test passkey</button><button id="authenticate" disabled>2. Verify passkey (approve fixed test request)</button><button id="cancel" disabled>Cancel pending ceremony</button></p>
<p id="status" role="status" aria-live="polite">Paste the terminal token. Reloading forgets it.</p>
<p>120-second expiry. Touch ID may be offered; this verifies user verification, not biometric identity. Restarting forgets enrollment. Afterwards remove only the <strong>vollmacht-binding-spike</strong> localhost credential from your passkey provider.</p>
</main></body></html>`;
const assets = new Map([
  ['/', ['text/html; charset=utf-8', page]],
  ['/app.js', ['text/javascript; charset=utf-8', readFileSync(new URL('../webauthn/web/app.js', import.meta.url))]],
  ['/style.css', ['text/css; charset=utf-8', readFileSync(new URL('../webauthn/web/style.css', import.meta.url))]],
]);
function single(req, key) {
  const values = [];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    if (req.rawHeaders[i].toLowerCase() === key) values.push(req.rawHeaders[i + 1]);
  }
  return values.length === 1 ? values[0] : undefined;
}

export function makeServer(token, session = new Session()) {
  if (!/^[a-f0-9]{64}$/.test(token)) throw new Error('invalid_token');
  const expected = Buffer.from(`Bearer ${token}`);
  const server = createServer({ maxHeaderSize: 8192, requestTimeout: 5000, headersTimeout: 5000, connectionsCheckingInterval: 1000 }, async (req, res) => {
    const send = (status, data, type = 'application/json') => {
      res.writeHead(status, { ...HEADERS, 'Content-Type': type, Connection: 'close' });
      res.end(typeof data === 'string' || Buffer.isBuffer(data) ? data : JSON.stringify(data));
    };
    const reject = (status = 400) => send(status, { error: 'request_rejected' });
    const timer = setTimeout(() => req.destroy(), 5000);
    timer.unref();
    try {
      if (single(req, 'host') !== 'localhost:8374') return reject();
      if (req.method === 'GET' && assets.has(req.url)) {
        const [type, body] = assets.get(req.url);
        return send(200, body, type);
      }
      if (req.method !== 'POST' || req.url !== '/api') return reject(404);
      const auth = Buffer.from(single(req, 'authorization') || '');
      if (single(req, 'origin') !== 'http://localhost:8374'
          || single(req, 'sec-fetch-site') !== 'same-origin'
          || single(req, 'content-type') !== 'application/json'
          || auth.length !== expected.length || !timingSafeEqual(auth, expected)) return reject(403);
      let size = 0;
      const chunks = [];
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 65_536) { reject(413); return; }
        chunks.push(chunk);
      }
      const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
      const command = JSON.parse(text);
      // Narrow browser transport: exact JSON.stringify output rejects duplicate keys,
      // alternate encodings and whitespace. This is NOT JCS canonicalization.
      if (JSON.stringify(command) !== text) return reject();
      try { send(200, await session.execute(command)); }
      catch (error) {
        const known = new Set(['already_registered', 'not_registered', 'ceremony_pending', 'missing_or_expired_ceremony']);
        send(known.has(error.message) ? 409 : 400, { error: known.has(error.message) ? error.message : 'verification_rejected' });
      }
    } catch { if (!res.headersSent && !res.destroyed) reject(); }
    finally { clearTimeout(timer); }
  });
  server.maxConnections = 16;
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 2) { console.error('Usage: npm run browser'); process.exitCode = 2; }
  else {
    const token = randomBytes(32).toString('hex');
    const server = makeServer(token);
    server.on('error', () => { console.error('Cannot bind localhost probe. Stop the previous probe and retry.'); process.exitCode = 1; });
    server.listen(8374, '127.0.0.1', () => console.log(`Open http://localhost:8374\nSession token: ${token}\nSimulation only. Ctrl+C forgets enrollment.`));
  }
}
