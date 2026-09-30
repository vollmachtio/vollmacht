import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request } from 'node:http';
import { once } from 'node:events';
import { Session } from './session.mjs';
import { makeServer } from './server.mjs';
import { authenticator } from './fixture.mjs';

async function enrolled(clock) {
  const session = new Session(clock);
  const device = authenticator();
  const start = await session.execute({ operation: 'register' });
  const credential = device.register(start.options.publicKey.challenge);
  assert.deepEqual(await session.execute({ operation: 'finish_registration', id: start.id, credential }), { registered: true });
  return { session, device, user: start.options.publicKey.user.id };
}

test('registration then bound assertion with enrolled user handle succeeds', async () => {
  const { session, device, user } = await enrolled();
  const start = await session.execute({ operation: 'authenticate' });
  const credential = device.assert(start.options.publicKey.challenge);
  credential.response.userHandle = user;
  assert.deepEqual(await session.execute({ operation: 'finish_authentication', id: start.id, credential }), { verified: true, simulated: true });
  await assert.rejects(session.execute({ operation: 'finish_authentication', id: start.id, credential }), /missing_or_expired/);
  await assert.rejects(session.execute({ operation: 'register' }), /already_registered/);
});

for (const [label, override] of [
  ['no UP', { flags: 68 }], ['no UV', { flags: 65 }],
  ['origin', { origin: 'http://localhost:9999' }], ['RP', { rpID: 'wrong.example' }],
  ['cross origin', { crossOrigin: true }],
]) test(`registration rejects ${label} and consumes state`, async () => {
  const session = new Session();
  const start = await session.execute({ operation: 'register' });
  const credential = authenticator().register(start.options.publicKey.challenge, override);
  await assert.rejects(session.execute({ operation: 'finish_registration', id: start.id, credential }));
  await assert.rejects(session.execute({ operation: 'finish_registration', id: start.id, credential }), /missing_or_expired/);
  await assert.rejects(session.execute({ operation: 'authenticate' }), /not_registered/);
  await session.execute({ operation: 'register' });
});

test('wrong user handle consumes an otherwise valid assertion', async () => {
  const { session, device } = await enrolled();
  const start = await session.execute({ operation: 'authenticate' });
  const credential = device.assert(start.options.publicKey.challenge);
  credential.response.userHandle = 'wrong';
  await assert.rejects(session.execute({ operation: 'finish_authentication', id: start.id, credential }), /wrong_user/);
});

test('nonzero credential counters advance and cannot regress', async () => {
  const { session, device } = await enrolled();
  for (const counter of [2, 1]) {
    const start = await session.execute({ operation: 'authenticate' });
    const credential = device.assert(start.options.publicKey.challenge, { counter });
    const finish = session.execute({ operation: 'finish_authentication', id: start.id, credential });
    if (counter === 2) assert.equal((await finish).verified, true);
    else await assert.rejects(finish);
  }
});

test('changed backup eligibility is rejected even with valid signature', async () => {
  const { session, device } = await enrolled();
  const start = await session.execute({ operation: 'authenticate' });
  const credential = device.assert(start.options.publicKey.challenge, { flags: 13 });
  await assert.rejects(session.execute({ operation: 'finish_authentication', id: start.id, credential }), /invalid_or_expired/);
});

test('expiry during asynchronous verification prevents enrollment or approval', async () => {
  for (const kind of ['register', 'authenticate']) {
    let now = 0;
    const { session, device } = kind === 'register'
      ? { session: new Session(() => now), device: authenticator() } : await enrolled(() => now);
    const start = await session.execute({ operation: kind });
    const credential = kind === 'register' ? device.register(start.options.publicKey.challenge) : device.assert(start.options.publicKey.challenge);
    const finish = session.execute({ operation: kind === 'register' ? 'finish_registration' : 'finish_authentication', id: start.id, credential });
    now = 120_000;
    await assert.rejects(finish, /invalid_or_expired/);
    if (kind === 'register') await assert.rejects(session.execute({ operation: 'authenticate' }), /not_registered/);
    await session.execute({ operation: kind });
  }
});

test('pending, stale cancellation and matching cancellation rules', async () => {
  const session = new Session();
  const start = await session.execute({ operation: 'register' });
  await assert.rejects(session.execute({ operation: 'register' }), /ceremony_pending/);
  await assert.rejects(session.execute({ operation: 'cancel', id: '0'.repeat(32) }), /missing_or_expired/);
  await assert.rejects(session.execute({ operation: 'register' }), /ceremony_pending/);
  assert.deepEqual(await session.execute({ operation: 'cancel', id: start.id }), { cancelled: true });
  await session.execute({ operation: 'register' });
});

test('wrong finish kind consumes matching registration', async () => {
  const session = new Session();
  const start = await session.execute({ operation: 'register' });
  await assert.rejects(session.execute({ operation: 'finish_authentication', id: start.id, credential: {} }), /bad_ceremony/);
  await session.execute({ operation: 'register' });
});

test('deadline boundary rejects registration and authentication, then permits restart', async () => {
  for (const kind of ['register', 'authenticate']) {
    let now = 0;
    const { session, device } = kind === 'register'
      ? { session: new Session(() => now), device: authenticator() } : await enrolled(() => now);
    const start = await session.execute({ operation: kind });
    const credential = kind === 'register' ? device.register(start.options.publicKey.challenge) : device.assert(start.options.publicKey.challenge);
    now = 120_000;
    await assert.rejects(session.execute({ operation: kind === 'register' ? 'finish_registration' : 'finish_authentication', id: start.id, credential }), /missing_or_expired/);
    await session.execute({ operation: kind });
  }
});

test('concurrent finish cannot enroll twice or start during verification', async () => {
  const session = new Session();
  const start = await session.execute({ operation: 'register' });
  const command = { operation: 'finish_registration', id: start.id, credential: authenticator().register(start.options.publicKey.challenge) };
  const results = await Promise.allSettled([session.execute(command), session.execute(command), session.execute({ operation: 'register' })]);
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
});

const TOKEN = 'a'.repeat(64);
async function running(t) {
  const server = makeServer(TOKEN);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise(resolve => { server.close(resolve); server.closeAllConnections(); }));
  return server.address().port;
}
function send(port, { body = '{"operation":"register"}', method = 'POST', path = '/api', headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = request({ hostname: '127.0.0.1', port, method, path, headers: {
      Host: 'localhost:8374', Origin: 'http://localhost:8374', 'Sec-Fetch-Site': 'same-origin',
      Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json', ...headers,
    } }, res => {
      let text = '';
      res.setEncoding('utf8');
      res.on('data', c => { text += c; });
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text }));
    });
    req.on('error', reject); req.end(body);
  });
}

test('HTTP denies origin/host/token/type/fetch-site and duplicate security headers', async t => {
  const port = await running(t);
  for (const headers of [
    { Host: 'evil.example' }, { Origin: 'null' }, { Origin: 'http://localhost:9999' },
    { Authorization: 'Bearer wrong' }, { 'Content-Type': 'text/plain' }, { 'Sec-Fetch-Site': 'same-site' },
    { Origin: ['http://localhost:8374', 'http://localhost:8374'] },
    { Authorization: [`Bearer ${TOKEN}`, `Bearer ${TOKEN}`] },
  ]) assert.ok((await send(port, { headers })).status >= 400);
  assert.equal((await send(port)).status, 200);
});

test('HTTP rejects malformed, duplicate, unknown, oversized and alternate routes', async t => {
  const port = await running(t);
  for (const body of ['{', '{"operation":"register","operation":"register"}', ' {"operation":"register"}',
    '{"operation":"register","extra":true}', '{"operation":"anything"}', 'null']) {
    assert.equal((await send(port, { body })).status, 400);
  }
  assert.equal((await send(port, { body: 'a'.repeat(65_537) })).status, 413);
  assert.equal((await send(port, { path: '/api?token=secret' })).status, 404);
  assert.equal((await send(port, { method: 'OPTIONS' })).status, 404);
});

test('static page contains exact simulation and security headers, never session token', async t => {
  const port = await running(t);
  for (const path of ['/', '/app.js', '/style.css']) {
    const response = await send(port, { method: 'GET', path, body: '' });
    assert.equal(response.status, 200);
    assert.equal(response.headers['cache-control'], 'no-store');
    assert.match(response.headers['content-security-policy'], /frame-ancestors 'none'/);
    assert.ok(!response.text.includes(TOKEN));
  }
});

test('HTTP browser-shaped enrollment and approval complete; replay is rejected', async t => {
  const port = await running(t);
  const api = async command => send(port, { body: JSON.stringify(command) });
  const device = authenticator();
  const registration = JSON.parse((await api({ operation: 'register' })).text);
  assert.equal((await api({ operation: 'finish_registration', id: registration.id,
    credential: device.register(registration.options.publicKey.challenge) })).status, 200);
  const start = JSON.parse((await api({ operation: 'authenticate' })).text);
  const credential = device.assert(start.options.publicKey.challenge);
  credential.extensions = credential.clientExtensionResults;
  delete credential.clientExtensionResults;
  credential.response.userHandle = registration.options.publicKey.user.id;
  const finish = { operation: 'finish_authentication', id: start.id, credential };
  assert.equal((await api(finish)).status, 200);
  assert.equal((await api(finish)).status, 409);
});
