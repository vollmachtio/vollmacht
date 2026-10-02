import test from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { strictJSON, parseRequest, readFrame, frame } from './helper-protocol.mjs';
import { verifyRequest } from './helper.mjs';
import { fixture } from './helper-fixture.mjs';

const challenge = Buffer.alloc(32).toString('base64url'), id = '000102030405060708090a0b0c0d0e0f';
const encode = object => Buffer.from(JSON.stringify(object));
const fresh = () => fixture(challenge,id).request;

test('strict profile rejects ambiguity before normalization', () => {
  for (const body of ['{"x":1,"x":2}','{"x":1,"\\u0078":2}','{"a":{"x":1,"x":2}}',
    '-0','-1','1.0','1e0','01','null','[]','"é"','"\\ud800"','{}{}','\ufeff{}','{"a":1,}',
    '{"a":truefalse}', '18446744073709551616']) assert.throws(() => strictJSON(Buffer.from(body)),body);
  assert.throws(() => strictJSON(Buffer.from([255])));
  for (let depth=1;depth<=9;depth++) {
    const bytes = Buffer.from('{"a":'.repeat(depth)+'0'+'}'.repeat(depth));
    if (depth<=8) strictJSON(bytes); else assert.throws(() => strictJSON(bytes));
  }
  const request = fresh();
  assert.equal(parseRequest(Buffer.from(JSON.stringify(request,null,2))).challenge,challenge);
});

test('request schema rejects missing, unknown, wrong typed fields', () => {
  const request = fresh();
  for (const section of [null,'credential','assertion']) {
    const object = section ? request[section] : request;
    for (const key of Object.keys(object)) {
      const removed = structuredClone(request);
      delete (section ? removed[section] : removed)[key];
      assert.throws(() => parseRequest(encode(removed)));
      for (const replacement of [null,{},[]]) {
        const invalid = structuredClone(request);
        (section ? invalid[section] : invalid)[key] = replacement;
        assert.throws(() => parseRequest(encode(invalid)));
      }
    }
    const invalid = structuredClone(request);
    (section ? invalid[section] : invalid).extra = true;
    assert.throws(() => parseRequest(encode(invalid)));
  }
});

test('binary and integer bounds reject noncanonical encodings', () => {
  for (const suffix of ['\n','\r','\r\n',' ']) {
    const request = fresh(); request.request_id += suffix;
    assert.throws(() => parseRequest(encode(request)));
  }
  for (const invalid of ['A','AA=','AA==','AB','+A','/A','A A']) {
    const request = fresh(); request.assertion.signature = invalid;
    assert.throws(() => parseRequest(encode(request)));
  }
  for (const counter of [-1,0.5,4294967296]) {
    const request=fresh(); request.credential.counter=counter;
    assert.throws(() => parseRequest(encode(request)));
  }
  const request=fresh(); request.assertion.client_data_json=Buffer.alloc(12289).toString('base64url');
  assert.throws(() => parseRequest(encode(request)));
});

test('single-frame transport handles splits, rejects truncation and surplus', async () => {
  const bytes=frame(encode(fresh()));
  for (const size of [1,2,3,4,17,bytes.length]) {
    const parts=[]; for(let at=0;at<bytes.length;at+=size) parts.push(bytes.subarray(at,at+size));
    assert.deepEqual(await readFrame(Readable.from(parts)),bytes.subarray(4));
  }
  for (const invalid of [Buffer.alloc(4),Buffer.from([0,1,0,1]),bytes.subarray(0,-1),
    Buffer.concat([bytes,Buffer.from([0])]),Buffer.concat([bytes,bytes])]) {
    await assert.rejects(readFrame(Readable.from([invalid])));
  }
});

test('valid ES256 retains exact signed bytes and supplied challenge', async () => {
  const request=fixture(challenge,id,{pretty:true,counter:1}).request;
  const result=await verifyRequest(parseRequest(encode(request)));
  assert.equal(result.outcome,'verified'); assert.equal(result.challenge,challenge); assert.equal(result.new_counter,1);
});

const cases = [
  ['wrong origin',{origin:'https://example.com'}], ['wrong RP',{rpID:'example.com'}],
  ['missing UP',{flags:4}], ['missing UV',{flags:1}], ['wrong type',{type:'webauthn.create'}],
  ['cross origin',{crossOrigin:true}], ['changed backup eligibility',{flags:13}],
  ['top origin',{topOrigin:'http://localhost:8374'}],
  ['invalid backup flags',{flags:21}],
];
for (const [name,options] of cases) test(name,async()=>{
  assert.equal((await verifyRequest(parseRequest(encode(fixture(challenge,id,options).request)))).outcome,'rejected');
});

test('credential, signature, user handle, key and counter substitutions reject',async()=>{
  const mutations=[
    r=>{r.assertion.id='AA';}, r=>{r.assertion.raw_id='AA';}, r=>{r.assertion.user_handle='AQ';},
    r=>{r.assertion.signature=Buffer.alloc(70).toString('base64url');},
    r=>{r.credential.public_key=fresh().credential.public_key;},
    r=>{r.credential.public_key='AA';}, r=>{r.credential.counter=1;},
    r=>{const key=Buffer.from(r.credential.public_key,'base64url');key[2]=3;r.credential.public_key=key.toString('base64url');},
    r=>{const key=Buffer.from(r.credential.public_key,'base64url');key[4]=0x27;r.credential.public_key=key.toString('base64url');},
    r=>{const key=Buffer.from(r.credential.public_key,'base64url');key[6]=2;r.credential.public_key=key.toString('base64url');},
    r=>{r.challenge=Buffer.alloc(32,1).toString('base64url');},
  ];
  for(const mutate of mutations){const r=fresh();mutate(r);assert.equal((await verifyRequest(parseRequest(encode(r)))).outcome,'rejected');}
});

test('every binary field enforces exact decoded size bounds', () => {
  for (const [section, key, min, max] of [
    [null,'challenge',32,32], ['credential','id',1,1024], ['credential','public_key',1,4096],
    ['credential','user_handle',1,64], ['assertion','id',1,1024], ['assertion','raw_id',1,1024],
    ['assertion','client_data_json',1,12288], ['assertion','authenticator_data',37,8192],
    ['assertion','signature',1,1024], ['assertion','user_handle',0,64],
  ]) {
    for (const size of [min - 1, min, max, max + 1].filter(n => n >= 0)) {
      const request = fresh();
      (section ? request[section] : request)[key] = Buffer.alloc(size).toString('base64url');
      if (size >= min && size <= max) parseRequest(encode(request));
      else assert.throws(() => parseRequest(encode(request)));
    }
  }
});

test('escaped strings round trip without prototype or delimiter confusion', () => {
  for (const key of ['__proto__','constructor','a"b','a\\b','\n',String.fromCharCode(0)]) {
    const input = Object.create(null);
    input[key] = `${key}:,{}[]`;
    const parsed = strictJSON(encode(input));
    assert.equal(Object.getPrototypeOf(parsed), null);
    assert.equal(parsed[key], input[key]);
  }
});

test('malformed envelope exits without a response',async()=>{
  const child=spawn(process.execPath,[fileURLToPath(new URL('./helper.mjs',import.meta.url))],{timeout:3000,env:{}});
  const out=[];child.stdout.on('data',b=>out.push(b));child.stderr.resume();
  child.stdin.on('error',()=>{});child.stdin.end(frame(Buffer.from('{"version":1,"version":1}')));
  const code=await new Promise((resolve,reject)=>{child.on('error',reject);child.on('close',resolve);});
  assert.notEqual(code,0);assert.equal(Buffer.concat(out).length,0);
});
