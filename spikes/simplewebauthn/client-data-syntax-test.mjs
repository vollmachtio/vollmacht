import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { validateClientData } from './client-data-syntax.mjs';

const accept = input => assert.equal(validateClientData(Buffer.from(input)), undefined);
const reject = input => assert.throws(() => validateClientData(Buffer.from(input)), {
  name: 'Error', message: 'client_data_rejected',
});

test('shared 24-vector oracle fixes policy independently of the Node parser', () => {
  const corpus = JSON.parse(readFileSync(new URL('./client-data-vectors.json', import.meta.url)));
  assert.equal(corpus.profile, 'candidate-client-data-syntax-v1');
  assert.equal(corpus.vectors.length, 24);
  const ids = new Set();
  for (const vector of corpus.vectors) {
    assert(!ids.has(vector.id));
    ids.add(vector.id);
    const bytes = Buffer.from(vector.raw_base64url, 'base64url');
    assert.equal(bytes.toString('base64url'), vector.raw_base64url);
    assert(['accept', 'reject'].includes(vector.expected_gate));
    if (vector.expected_gate === 'accept') accept(bytes);
    else reject(bytes);
  }
});

test('valid input is unchanged and no semantic value is returned', () => {
  const original = Buffer.from(' \t{"z":-0.0,"é":"\\ud83d\\ude00","a":[null,true,1E+2]}\r\n');
  const copy = Buffer.from(original);
  accept(original);
  assert.deepEqual(original, copy);
  const view = new Uint8Array(original.buffer, original.byteOffset, original.byteLength);
  assert.equal(validateClientData(view), undefined);
  assert.deepEqual(original, copy);
  for (const text of ['{}', '{"type":null,"challenge":7,"origin":false}', '{"__proto__":{},"constructor":[],"prototype":null}']) accept(text);
});

test('root framing and permissive JSON extensions reject', () => {
  for (const input of ['', ' ', 'null', 'true', '1', '"x"', '[]', '{}{}', '{}x', '{', '{"x":1,}', '{"x":[1,]}', '{/*comment*/}', '{}//comment', '{"x":undefined}', '{x:1}']) reject(input);
  accept(' \r\n\t{} \n');
});

test('decoded duplicate names reject at every depth and inside arrays', () => {
  for (const duplicate of ['{"challenge":1,"\\u0063hallenge":2}', '{"😀":1,"\\ud83d\\ude00":2}', '{"":1,"":2}', '{"__proto__":1,"__proto__":2}']) {
    for (let depth = 1; depth <= 16; depth++) reject('{"x":'.repeat(depth - 1) + duplicate + '}'.repeat(depth - 1));
    reject(`{"x":[${duplicate}]}`);
  }
  accept('{"left":{"x":1},"right":{"x":2}}');
  accept('{"é":1,"e\\u0301":2}');
});

test('container limit counts root, arrays, objects and empty containers', () => {
  for (let depth = 1; depth <= 18; depth++) {
    const check = depth <= 16 ? accept : reject;
    check('{"x":'.repeat(depth) + '0' + '}'.repeat(depth));
    if (depth > 1) for (const scalar of ['', 'null', '"x"']) check('{"x":' + '['.repeat(depth - 1) + scalar + ']'.repeat(depth - 1) + '}');
  }
});

test('raw byte bound includes whitespace and multibyte characters', () => {
  for (const size of [12_287, 12_288, 12_289]) {
    const check = size <= 12_288 ? accept : reject;
    check('{"x":"' + 'a'.repeat(size - 8) + '"}');
    check(' '.repeat(size - 2) + '{}');
  }
  const multibyte = '{"x":"' + 'é'.repeat(6140) + '"}';
  assert.equal(Buffer.byteLength(multibyte), 12_288);
  accept(multibyte);
  reject(multibyte + ' ');
});

test('fatal UTF8, BOM and unpaired surrogates reject without normalization', () => {
  for (const invalid of [[0xff], [0xc0, 0xaf], [0xed, 0xa0, 0x80], [0xf4, 0x90, 0x80, 0x80], [0xe2, 0x82]]) reject(Buffer.concat([Buffer.from('{"x":"'), Buffer.from(invalid), Buffer.from('"}') ]));
  for (const text of ['\ufeff{}', ' \ufeff{}', '{"x":"\\ud800"}', '{"\\udc00":1}', '{"x":"\\ud800a"}', '{"x":"\\ud800\\ud800"}', '{"x":"\\x20"}', '{"x":"\\u12"}', '{"x":"\n"}', '{"x":"\0"}']) reject(text);
  for (const text of ['{"x":"\\ud83d\\ude00"}', '{"\\ud83d\\ude00":"😀"}', '{"x":"\\u0000\\ufeff"}', '{"日本語":"é😀"}']) accept(text);
});

test('finite number forms preserve the broader signed-data policy', () => {
  for (const number of ['-1', '-0', '-0.0', '1.0', '1e0', '1E+2', '1e-2', '9007199254740993', '18446744073709551615', '1e308']) accept(`{"extension":${number}}`);
  for (const number of ['1e400', '-1e400', 'NaN', 'Infinity', '+1', '01', '1.', '.1', '1e']) reject(`{"extension":${number}}`);
});

test('invalid API inputs fail with a bounded error', () => {
  for (const input of [null, undefined, '{}', {}, [], new ArrayBuffer(2), 7]) assert.throws(() => validateClientData(input), { name: 'Error', message: 'client_data_rejected' });
});
