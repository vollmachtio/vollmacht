// Signed client-data syntax policy only, not WebAuthn verification. Retain and
// verify original evidence; never replace it with a parsed/serialized value.
import { visit } from 'jsonc-parser';

const reject = () => { throw new Error('client_data_rejected'); };

export function validateClientData(bytes) {
  try {
    if (!(bytes instanceof Uint8Array) || bytes.length < 1 || bytes.length > 12_288) reject();
    // ignoreBOM preserves a leading BOM so it can be rejected explicitly.
    const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    if (text.startsWith('\uFEFF')) reject();
    const stack = [];
    let rootSeen = false;
    const string = value => { if (!value.isWellFormed()) reject(); };
    const begin = kind => {
      if (stack.length === 0) {
        if (rootSeen || kind !== 'object') reject();
        rootSeen = true;
      }
      if (stack.length >= 16) reject();
      stack.push({ kind, names: kind === 'object' ? new Set() : undefined });
    };
    const end = kind => { if (stack.pop()?.kind !== kind) reject(); };
    visit(text, {
      onObjectBegin: () => begin('object'),
      onObjectEnd: () => end('object'),
      onArrayBegin: () => begin('array'),
      onArrayEnd: () => end('array'),
      onObjectProperty: name => {
        string(name);
        const current = stack.at(-1);
        if (current?.kind !== 'object' || current.names.has(name)) reject();
        current.names.add(name);
      },
      onLiteralValue: value => {
        if (stack.length === 0) reject();
        if (typeof value === 'string') string(value);
        if (typeof value === 'number' && !Number.isFinite(value)) reject();
      },
      // The library is fault tolerant by design. Throw, do not recover or
      // return false (which only suppresses callbacks in this visitor API).
      onError: reject,
      onComment: reject,
    }, { disallowComments: true, allowTrailingComma: false, allowEmptyContent: false });
    if (!rootSeen || stack.length !== 0) reject();
  } catch {
    // Do not expose parser diagnostics, decoded keys, or original evidence.
    reject();
  }
}
