// Metadata policy, not a substitute for reviewing package contents or advisories.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

export function checkLock(lock) {
  assert.equal(lock.lockfileVersion, 3);
  assert.ok(lock.packages && Object.keys(lock.packages).length > 1);
  const licenses = new Set(['MIT', 'Apache-2.0', 'BSD-3-Clause', '0BSD']);
  for (const [path, pkg] of Object.entries(lock.packages)) {
    if (path === '') continue;
    assert.ok(path.startsWith('node_modules/'), 'unexpected package location');
    assert.ok(!pkg.link && !pkg.hasInstallScript, 'links/install scripts require review');
    const source = new URL(pkg.resolved);
    assert.equal(source.origin, 'https://registry.npmjs.org');
    assert.equal(source.username + source.password + source.search + source.hash, '');
    assert.match(pkg.integrity, /^sha512-[A-Za-z0-9+/]{86}==$/);
    assert.ok(licenses.has(pkg.license), 'license requires review');
  }
}

const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)));
checkLock(lock);
// Exercise fail-closed rules without fetching or executing any dependency.
const path = Object.keys(lock.packages).find(path => path !== '');
for (const patch of [
  { resolved: 'https://example.com/package.tgz' }, { integrity: 'sha1-invalid' },
  { license: 'UNLICENSED' }, { hasInstallScript: true }, { link: true },
]) {
  const changed = structuredClone(lock);
  Object.assign(changed.packages[path], patch);
  assert.throws(() => checkLock(changed));
}
console.log('Lockfile source, integrity, license and lifecycle checks passed (5 negative controls).');
