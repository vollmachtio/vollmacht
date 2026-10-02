// Developer observation, not a benchmark gate or a hardware ceremony.
import { makeRunner } from './helper-runner.mjs';

try {
  if (process.argv.length !== 4) throw new Error();
  const run = makeRunner(process.argv[2], process.argv[3]);
  const samples = [];
  for (let i = 0; i < 21; i++) {
    const start = performance.now();
    if (await run() !== 'verified') throw new Error();
    samples.push(performance.now() - start);
  }
  const first = samples.shift();
  const sorted = [...samples].sort((a, b) => a - b);
  const ms = value => Number(value.toFixed(3));
  console.log(JSON.stringify({
    scope: 'Rust driver startup, synthetic key/assertion generation, launcher, Node import and verification, cleanup',
    first_process_ms: ms(first),
    subsequent_process_ms: { count: samples.length, min: ms(sorted[0]),
      median: ms((sorted[9] + sorted[10]) / 2), p95_nearest_rank: ms(sorted[18]), max: ms(sorted[19]) },
    samples_ms: samples.map(ms),
    filesystem_cache: 'uncontrolled; fresh processes do not imply cold filesystem cache',
  }));
} catch {
  console.error('helper_measure_failed');
  process.exitCode = 1;
}
