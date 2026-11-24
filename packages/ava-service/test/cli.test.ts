import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';

const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url));
test('CLI distinguishes parent path components from a contained dot-prefixed configuration', async t => {
  const directory = await mkdtemp(resolve(tmpdir(), 'ava-cli-'));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const cwd = resolve(directory, 'consumer');
  await mkdir(resolve(cwd, '..config'), { recursive: true });
  const outside = resolve(directory, 'deployment.json');
  const inside = resolve(cwd, '..config/deployment.json');
  // Stop at the next public configuration check, before any token or RPC access.
  for (const path of [outside, inside]) await writeFile(path, JSON.stringify({ startBlock: -1 }));
  const invoke = (file: string) => spawnSync(process.execPath,
    ['--import', import.meta.resolve('tsx'), cli, file], { cwd, encoding: 'utf8' });
  const denied = invoke(outside);
  assert.notEqual(denied.status, 0);
  assert.match(denied.stderr, /Configuration must be inside this project/);
  const accepted = invoke('..config/deployment.json');
  assert.notEqual(accepted.status, 0);
  assert.match(accepted.stderr, /startBlock must be a nonnegative decimal string/);
  assert.doesNotMatch(accepted.stderr, /Configuration must be inside this project/);
});
