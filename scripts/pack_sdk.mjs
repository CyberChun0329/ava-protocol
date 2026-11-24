import { execFileSync } from 'node:child_process';
import { cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, renameSync, rmSync } from 'node:fs';
import { basename, resolve, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildRuntime } from './build_runtime.mjs';
import {assertArtifactCapacity} from './test-artifacts.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
await assertArtifactCapacity(root);
const destination = resolve(root, '.local/sdk-artifacts');
const packages = ['ava-sdk', 'ava-agent-sdk', 'ava-service'];
const expected = ['ava-protocol-sdk-0.1.0.tgz', 'ava-protocol-agent-sdk-0.1.0.tgz',
  'ava-protocol-local-service-0.1.0.tgz', 'ava-protocol-contracts-0.1.0.tgz'];
mkdirSync(resolve(root, '.local'), { recursive: true });
if (existsSync(destination)) {
  const files = readdirSync(destination);
  if (![2, 3, 4].includes(files.length) || !expected.slice(0, 2).every(file => files.includes(file))
      || files.some(file => !expected.includes(file))) {
    throw new Error('Preserve unexpected files in the SDK artifact directory before replacing the generated set');
  }
}
const staging = mkdtempSync(resolve(root, '.local/sdk-artifacts-stage-'));
const previous = `${staging}-previous`;
try {
  const build = await buildRuntime(root);
  console.log(`Runtime ${build.status}: ${build.inputHash}`);
  for (const name of packages) {
    const result = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', staging], {
      cwd: resolve(root, 'packages', name), encoding: 'utf8',
      env: { ...process.env, npm_config_cache: resolve(root, '.tmp/npm-cache') },
    }));
    console.log(JSON.stringify(result.map(({ filename, size, integrity }) => ({ filename, size, integrity }))));
  }
  // Stage the current canonical sources rather than maintain a second checked-in copy.
  const contracts = resolve(staging, 'contracts');
  cpSync(resolve(root, 'packages/ava-contracts'), contracts, { recursive: true });
  const sources = resolve(root, 'src');
  cpSync(sources, resolve(contracts, 'src'), { recursive: true,
    filter: path => {
      if (relative(sources, path).split(sep)[0] === 'apps') return false;
      const entry = lstatSync(path);
      if (entry.isSymbolicLink()) throw new Error('Contract source distribution must not contain symlinks');
      return entry.isDirectory() || path.endsWith('.sol') || ['LICENSE', 'NOTICE', 'README.md'].includes(basename(path));
    } });
  mkdirSync(resolve(contracts, 'script'));
  for (const name of ['DeployAVACore.s.sol', 'AVADefaultBindings.sol', 'AVADefaultPolicies.sol']) {
    cpSync(resolve(root, 'script', name), resolve(contracts, 'script', name));
  }
  const packed = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', staging], {
    cwd: contracts, encoding: 'utf8',
    env: { ...process.env, npm_config_cache: resolve(root, '.tmp/npm-cache') },
  }));
  console.log(JSON.stringify(packed.map(({ filename, size, integrity }) => ({ filename, size, integrity }))));
  rmSync(contracts, { recursive: true });
  if (readdirSync(staging).length !== expected.length || !expected.every(file => existsSync(resolve(staging, file)))) {
    throw new Error('Packaging did not produce the expected artifact set');
  }
  if (existsSync(destination)) renameSync(destination, previous);
  try { renameSync(staging, destination); }
  catch (error) { if (existsSync(previous)) renameSync(previous, destination); throw error; }
  rmSync(previous, { recursive: true, force: true });
} finally { rmSync(staging, { recursive: true, force: true }); }
