import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { cp, lstat, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { performance } from 'node:perf_hooks';

export const currentPreviewRelease = '0.1.0-preview.12';
const names = ['contracts', 'sdk', 'agent-sdk', 'local-service'];
const json = value => JSON.stringify(value, null, 2) + '\n';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const pathOK = path => typeof path === 'string' && path.length > 0 && !path.startsWith('/')
  && !path.includes('\\') && !/[\x00-\x1f\x7f]/.test(path) && path.split('/').every(part => part !== '' && part !== '.' && part !== '..');

async function inventory(root, directory = root) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = resolve(directory, entry.name), name = relative(root, path).split(sep).join('/');
    assert(pathOK(name), `Invalid payload path: ${name}`);
    assert(!entry.isSymbolicLink(), `Symlink is not allowed: ${name}`);
    if (entry.isDirectory()) result.push(...await inventory(root, path));
    else { assert(entry.isFile(), `Non-file payload: ${name}`); result.push(name); }
  }
  return result;
}

function archiveEntries(path) {
  const options = { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 };
  const names = execFileSync('tar', ['-tzf', path], options).trimEnd().split('\n');
  const listing = execFileSync('tar', ['-tvzf', path], options).trimEnd().split('\n');
  assert.equal(names.length, listing.length, 'Archive listing mismatch');
  const seen = new Set();
  for (let i = 0; i < names.length; i++) {
    const name = names[i].replace(/\/$/, '');
    assert(pathOK(name) && (name === 'package' || name.startsWith('package/')), `Unsafe archive member: ${name}`);
    assert(!seen.has(name), `Duplicate archive member: ${name}`); seen.add(name);
    assert(['-', 'd'].includes(listing[i][0]), `Archive link or special member: ${name}`);
  }
  assert(seen.has('package/package.json'), 'Archive package.json missing');
  return names.filter(name => !name.endsWith('/'));
}

/** Check a complete bundle before installing any of its contents. Hashes provide integrity, not publisher authentication. */
export async function verifyPreview(directory) {
  const root = resolve(directory);
  assert((await lstat(root)).isDirectory() && !(await lstat(root)).isSymbolicLink(), 'Preview must be a real directory');
  const manifest = JSON.parse(await readFile(resolve(root, 'manifest.json'), 'utf8'));
  assert(isObject(manifest) && manifest.schemaVersion === 1
    && ['0.1.0-preview.9', '0.1.0-preview.10', '0.1.0-preview.11', currentPreviewRelease].includes(manifest.release)
    && manifest.status === 'developer-preview' && isObject(manifest.components)
    && isObject(manifest.compatibility) && isObject(manifest.files), 'Invalid preview manifest');
  const { release } = manifest;
  assert.deepEqual(Object.keys(manifest.components).sort(), [...names].sort(), 'Expected exactly four components');
  const payload = await inventory(root);
  assert.deepEqual(payload.filter(path => path !== 'manifest.json').sort(), Object.keys(manifest.files).sort(),
    'Missing or unlisted preview payload');
  for (const [path, expected] of Object.entries(manifest.files)) {
    assert(pathOK(path) && path !== 'manifest.json' && /^[a-f0-9]{64}$/.test(expected), `Invalid payload entry: ${path}`);
    assert.equal(hash(await readFile(resolve(root, path))), expected, `Payload hash mismatch: ${path}`);
  }
  for (const required of ['README.md', 'verify.mjs', 'work-order/package.json', 'work-order/package-lock.json']) {
    assert(Object.hasOwn(manifest.files, required), `Missing preview file: ${required}`);
  }
  const fixtureRoot = resolve(root, 'work-order');
  for (const name of Object.keys(manifest.files).filter(path => path.startsWith('work-order/') && /\.(?:ts|mjs|sol)$/.test(path))) {
    const source = await readFile(resolve(root, name), 'utf8');
    for (const match of source.matchAll(/(?:\bfrom\s+|\bimport\s*\(?\s*|\brequire\s*\(\s*)['"]([^'"]+)['"]/g)) {
      const specifier = match[1];
      if (specifier.startsWith('.')) {
        const target = resolve(dirname(resolve(root, name)), specifier);
        assert(target.startsWith(fixtureRoot + sep), `Fixture import escapes its project: ${name}`);
      } else {
        assert(specifier.startsWith('node:') || specifier === 'viem' || specifier === 'viem/accounts'
          || specifier === 'viem/chains' || specifier === '@ava-protocol/sdk'
          || specifier === '@ava-protocol/sdk/deployment' || specifier === '@ava-protocol/sdk/costs'
          || specifier === '@ava-protocol/agent-sdk' || specifier === '@ava-protocol/local-service/server'
          || (specifier.startsWith('@ava-protocol/contracts/') && pathOK(specifier)), `Unexpected fixture import: ${specifier}`);
      }
    }
  }
  const archiveFiles = {};
  for (const name of names) {
    const item = manifest.components[name], packageName = `@ava-protocol/${name}`;
    const expectedRequires = name === 'agent-sdk' || name === 'local-service' ? { '@ava-protocol/sdk': release } : {};
    assert(isObject(item) && item.name === packageName && item.version === release && item.sourceVersion === '0.1.0'
      && pathOK(item.archive) && item.archive.startsWith('artifacts/')
      && item.archive === `artifacts/ava-protocol-${name}-${release}.tgz`
      && item.sha256 === manifest.files[item.archive], `Invalid component: ${name}`);
    assert.deepEqual(item.requires, expectedRequires, `Incompatible component requirements: ${name}`);
    const path = resolve(root, item.archive); archiveFiles[name] = archiveEntries(path);
    const pkg = JSON.parse(execFileSync('tar', ['-xOzf', path, 'package/package.json'], { encoding: 'utf8', maxBuffer: 1024 * 1024 }));
    assert.equal(pkg.name, packageName); assert.equal(pkg.version, release);
    if (Object.keys(expectedRequires).length) assert.equal(pkg.dependencies?.['@ava-protocol/sdk'], release);
    else assert.equal(pkg.dependencies?.['@ava-protocol/sdk'], undefined);
  }
  const project = JSON.parse(await readFile(resolve(root, 'work-order/package.json'), 'utf8'));
  const lock = JSON.parse(await readFile(resolve(root, 'work-order/package-lock.json'), 'utf8'));
  assert(isObject(project) && project.private === true && isObject(project.dependencies)
    && lock.lockfileVersion === 3 && isObject(lock.packages) && isObject(lock.packages['']), 'Invalid consumer lock');
  for (const item of Object.values(lock.packages)) {
    assert(isObject(item) && !item.link, 'Workspace or symlink lock entry');
    if (typeof item.resolved === 'string' && item.resolved.startsWith('file:')) {
      assert(names.some(name => item.resolved === `file:${manifest.components[name].archive}`), 'Unexpected local lock dependency');
    }
  }
  for (const name of names) {
    const component = manifest.components[name], spec = `file:${component.archive}`;
    const locked = lock.packages[`node_modules/${component.name}`];
    const bytes = await readFile(resolve(root, component.archive));
    assert.equal(project.dependencies[component.name], spec, `Wrong consumer dependency: ${name}`);
    assert.equal(lock.packages[''].dependencies?.[component.name], spec, `Wrong consumer root lock: ${name}`);
    assert(isObject(locked) && locked.version === release && locked.resolved === spec
      && locked.integrity === `sha512-${createHash('sha512').update(bytes).digest('base64')}`, `Wrong locked component: ${name}`);
    for (const [path, entry] of Object.entries(lock.packages)) {
      if (path.endsWith(`/node_modules/${component.name}`)) {
        assert(entry.version === release && entry.resolved === spec && entry.integrity === locked.integrity,
          `Conflicting nested component: ${name}`);
      }
    }
  }
  return { root, manifest, archiveFiles };
}

function commandPath(name) {
  return execFileSync('which', [name], { encoding: 'utf8' }).trim();
}
async function selectedSolc() {
  const candidates = [process.env.AVA_PREVIEW_SOLC, resolve(homedir(), '.svm/0.8.26/solc-0.8.26'),
    resolve(homedir(), 'Library/Application Support/svm/0.8.26/solc-0.8.26')];
  try { candidates.push(commandPath('solc')); } catch { /* An explicit compiler path may still be available. */ }
  for (const candidate of candidates.filter(Boolean)) {
    try {
      const path = await realpath(candidate), version = execFileSync(path, ['--version'], { encoding: 'utf8' }).trim();
      if (/\b0\.8\.26\b/.test(version)) return { path, version, sha256: hash(await readFile(path)) };
    } catch { /* Try the next standard location. */ }
  }
  throw new Error('Solc 0.8.26 not found; set AVA_PREVIEW_SOLC to its executable path');
}

/** Install and exercise the verified package set in an exclusively created, retained directory. */
export async function runConsumer(directory, workdir) {
  const verified = await verifyPreview(directory);
  const { release } = verified.manifest;
  assert.equal(release, currentPreviewRelease, 'Run a prior release with its bundled verifier');
  assert(Number(process.versions.node.split('.')[0]) >= 24, 'Node 24 or later is required');
  assert(typeof workdir === 'string' && isAbsolute(workdir), 'workdir must be an absolute new directory');
  const dest = resolve(workdir), bundle = await realpath(verified.root), parent = await realpath(dirname(dest));
  const actualDest = resolve(parent, dest.slice(dirname(dest).length + 1));
  assert(actualDest !== bundle && !actualDest.startsWith(bundle + sep), 'workdir must be outside the preview bundle');
  await mkdir(dest, { mode: 0o700 });
  const started = performance.now();
  const record = { status: 'running', previewRelease: release, startedAt: new Date().toISOString(),
    workdir: dest, stages: [], packageHashes: {}, fixtureHashes: {}, installedHashes: {} };
  const save = () => writeFile(resolve(dest, 'verification.json'), json(record), { mode: 0o600 });
  const run = async (command, args, label, env) => {
    const begin = performance.now();
    const child = spawn(command, args, { cwd: dest, env, stdio: ['ignore', 'pipe', 'pipe'] });
    const chunks = [];
    child.stdout.on('data', chunk => chunks.push(chunk)); child.stderr.on('data', chunk => chunks.push(chunk));
    let interruptedBy;
    const interrupt = signal => { interruptedBy ??= signal; child.kill(signal); };
    const sigint = () => interrupt('SIGINT'), sigterm = () => interrupt('SIGTERM');
    process.once('SIGINT', sigint); process.once('SIGTERM', sigterm);
    let exit;
    try { [exit] = await once(child, 'close'); }
    catch (error) { chunks.push(Buffer.from(String(error))); throw error; }
    finally {
      process.off('SIGINT', sigint); process.off('SIGTERM', sigterm);
      await writeFile(resolve(dest, `${label}.log`), Buffer.concat(chunks), { mode: 0o600 });
    }
    record.stages.push({ label, command, args, exit, interruptedBy, elapsedMs: performance.now() - begin }); await save();
    if (interruptedBy) throw new Error(`${label} interrupted by ${interruptedBy}; inspect ${resolve(dest, `${label}.log`)}`);
    assert.equal(exit, 0, `${label} failed; inspect ${resolve(dest, `${label}.log`)}`);
  };
  try {
    await cp(resolve(bundle, 'work-order'), dest, { recursive: true });
    await cp(resolve(bundle, 'artifacts'), resolve(dest, 'artifacts'), { recursive: true });
    for (const name of names) record.packageHashes[name] = verified.manifest.components[name].sha256;
    for (const [path, digest] of Object.entries(verified.manifest.files)) {
      if (path.startsWith('work-order/')) record.fixtureHashes[path.slice('work-order/'.length)] = digest;
    }
    for (const [path, digest] of Object.entries(record.fixtureHashes)) {
      assert.equal(hash(await readFile(resolve(dest, path))), digest, `Copied fixture changed: ${path}`);
    }
    for (const name of names) {
      const item = verified.manifest.components[name];
      assert.equal(hash(await readFile(resolve(dest, item.archive))), item.sha256, `Copied archive changed: ${name}`);
    }
    await writeFile(resolve(dest, 'package-hashes.json'), json(record.packageHashes));
    await writeFile(resolve(dest, 'fixture-hashes.json'), json({ files: record.fixtureHashes,
      runnerSha256: verified.manifest.files['verify.mjs'] }));
    await mkdir(resolve(dest, '.npm-cache'), { mode: 0o700 });
    assert.deepEqual(await readdir(resolve(dest, '.npm-cache')), []);
    record.emptyCacheBefore = true;
    const solc = await selectedSolc();
    await mkdir(resolve(dest, '.tools'), { mode: 0o700 });
    const privateSolc = resolve(dest, '.tools/solc-0.8.26');
    await cp(solc.path, privateSolc); assert.equal(hash(await readFile(privateSolc)), solc.sha256);
    record.toolchain = { node: { path: process.execPath, version: process.version }, solc: { ...solc, privateCopy: privateSolc },
      npm: { path: commandPath('npm'), version: execFileSync('npm', ['--version'], { encoding: 'utf8' }).trim() },
      forge: { path: commandPath('forge'), version: execFileSync('forge', ['--version'], { encoding: 'utf8' }).trim() },
      anvil: { path: commandPath('anvil'), version: execFileSync('anvil', ['--version'], { encoding: 'utf8' }).trim() } };
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) =>
      !/^(?:FOUNDRY_|DAPP_|SOLC|SVM_|NPM_CONFIG_|npm_config_|NODE_OPTIONS$|NODE_PATH$|TMPDIR$)/.test(name)));
    Object.assign(env, { NODE_PATH: '', npm_config_cache: resolve(dest, '.npm-cache'),
      FOUNDRY_OUT: resolve(dest, 'out'), FOUNDRY_CACHE_PATH: resolve(dest, '.forge-cache'),
      FOUNDRY_BROADCAST: resolve(dest, 'broadcast'), FOUNDRY_SOLC: privateSolc, FOUNDRY_OFFLINE: 'true',
      TMPDIR: resolve(dest, '.tmp'), AVA_WORK_ORDER_PROFILES: '1', AVA_WORK_ORDER_RULE_LIFECYCLE: '0' });
    await mkdir(env.TMPDIR, { mode: 0o700 });
    await save();
    await run(record.toolchain.npm.path, ['ci', '--ignore-scripts', '--no-audit', '--no-fund', '--workspaces=false'], 'npm', env);
    const lock = JSON.parse(await readFile(resolve(dest, 'package-lock.json'), 'utf8'));
    assert(Object.values(lock.packages).every(item => !item.link), 'Workspace links are not allowed');
    for (const name of names) {
      const component = verified.manifest.components[name], packageDir = resolve(dest, 'node_modules/@ava-protocol', name);
      assert(!(await lstat(packageDir)).isSymbolicLink());
      const actualDir = await realpath(packageDir);
      assert(actualDir.startsWith(resolve(dest, 'node_modules') + sep));
      const pkg = JSON.parse(await readFile(resolve(packageDir, 'package.json'), 'utf8'));
      assert.equal(pkg.name, component.name); assert.equal(pkg.version, release);
      assert.equal(lock.packages[`node_modules/@ava-protocol/${name}`]?.version, release);
      if (name === 'agent-sdk' || name === 'local-service') assert.equal(pkg.dependencies?.['@ava-protocol/sdk'], release);
      const files = {};
      for (const member of verified.archiveFiles[name]) {
        const relativeName = member.slice('package/'.length);
        const file = resolve(packageDir, relativeName);
        assert((await lstat(file)).isFile() && !(await lstat(file)).isSymbolicLink());
        assert((await realpath(file)).startsWith(actualDir + sep));
        const archived = execFileSync('tar', ['-xOzf', resolve(dest, component.archive), member], { maxBuffer: 32 * 1024 * 1024 });
        const installed = await readFile(file); assert.equal(hash(installed), hash(archived), `Installed file differs: ${name}/${relativeName}`);
        files[relativeName] = hash(installed);
      }
      record.installedHashes[name] = files;
    }
    const probe = `import { realpathSync } from 'node:fs';\nimport { fileURLToPath } from 'node:url';\nimport { resolve, sep } from 'node:path';\nfor (const name of ['@ava-protocol/sdk','@ava-protocol/sdk/deployment','@ava-protocol/sdk/costs','@ava-protocol/agent-sdk','@ava-protocol/local-service/server','@ava-protocol/local-service/custody','@ava-protocol/local-service/testing']) {\n const path = realpathSync(fileURLToPath(import.meta.resolve(name)));\n if (!path.startsWith(resolve('node_modules') + sep)) throw new Error('Import outside installed project');\n await import(name); console.log(name + ' ' + path);\n}\n`;
    await writeFile(resolve(dest, 'public-imports.mjs'), probe);
    await run(process.execPath, ['public-imports.mjs'], 'public-imports', env);
    await run(process.execPath, ['node_modules/typescript/bin/tsc', '-p', 'tsconfig.json'], 'typecheck', env);
    await run(process.execPath, ['build/check.js'], 'workflow', env);
    const evidence = JSON.parse(await readFile(resolve(dest, 'evidence.json'), 'utf8'));
    assert.equal(evidence.status, 'scoped-checks-passed');
    assert.equal(evidence.chainId, 31337);
    assert.deepEqual(evidence.packageHashes, record.packageHashes);
    assert.deepEqual(evidence.fixtureHashes, { files: record.fixtureHashes, runnerSha256: verified.manifest.files['verify.mjs'] });
    assert.deepEqual(evidence.profiles?.map(profile => profile.name), ['fresh-split', 'fresh-combined', 'reused-combined']);
    for (const profile of evidence.profiles) {
      assert(profile.installation?.ready && profile.originalRecognition && profile.originalRequest && profile.originalReceipt
        && profile.correction && profile.http && profile.phases && Array.isArray(profile.transactions));
      assert(Object.values(profile.checks ?? {}).every(value => value === true) && Object.keys(profile.checks ?? {}).length > 0);
    }
    record.evidenceSha256 = hash(await readFile(resolve(dest, 'evidence.json')));
    await run(process.execPath, ['build/check.js'], 'lifecycle',
      { ...env, AVA_WORK_ORDER_PROFILES: '0', AVA_WORK_ORDER_RULE_LIFECYCLE: '1' });
    const lifecycleBytes = await readFile(resolve(dest, 'lifecycle-evidence.json'));
    const lifecycle = JSON.parse(lifecycleBytes.toString('utf8'));
    assert.equal(lifecycle.status, 'scoped-checks-passed');
    assert.equal(lifecycle.chainId, 31337);
    assert.deepEqual(lifecycle.packageHashes, record.packageHashes);
    assert.deepEqual(lifecycle.fixtureHashes, { files: record.fixtureHashes, runnerSha256: verified.manifest.files['verify.mjs'] });
    const deployment = lifecycle.deploymentVerification;
    assert(deployment?.coreTransactions > 0 && deployment.appTransactions > 0 && deployment.deterministicCreations > 0
      && deployment.changedCreationAddressRefused === true && deployment.swappedHashesRefused === true
      && deployment.usesRpcRegistrationLogs === true);
    const rule = lifecycle.ruleLifecycle;
    assert.equal(rule?.successorInstallation?.ready, true);
    assert.equal(rule.oldInstallationRefused, true);
    for (const check of ['predecessorIntakeRefused', 'successorIntakeRefused', 'approvedBacklogExecutedOnce',
      'historicalCorrectionAfterReplacement', 'explicitRecovery']) assert.equal(rule.checks?.[check], true, `Lifecycle check failed: ${check}`);
    const recovery = rule.transactionRecovery;
    assert(typeof recovery?.key === 'string' && recovery.key.length > 0
      && /^0x[0-9a-fA-F]{64}$/.test(recovery.hash) && typeof recovery.nonce === 'string' && /^\d+$/.test(recovery.nonce)
      && /^0x[0-9a-fA-F]{64}$/.test(recovery.blockHash) && recovery.attempts === 2 && recovery.accepted === 1);
    record.lifecycleEvidenceSha256 = hash(lifecycleBytes);
    record.status = 'scoped-checks-passed';
    return record;
  } catch (error) {
    record.status = 'failed'; record.error = error instanceof Error ? error.message : String(error); throw error;
  } finally {
    record.elapsedMs = performance.now() - started; record.finishedAt = new Date().toISOString(); await save();
  }
}

const isMain = process.argv[1] && await realpath(resolve(process.argv[1])) === await realpath(fileURLToPath(import.meta.url));
if (isMain) {
  const root = dirname(fileURLToPath(import.meta.url)), args = process.argv.slice(2);
  if (args.length === 1 && args[0] === '--verify-only') {
    const { manifest } = await verifyPreview(root);
    console.log(json({ status: 'verified', release: manifest.release, integrity: 'hashes only; publisher not authenticated' }));
  } else if (args.length === 2 && args[0] === '--workdir') {
    const result = await runConsumer(root, args[1]);
    console.log(json({ status: result.status, workdir: result.workdir, evidenceSha256: result.evidenceSha256,
      lifecycleEvidenceSha256: result.lifecycleEvidenceSha256 }));
  } else throw new Error('Usage: node verify.mjs --verify-only | --workdir <new-absolute-directory>');
}
