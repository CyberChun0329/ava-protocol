import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { createHash } from 'node:crypto';
import { chmod, mkdtemp, mkdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { delimiter, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { currentPreviewRelease, verifyPreview, runConsumer } from '../../examples/developer-preview/verify.mjs';

const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const components = ['contracts', 'sdk', 'agent-sdk', 'local-service'];
async function fixture(version = currentPreviewRelease) {
  const root = await mkdtemp(resolve(tmpdir(), 'ava-preview-test-'));
  const bundle = resolve(root, 'bundle'); await mkdir(resolve(bundle, 'artifacts'), { recursive: true });
  await mkdir(resolve(bundle, 'work-order'));
  await writeFile(resolve(bundle, 'README.md'), 'synthetic preview\n');
  await writeFile(resolve(bundle, 'verify.mjs'), await readFile(fileURLToPath(new URL('../../examples/developer-preview/verify.mjs', import.meta.url))));
  const manifest = { schemaVersion: 1, release: version, status: 'developer-preview', components: {}, compatibility: {}, files: {} };
  async function archive(component, pkg = {}) {
    const staging = resolve(root, 'staging'); await rm(staging, { recursive: true, force: true });
    await mkdir(resolve(staging, 'package'), { recursive: true });
    const requires = ['agent-sdk', 'local-service'].includes(component) ? { '@ava-protocol/sdk': version } : {};
    await writeFile(resolve(staging, 'package/package.json'), JSON.stringify({
      name: `@ava-protocol/${component}`, version, dependencies: requires, ...pkg }));
    const archivePath = `artifacts/ava-protocol-${component}-${version}.tgz`;
    execFileSync('tar', ['-czf', resolve(bundle, archivePath), '-C', staging, 'package']);
    const sha256 = hash(await readFile(resolve(bundle, archivePath)));
    manifest.components[component] = { name: `@ava-protocol/${component}`, version, sourceVersion: '0.1.0',
      archive: archivePath, sha256, requires };
    manifest.files[archivePath] = sha256;
  }
  for (const component of components) await archive(component);
  const dependencies = Object.fromEntries(components.map(name =>
    [`@ava-protocol/${name}`, `file:artifacts/ava-protocol-${name}-${version}.tgz`]));
  await writeFile(resolve(bundle, 'work-order/package.json'), JSON.stringify({ private: true, dependencies }));
  for (const path of ['README.md', 'verify.mjs', 'work-order/package.json']) {
    manifest.files[path] = hash(await readFile(resolve(bundle, path)));
  }
  const save = async () => {
    const packages = { '': { dependencies } };
    for (const name of components) {
      const component = manifest.components[name], bytes = await readFile(resolve(bundle, component.archive));
      packages[`node_modules/${component.name}`] = { version, resolved: `file:${component.archive}`,
        integrity: `sha512-${createHash('sha512').update(bytes).digest('base64')}` };
    }
    const lock = JSON.stringify({ lockfileVersion: 3, packages });
    await writeFile(resolve(bundle, 'work-order/package-lock.json'), lock);
    manifest.files['work-order/package-lock.json'] = hash(lock);
    await writeFile(resolve(bundle, 'manifest.json'), JSON.stringify(manifest));
  };
  await save();
  return { root, bundle, manifest, archive, save, close: () => rm(root, { recursive: true, force: true }) };
}

for (const version of ['0.1.0-preview.9', '0.1.0-preview.10', '0.1.0-preview.11']) {
  test(`frozen ${version} remains verifiable and uses its bundled verifier to run the consumer`, async () => {
    const f = await fixture(version);
    try {
      assert.equal((await verifyPreview(f.bundle)).manifest.release, version);
      await assert.rejects(runConsumer(f.bundle, f.root), /bundled verifier/);
    } finally { await f.close(); }
  });
}

test('preview rejects missing or changed payloads and recovers when the verified bytes return', async () => {
  const f = await fixture();
  try {
    await verifyPreview(f.bundle);
    const archive = resolve(f.bundle, f.manifest.components.sdk.archive), original = await readFile(archive);
    await rm(archive); await assert.rejects(verifyPreview(f.bundle));
    await writeFile(archive, Buffer.from('tampered')); await assert.rejects(verifyPreview(f.bundle));
    await writeFile(archive, original); await verifyPreview(f.bundle);
    await writeFile(resolve(f.bundle, 'unexpected.txt'), 'extra'); await assert.rejects(verifyPreview(f.bundle));
    await rm(resolve(f.bundle, 'unexpected.txt')); await verifyPreview(f.bundle);
    const result = JSON.parse(execFileSync(process.execPath, [resolve(f.bundle, 'verify.mjs'), '--verify-only'],
      { cwd: f.root, encoding: 'utf8' }));
    assert.equal(result.status, 'verified');
    assert.equal(result.release, '0.1.0-preview.12');
  } finally { await f.close(); }
});

test('archive package identity and exact SDK dependency cannot be hidden behind fresh hashes', async () => {
  const f = await fixture();
  try {
    await f.archive('sdk', { version: '0.1.0' }); await f.save(); await assert.rejects(verifyPreview(f.bundle));
    await f.archive('sdk'); await f.archive('agent-sdk', { dependencies: { '@ava-protocol/sdk': '^0.1.0' } });
    await f.save(); await assert.rejects(verifyPreview(f.bundle));
    await f.archive('agent-sdk'); await f.save(); await verifyPreview(f.bundle);
  } finally { await f.close(); }
});

test('unsafe paths, symlinks and an existing consumer directory are rejected', async () => {
  const f = await fixture();
  try {
    f.manifest.files['../escape'] = '0'.repeat(64); await f.save(); await assert.rejects(verifyPreview(f.bundle));
    delete f.manifest.files['../escape']; await f.save();
    await symlink(resolve(f.bundle, 'README.md'), resolve(f.bundle, 'link')); await assert.rejects(verifyPreview(f.bundle));
    await rm(resolve(f.bundle, 'link')); await verifyPreview(f.bundle);
    const existing = resolve(f.root, 'existing'); await mkdir(existing);
    await assert.rejects(runConsumer(f.bundle, existing), /exist/i);
  } finally { await f.close(); }
});

test('a mismatched consumer lock is rejected before any work directory is created', async () => {
  const f = await fixture();
  try {
    const lockPath = resolve(f.bundle, 'work-order/package-lock.json');
    const original = await readFile(lockPath), lock = JSON.parse(original.toString());
    lock.packages['node_modules/@ava-protocol/sdk'].version = '0.1.0';
    const changed = JSON.stringify(lock); await writeFile(lockPath, changed);
    f.manifest.files['work-order/package-lock.json'] = hash(changed);
    await writeFile(resolve(f.bundle, 'manifest.json'), JSON.stringify(f.manifest));
    const workdir = resolve(f.root, 'not-created');
    await assert.rejects(runConsumer(f.bundle, workdir));
    await assert.rejects(readFile(resolve(workdir, 'verification.json')), { code: 'ENOENT' });
    await f.save(); await verifyPreview(f.bundle);
  } finally { await f.close(); }
});

test('a manifest-matched fixture cannot import outside the copied work order', async () => {
  const f = await fixture();
  try {
    const path = 'work-order/check.ts', source = "import '../../repository-private.ts';\n";
    await writeFile(resolve(f.bundle, path), source);
    f.manifest.files[path] = hash(source); await f.save();
    await assert.rejects(verifyPreview(f.bundle), /escapes/);
    await rm(resolve(f.bundle, path)); delete f.manifest.files[path]; await f.save();
    await verifyPreview(f.bundle);
  } finally { await f.close(); }
});

for (const signal of ['SIGINT', 'SIGTERM']) {
  test(`preview forwards ${signal} to its active command and retains a failed receipt even if the command exits zero`,
    { timeout: 20_000, skip: process.platform === 'win32' }, async () => {
      const f = await fixture();
      let verifier;
      try {
        const bin = resolve(f.root, 'bin'); await mkdir(bin);
        const marker = resolve(f.root, 'npm-child.json'), stopped = resolve(f.root, 'npm-stopped.txt');
        const tool = async (name, source) => {
          const file = resolve(bin, name);
          await writeFile(file, '#!' + process.execPath + '\n' + source); await chmod(file, 0o700);
          return file;
        };
        const solc = await tool('solc', "console.log('Version: 0.8.26');\n");
        for (const name of ['forge', 'anvil']) await tool(name, "console.log('synthetic tool 1.5.1');\n");
        await tool('npm', `import { writeFileSync } from 'node:fs';
if (process.argv.includes('--version')) { console.log('10.0.0'); process.exit(0); }
writeFileSync(${JSON.stringify(marker)}, JSON.stringify({pid:process.pid}));
for (const signal of ['SIGINT','SIGTERM']) process.once(signal, () => {
 writeFileSync(${JSON.stringify(stopped)}, signal); process.exit(0);
});
setInterval(() => {}, 1000);
`);
        const workdir = resolve(f.root, 'consumer');
        verifier = spawn(process.execPath, [resolve(f.bundle, 'verify.mjs'), '--workdir', workdir], {
          env: { ...process.env, PATH: bin + delimiter + process.env.PATH, AVA_PREVIEW_SOLC: solc },
          stdio: ['ignore', 'pipe', 'pipe'], detached: true,
        });
        const closed = once(verifier, 'close');
        let output = '';
        verifier.stdout.on('data', chunk => { output += chunk; });
        verifier.stderr.on('data', chunk => { output += chunk; });
        const waitFor = async (read, description) => {
          const deadline = Date.now() + 8_000;
          while (Date.now() < deadline) {
            try { return await read(); } catch {}
            await new Promise(accept => setTimeout(accept, 20));
          }
          assert.fail(`${description}; verifier output: ${output}`);
        };
        const child = await waitFor(async () => JSON.parse(await readFile(marker, 'utf8')), 'npm must be running');
        assert.equal(JSON.parse(await readFile(resolve(workdir, 'verification.json'), 'utf8')).status, 'running');
        verifier.kill(signal);
        await closed;
        const receipt = JSON.parse(await readFile(resolve(workdir, 'verification.json'), 'utf8'));
        assert.equal(receipt.status, 'failed', 'interrupt must settle the retained verification receipt');
        assert.match(receipt.error, /interrupt/i);
        assert(receipt.finishedAt);
        assert.notEqual(verifier.exitCode, 0);
        assert.equal(await readFile(stopped, 'utf8'), signal, 'the original signal reaches the active command');
        assert.throws(() => process.kill(child.pid, 0), { code: 'ESRCH' }, 'active command must be reaped before the verifier exits');
        assert.deepEqual(receipt.stages.map(stage => stage.label), ['npm'], 'interruption cannot start another stage');
        await verifyPreview(f.bundle);
      } finally {
        if (verifier?.pid) {
          try { process.kill(-verifier.pid, 'SIGKILL'); } catch (error) { if (error.code !== 'ESRCH') throw error; }
        }
        await f.close();
      }
    });
}
