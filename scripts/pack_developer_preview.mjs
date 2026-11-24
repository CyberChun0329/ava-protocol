import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cp, lstat, mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { assertArtifactCapacity } from './test-artifacts.mjs';
import { currentPreviewRelease as release, verifyPreview } from '../examples/developer-preview/verify.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const names = ['contracts', 'sdk', 'agent-sdk', 'local-service'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => JSON.stringify(value, null, 2) + '\n';

async function files(directory, prefix = '') {
  const entries = [];
  for (const entry of (await readdir(directory, { withFileTypes: true })).sort((a, b) => a.name.localeCompare(b.name))) {
    const name = prefix + entry.name, path = resolve(directory, entry.name);
    assert(!entry.isSymbolicLink(), `Preview input must not be a symlink: ${path}`);
    if (entry.isDirectory()) entries.push(...await files(path, name + '/'));
    else { assert(entry.isFile(), `Preview input must be a file: ${path}`); entries.push(name); }
  }
  return entries;
}

export async function packDeveloperPreview() {
  const parent = resolve(root, '.local/developer-preview');
  const destination = resolve(parent, `ava-core-sdk-${release}`);
  const archive = `${destination}.tar.gz`;
  // A fixed version is an immutable handoff; never silently replace a different candidate.
  for (const path of [destination, archive, `${archive}.sha256`]) {
    try { await lstat(path); throw new Error(`Preview already exists; preserve the fixed candidate: ${path}`); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  await assertArtifactCapacity(root);
  await mkdir(parent, { recursive: true });
  const staging = await mkdtemp(resolve(parent, '.stage-'));
  const bundle = resolve(staging, `ava-core-sdk-${release}`);
  const env = { ...process.env, COPYFILE_DISABLE: '1', npm_config_cache: resolve(staging, 'pack-cache') };
  try {
    // Reuse the canonical source selection and runtime builder; no second contract distribution.
    execFileSync(process.execPath, ['scripts/pack_sdk.mjs'], { cwd: root, env, stdio: 'inherit' });
    await mkdir(resolve(bundle, 'artifacts'), { recursive: true });
    const components = {}, sourceArchives = {}, sourceContents = {};
    for (const name of names) {
      const original = resolve(root, '.local/sdk-artifacts', `ava-protocol-${name}-0.1.0.tgz`);
      sourceArchives[name] = sha256(await readFile(original));
      const unpacked = resolve(staging, `unpack-${name}`);
      await mkdir(unpacked);
      execFileSync('tar', ['-xzf', original, '-C', unpacked], { env });
      const directory = resolve(unpacked, 'package');
      const packagePath = resolve(directory, 'package.json');
      const pkg = JSON.parse(await readFile(packagePath, 'utf8'));
      assert.equal(pkg.name, `@ava-protocol/${name}`);
      assert.equal(pkg.version, '0.1.0');
      const unchanged = {};
      for (const path of await files(directory)) {
        if (!['package.json', 'README.md'].includes(path)) unchanged[path] = sha256(await readFile(resolve(directory, path)));
      }
      sourceContents[name] = { sha256: sha256(JSON.stringify(unchanged)), files: unchanged };
      pkg.version = release;
      const requires = name === 'agent-sdk' || name === 'local-service' ? { '@ava-protocol/sdk': release } : {};
      for (const [dependency, version] of Object.entries(requires)) {
        assert.equal(pkg.dependencies[dependency], '0.1.0'); pkg.dependencies[dependency] = version;
      }
      await writeFile(packagePath, json(pkg));
      const readme = await readFile(resolve(directory, 'README.md'), 'utf8');
      await writeFile(resolve(directory, 'README.md'), readme.replaceAll('0.1.0', release));
      const result = JSON.parse(execFileSync('npm', ['pack', '--ignore-scripts', '--json', '--pack-destination', resolve(bundle, 'artifacts')],
        { cwd: directory, env, encoding: 'utf8' }));
      const filename = `ava-protocol-${name}-${release}.tgz`;
      assert.equal(result.length, 1); assert.equal(result[0].filename, filename);
      components[name] = { name: pkg.name, version: release, sourceVersion: '0.1.0',
        archive: `artifacts/${filename}`, sha256: sha256(await readFile(resolve(bundle, 'artifacts', filename))), requires };
    }
    await cp(resolve(root, 'examples/independent-app'), resolve(bundle, 'work-order'), { recursive: true });
    await cp(resolve(root, 'examples/developer-preview/verify.mjs'), resolve(bundle, 'verify.mjs'));
    await cp(resolve(root, 'examples/developer-preview/README.md'), resolve(bundle, 'README.md'));
    const projectPath = resolve(bundle, 'work-order/package.json');
    const project = JSON.parse(await readFile(projectPath, 'utf8'));
    for (const item of Object.values(components)) project.dependencies[item.name] = `file:${item.archive}`;
    await writeFile(projectPath, json(project));
    const exampleReadme = resolve(bundle, 'work-order/README.md');
    await writeFile(exampleReadme, 'Portable bundle: run `node ../verify.mjs --workdir /absolute/new/directory` from this directory.\n'
      + 'The repository commands below apply only to a full development checkout; the portable check needs no checkout or shared cache.\n\n'
      + await readFile(exampleReadme, 'utf8'));
    // npm resolves file: paths from the consumer root. Keep lock-generation artifacts out of the payload.
    await cp(resolve(bundle, 'artifacts'), resolve(bundle, 'work-order/artifacts'), { recursive: true });
    const lockEnv = { ...env, NODE_PATH: '', npm_config_cache: resolve(staging, 'lock-cache') };
    const lockOutput = execFileSync('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', '--workspaces=false'],
      { cwd: resolve(bundle, 'work-order'), env: lockEnv, encoding: 'utf8' });
    await writeFile(resolve(parent, `lock-${release}.log`), lockOutput);
    await rm(resolve(bundle, 'work-order/artifacts'), { recursive: true });
    const sourceInputs = {};
    for (const base of ['examples/independent-app', 'examples/developer-preview']) {
      for (const path of await files(resolve(root, base))) sourceInputs[`${base}/${path}`] = sha256(await readFile(resolve(root, base, path)));
    }
    for (const path of ['scripts/pack_developer_preview.mjs', 'scripts/pack_sdk.mjs', 'scripts/build_runtime.mjs', 'foundry.toml', 'package-lock.json']) {
      sourceInputs[path] = sha256(await readFile(resolve(root, path)));
    }
    const manifest = { schemaVersion: 1, release, status: 'developer-preview', components,
      compatibility: { group: `ava-core-sdk-${release}`, publicDeploymentSchema: 1,
        node: '>=24.0.0', referenceFoundry: '1.5.1-stable', compiler: { solc: '0.8.26', evmVersion: 'cancun',
          optimizer: true, optimizerRuns: 200, viaIR: true, bytecodeHash: 'none' },
        supportedService: { chainId: 31337, transport: 'loopback', processes: 1 },
        requiredInterfaces: ['AVAAuthorityMatrix.isAuthorisedSubject(address,bytes32,bytes32,bytes32,bytes32)',
          'AVAEvidenceResourceBinding.bindingStatus(uint256)',
          'AVAGovernanceKernel.getGovernedObjectCommitmentReference(uint256)'],
        rule: 'Install these exact component archives together. Other pairings are unverified; installation identity is checked on chain by the SDK.' },
      provenance: { sourceArchives, sourceContents, sourceInputs,
        packagingTransform: 'Only staged package versions, internal exact SDK dependencies and README version references change. Runtime JS/declarations and Solidity sources are byte-identical to the source archives. Workspace development versions remain 0.1.0.' },
      files: {} };
    for (const path of await files(bundle)) manifest.files[path] = sha256(await readFile(resolve(bundle, path)));
    await writeFile(resolve(bundle, 'manifest.json'), json(manifest));
    await verifyPreview(bundle);
    const temporaryArchive = resolve(staging, 'preview.tar.gz');
    execFileSync('tar', ['--no-xattrs', '--no-acls', '-czf', temporaryArchive, '-C', staging, relative(staging, bundle)], { env });
    // Publish locally only after the complete bundle passes the standalone verifier.
    await rename(bundle, destination);
    await rename(temporaryArchive, archive);
    const digest = sha256(await readFile(archive));
    await writeFile(`${archive}.sha256`, `${digest}  ${relative(parent, archive)}\n`, { flag: 'wx' });
    console.log(json({ release, directory: destination, archive, sha256: digest,
      manifestSha256: sha256(await readFile(resolve(destination, 'manifest.json'))) }));
    return { directory: destination, archive, sha256: digest };
  } finally { await rm(staging, { recursive: true, force: true }); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  assert.equal(process.argv.length, 2, 'Usage: node scripts/pack_developer_preview.mjs');
  await packDeveloperPreview();
}
