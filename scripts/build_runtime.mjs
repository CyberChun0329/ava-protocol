import { createHash } from 'node:crypto';
import { existsSync, realpathSync } from 'node:fs';
import { readdir, readFile, mkdir, rm, writeFile, rename, copyFile } from 'node:fs/promises';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const packages = ['ava-sdk', 'ava-agent-sdk', 'ava-service'];
export const runtimeResources = ['material_custody.py','privacy_vault.py','private_files.py','custody_credentials.py','custody_operator.py','privacy_backup.py'].map(name => ({source:`scripts/${name}`, output:`packages/ava-service/dist/python/${name}`}));
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

async function filesUnder(root, directory) {
  const files = [];
  async function visit(dir) {
    let entries;
    try { entries = await readdir(join(root, dir), { withFileTypes: true }); }
    catch (error) { if (error.code === 'ENOENT') return; throw error; }
    for (const entry of entries) {
      const path = join(dir, entry.name);
      if (entry.isDirectory()) await visit(path);
      else files.push(path);
    }
  }
  await visit(directory);
  return files.sort();
}

async function inputs(root) {
  const sources = (await Promise.all(packages.map((name) => filesUnder(root, `packages/${name}/src`)))).flat().filter((p) => p.endsWith('.ts')).sort();
  const compilerFiles = (await Promise.all(['bin', 'lib'].map(directory =>
    filesUnder(root, `node_modules/typescript/${directory}`)))).flat();
  const paths = ['package.json', 'package-lock.json', 'tsconfig.json', 'node_modules/typescript/package.json',
    ...compilerFiles, ...runtimeResources.map(item=>item.source), ...packages.flatMap((name) => [`packages/${name}/package.json`, `packages/${name}/tsconfig.build.json`]), ...sources].sort();
  const records = await Promise.all(paths.map(async (path) => [path, hash(await readFile(join(root, path)))]));
  const version = JSON.parse(await readFile(join(root, 'node_modules/typescript/package.json'), 'utf8')).version;
  const builder = hash(await readFile(fileURLToPath(import.meta.url)));
  return { sources, inputHash: hash(JSON.stringify({ schema: 1, builder, node: process.version, typescript: version, records })) };
}

async function outputIdentity(root, sources) {
  const expected = sources.filter((p) => !p.endsWith('.d.ts')).flatMap((p) => {
    const stem = p.replace('/src/', '/dist/').slice(0, -3);
    return [`${stem}.js`, `${stem}.d.ts`];
  }).concat(runtimeResources.map(item=>item.output)).sort();
  const actual = (await Promise.all(packages.map((name) => filesUnder(root, `packages/${name}/dist`)))).flat().sort();
  if (JSON.stringify(expected) !== JSON.stringify(actual)) return null;
  return Promise.all(actual.map(async (path) => [path, hash(await readFile(join(root, path)))]));
}

export async function buildRuntime(root, { force = false } = {}) {
  root = resolve(root);
  const stamp = join(root, '.build/runtime-build.json');
  const before = await inputs(root);
  if (!force) {
    let cached;
    try { cached = JSON.parse(await readFile(stamp, 'utf8')); } catch (error) { if (error.code !== 'ENOENT' && !(error instanceof SyntaxError)) throw error; }
    if (cached?.inputHash === before.inputHash) {
      const outputs = await outputIdentity(root, before.sources);
      if (outputs && JSON.stringify(outputs) === JSON.stringify(cached.outputs)) return { status: 'cached', inputHash: before.inputHash };
    }
  }
  await rm(stamp, { force: true });
  for (const name of packages) await rm(join(root, 'packages', name, 'dist'), { recursive: true, force: true });
  const compiler = join(root, 'node_modules/typescript/bin/tsc');
  const result = spawnSync(process.execPath, [compiler, '-b', ...packages.map((name) => `packages/${name}/tsconfig.build.json`), '--force'], { cwd: root, stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`Runtime build failed (exit ${result.status})`);
  for(const resource of runtimeResources){await mkdir(join(root,dirname(resource.output)),{recursive:true});await copyFile(join(root,resource.source),join(root,resource.output));}
  const after = await inputs(root);
  if (before.inputHash !== after.inputHash) throw new Error('Runtime build inputs changed during compilation');
  const outputs = await outputIdentity(root, after.sources);
  if (!outputs) throw new Error('Runtime build produced unexpected outputs');
  await mkdir(join(root, '.build'), { recursive: true });
  const temporary = `${stamp}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, JSON.stringify({ inputHash: after.inputHash, outputs }) + '\n');
    await rename(temporary, stamp);
  } finally { await rm(temporary, { force: true }); }
  return { status: 'built', inputHash: after.inputHash };
}

if (process.argv[1] && existsSync(process.argv[1]) && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.slice(2).some((arg) => arg !== '--force')) throw new Error('Usage: build_runtime.mjs [--force]');
  const root = resolve(fileURLToPath(new URL('..', import.meta.url)));
  const result = await buildRuntime(root, { force: process.argv.includes('--force') });
  console.log(`Runtime ${result.status}: ${result.inputHash}`);
}
