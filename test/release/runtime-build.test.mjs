import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, copyFile, cp, writeFile, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildRuntime, runtimeResources } from '../../scripts/build_runtime.mjs';

const repo = process.cwd();
const packages = ['ava-sdk', 'ava-agent-sdk', 'ava-service'];

async function fixture(t, ownCompiler = false) {
  const root = await mkdtemp(join(repo, '.tmp/ava-runtime-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  if (ownCompiler) {
    await mkdir(join(root, 'node_modules'));
    await cp(join(repo, 'node_modules/typescript'), join(root, 'node_modules/typescript'), { recursive: true });
    await symlink(join(repo, 'node_modules/@types'), join(root, 'node_modules/@types'), 'dir');
  } else await symlink(join(repo, 'node_modules'), join(root, 'node_modules'), 'dir');
  for (const file of ['tsconfig.json', 'package.json', 'package-lock.json']) await copyFile(join(repo, file), join(root, file));
  await mkdir(join(root,'scripts'),{recursive:true});
  for(const resource of runtimeResources)await copyFile(join(repo,resource.source),join(root,resource.source));
  for (const name of packages) {
    const dir = join(root, 'packages', name);
    await mkdir(join(dir, 'src'), { recursive: true });
    for (const file of ['tsconfig.build.json', 'package.json']) await copyFile(join(repo, 'packages', name, file), join(dir, file));
    await writeFile(join(dir, 'src/index.ts'), 'export const value: number = 1;\n');
  }
  return root;
}

test('builds once and reuses verified outputs', async (t) => {
  const root = await fixture(t);
  await writeFile(join(root, 'packages/ava-sdk/src/types.d.ts'), 'export type Example = string;\n');
  const start = performance.now();
  const first = await buildRuntime(root);
  const builtMs = performance.now() - start;
  assert.equal(first.status, 'built');
  const cachedStart = performance.now();
  assert.equal((await buildRuntime(root)).status, 'cached');
  t.diagnostic(`fixture built ${builtMs.toFixed(1)} ms; cache hit ${(performance.now() - cachedStart).toFixed(1)} ms`);
  assert.match(await readFile(join(root, 'packages/ava-sdk/dist/index.js'), 'utf8'), /value = 1/);
});

test('rebuilds after input changes and repairs missing, altered, or retired outputs', async (t) => {
  const root = await fixture(t);
  const source = join(root, 'packages/ava-sdk/src/index.ts');
  const output = join(root, 'packages/ava-sdk/dist/index.js');
  await buildRuntime(root);
  await writeFile(source, 'export const value: number = 2;\n');
  assert.equal((await buildRuntime(root)).status, 'built');
  assert.match(await readFile(output, 'utf8'), /value = 2/);
  await writeFile(join(root, 'packages/ava-sdk/tsconfig.build.json'), (await readFile(join(root, 'packages/ava-sdk/tsconfig.build.json'), 'utf8')) + '\n');
  assert.equal((await buildRuntime(root)).status, 'built');
  await rm(output);
  assert.equal((await buildRuntime(root)).status, 'built');
  await writeFile(output, 'tampered');
  assert.equal((await buildRuntime(root)).status, 'built');
  assert.match(await readFile(output, 'utf8'), /value = 2/);
  await writeFile(join(root, 'packages/ava-sdk/src/retired.ts'), 'export const retired = true;\n');
  await buildRuntime(root);
  await rm(join(root, 'packages/ava-sdk/src/retired.ts'));
  assert.equal((await buildRuntime(root)).status, 'built');
  await assert.rejects(readFile(join(root, 'packages/ava-sdk/dist/retired.js')), { code: 'ENOENT' });
  await writeFile(join(root, 'packages/ava-sdk/dist/extra.js'), 'extra');
  assert.equal((await buildRuntime(root)).status, 'built');
  await assert.rejects(readFile(join(root, 'packages/ava-sdk/dist/extra.js')), { code: 'ENOENT' });
});

test('failed compilation is not cached and valid source can be rebuilt', async (t) => {
  const root = await fixture(t);
  const source = join(root, 'packages/ava-sdk/src/index.ts');
  await buildRuntime(root);
  await writeFile(source, 'export const value: number = "bad";\n');
  await assert.rejects(buildRuntime(root), /Runtime build failed/);
  await assert.rejects(readFile(join(root, '.build/runtime-build.json')), { code: 'ENOENT' });
  await writeFile(source, 'export const value: number = 1;\n');
  assert.equal((await buildRuntime(root)).status, 'built');
  assert.equal((await buildRuntime(root)).status, 'cached');
});

test('CLI uses its own root and supports force', async (t) => {
  const root = await fixture(t);
  await mkdir(join(root, 'scripts'),{recursive:true});
  const script = join(root, 'scripts/build_runtime.mjs');
  await copyFile(fileURLToPath(new URL('../../scripts/build_runtime.mjs', import.meta.url)), script);
  const { spawnSync } = await import('node:child_process');
  const run = (...args) => spawnSync(process.execPath, [script, ...args], { cwd: tmpdir(), encoding: 'utf8' });
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  assert.match(first.stdout, /Runtime built:/);
  assert.match(run().stdout, /Runtime cached:/);
  const forced = run('--force');
  assert.equal(forced.status, 0);
  assert.match(forced.stdout, /Runtime built:/);
  await writeFile(script, (await readFile(script, 'utf8')) + '\n// changed build tool\n');
  assert.match(run().stdout, /Runtime built:/);
  const imported = spawnSync(process.execPath, ['--input-type=module', '-'], {
    input: `import { buildRuntime, runtimeResources } from ${JSON.stringify(new URL('../../scripts/build_runtime.mjs', import.meta.url).href)}; console.log(typeof buildRuntime);`,
    cwd: repo, encoding: 'utf8',
  });
  assert.equal(imported.status, 0, imported.stderr);
  assert.match(imported.stdout, /function/);
});

test('same-version compiler changes invalidate the cache and missing compiler recovery rebuilds', async (t) => {
  const root = await fixture(t, true);
  await buildRuntime(root);
  const entry = join(root, 'node_modules/typescript/bin/tsc');
  await writeFile(entry, (await readFile(entry, 'utf8')) + '\n// same-version compiler change\n');
  assert.equal((await buildRuntime(root)).status, 'built');
  const compiler = join(root, 'node_modules/typescript/lib/_tsc.js');
  const original = await readFile(compiler);
  await rm(compiler);
  await assert.rejects(buildRuntime(root), /Runtime build failed/);
  await assert.rejects(readFile(join(root, '.build/runtime-build.json')), { code: 'ENOENT' });
  await writeFile(compiler, original);
  assert.equal((await buildRuntime(root)).status, 'built');
  assert.equal((await buildRuntime(root)).status, 'cached');
});

test('bundled Python payloads are current cache inputs and altered outputs are repaired',async t=>{
 const root=await fixture(t),resource=runtimeResources[0];
 await buildRuntime(root);
 assert.equal(await readFile(join(root,resource.output),'utf8'),await readFile(join(root,resource.source),'utf8'));
 await writeFile(join(root,resource.source),(await readFile(join(root,resource.source),'utf8'))+'\n# resource change\n');
 assert.equal((await buildRuntime(root)).status,'built');
 await writeFile(join(root,resource.output),'tampered');
 assert.equal((await buildRuntime(root)).status,'built');
 assert.equal(await readFile(join(root,resource.output),'utf8'),await readFile(join(root,resource.source),'utf8'));
});
