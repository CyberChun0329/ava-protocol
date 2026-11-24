import assert from 'node:assert/strict';
import { test } from 'node:test';
import { once } from 'node:events';
import { LocalMaterialCustody, MaterialCustodyUnavailableError } from '@ava-protocol/local-service/custody';
const base = { appId: `0x${'01'.repeat(32)}` as const, vaultPath: '.local/synthetic-vault' };
test('custody requires exactly one credential mode; a profile cannot silently use a legacy key', () => {
  assert.throws(() => new LocalMaterialCustody(base as any), MaterialCustodyUnavailableError);
  assert.throws(() => new LocalMaterialCustody({ ...base, masterKeyFile: 'old.key', credentialProfileFile: 'profile.json' } as any), MaterialCustodyUnavailableError);
  assert.throws(() => new LocalMaterialCustody({ ...base, credentialProfileFile: '' }), MaterialCustodyUnavailableError);
});

test('public custody operator preserves old receipts, isolates new writes and survives removal of the old key path', async t => {
  const { randomBytes } = await import('node:crypto');
  const { mkdtemp, writeFile, readFile, rename, copyFile, mkdir, rm } = await import('node:fs/promises');
  const { resolve, join } = await import('node:path');
  const { runCustodyOperator } = await import('@ava-protocol/local-service/custody');
  const rootDirectory = await mkdtemp(resolve(process.env.AVA_TEST_OUTPUT_ROOT ?? '.tmp', 'custody-profile-'));
  t.after(() => rm(rootDirectory, { recursive: true, force: true }));
  const vaultPath = join(rootDirectory, 'vault'), masterKeyFile = join(rootDirectory, 'old.key'),
    newKey = join(rootDirectory, 'new.key'), pythonPath = resolve('.local/privacy-venv/bin/python');
  await writeFile(masterKeyFile, randomBytes(32), { mode: 0o600 });
  await writeFile(newKey, randomBytes(32), { mode: 0o600 });
  const options = { ...base, rootDirectory, vaultPath, masterKeyFile, pythonPath };
  const legacy = new LocalMaterialCustody(options), bytes = Buffer.from('Synthetic historical signed material.');
  const receipt = await legacy.stage(`0x${'02'.repeat(32)}`, `0x${'03'.repeat(32)}`, bytes, { author: 'synthetic' });
  const encoded = await readFile(join(vaultPath, receipt.resourceId.slice(2) + '.json'));
  const operator = { vaultPath, rootDirectory, pythonPath };
  const prepared = await runCustodyOperator(operator, { operation: 'prepare', masterKeyFile,
    newMasterKeyFile: newKey, expectedReceipts: [receipt] });
  assert.equal(prepared.mode, 'prepared');
  assert.deepEqual((await legacy.read(receipt)).payload, bytes, 'preparation leaves the old generation live');
  await runCustodyOperator(operator, { operation: 'activate', generationId: prepared.generationId! });
  await assert.rejects(legacy.read(receipt), MaterialCustodyUnavailableError);
  const profile = new LocalMaterialCustody({ ...base, rootDirectory, vaultPath, pythonPath,
    credentialProfileFile: join(vaultPath, '.ava-custody-profile.json') });
  assert.equal((await profile.verifyConfiguration()).mode, 'profile');
  assert.deepEqual((await profile.read(receipt)).payload, bytes);
  assert.deepEqual(await readFile(join(vaultPath, receipt.resourceId.slice(2) + '.json')), encoded);
  const fresh = await profile.stage(receipt.caseId, receipt.materialClass, Buffer.from('New generation material'), {});
  const detached = join(rootDirectory, 'independent-records'); await mkdir(detached, { mode: 0o700 });
  await copyFile(join(vaultPath, fresh.resourceId.slice(2) + '.json'), join(detached, fresh.resourceId.slice(2) + '.json'));
  await assert.rejects(new LocalMaterialCustody({ ...options, vaultPath: detached }).read(fresh), MaterialCustodyUnavailableError);
  assert.equal((await new LocalMaterialCustody({ ...options, vaultPath: detached, masterKeyFile: newKey }).read(fresh)).payload.toString(), 'New generation material');
  await rename(masterKeyFile, masterKeyFile + '.retired');
  assert.deepEqual((await profile.read(receipt)).payload, bytes);
  await rename(newKey, newKey + '.missing');
  await assert.rejects(profile.verifyConfiguration(), MaterialCustodyUnavailableError);
  await assert.rejects(profile.read(receipt), MaterialCustodyUnavailableError);
  await rename(newKey + '.missing', newKey);
  assert.deepEqual((await profile.read(receipt)).payload, bytes);
});

test('a killed operator before selector replacement fails closed and resumes the same prepared generation', async t => {
  const { randomBytes } = await import('node:crypto');
  const { mkdtemp, writeFile, rm, readFile } = await import('node:fs/promises');
  const { resolve, join } = await import('node:path');
  const { spawn } = await import('node:child_process');
  const { runCustodyOperator } = await import('@ava-protocol/local-service/custody');
  const rootDirectory = await mkdtemp(resolve(process.env.AVA_TEST_OUTPUT_ROOT ?? '.tmp', 'custody-killed-'));
  const pythonPath = resolve('.local/privacy-venv/bin/python'), vaultPath = join(rootDirectory, 'vault'),
    masterKeyFile = join(rootDirectory, 'old.key'), newKey = join(rootDirectory, 'new.key');
  t.after(() => rm(rootDirectory, { recursive: true, force: true }));
  await writeFile(masterKeyFile, randomBytes(32), { mode: 0o600 });
  await writeFile(newKey, randomBytes(32), { mode: 0o600 });
  const local = new LocalMaterialCustody({ ...base, rootDirectory, vaultPath, masterKeyFile, pythonPath });
  const record = await local.stage(`0x${'02'.repeat(32)}`, `0x${'03'.repeat(32)}`, Buffer.from('Synthetic crash-recovery material'), {});
  const recordPath = join(vaultPath, record.resourceId.slice(2) + '.json'), before = await readFile(recordPath);
  const options = { rootDirectory, vaultPath, pythonPath };
  const prepared = await runCustodyOperator(options, { operation: 'prepare', masterKeyFile,
    newMasterKeyFile: newKey, expectedReceipts: [record] });
  // Test-side filesystem syscall proxy only; production operator receives no fault switch.
  const bootstrap = `import os,sys,runpy,threading\nsys.path.insert(0,os.path.dirname(sys.argv[1]))\nreal_replace=os.replace\ndef replace(src,dst,*a,**kw):\n if str(dst).endswith('.ava-custody-profile.json'):\n  sys.stderr.write('selector-replacement-ready\\n');sys.stderr.flush();threading.Event().wait()\n return real_replace(src,dst,*a,**kw)\nos.replace=replace\nrunpy.run_path(sys.argv[1],run_name='__main__')`;
  const child = spawn(pythonPath, ['-c', bootstrap, resolve('scripts/custody_operator.py')],
    { env: { ...process.env, AVA_CUSTODY_ROOT: rootDirectory, PYTHONDONTWRITEBYTECODE: '1' }, stdio: ['pipe', 'pipe', 'pipe'] });
  t.after(() => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL'); });
  const exited = once(child, 'exit');
  const ready = new Promise<void>((done, reject) => {
    let text = ''; const timeout = setTimeout(() => reject(new Error('operator_barrier_timeout')), 10_000);
    child.stderr.on('data', bytes => { text += bytes.toString(); if (text.includes('selector-replacement-ready')) { clearTimeout(timeout); done(); } });
    child.once('error', error => { clearTimeout(timeout); reject(error); });
    child.once('exit', () => { clearTimeout(timeout); reject(new Error('operator_exited_before_barrier')); });
  });
  child.stdin.end(JSON.stringify({ operation: 'activate', vaultPath, generationId: prepared.generationId }));
  await ready; child.kill('SIGKILL');
  assert.equal((await exited)[1], 'SIGKILL');
  assert.equal((await runCustodyOperator(options, { operation: 'inspect' })).mode, 'activation_incomplete');
  await assert.rejects(local.read(record), MaterialCustodyUnavailableError);
  const resumed = await runCustodyOperator(options, { operation: 'activate', generationId: prepared.generationId! });
  assert.equal(resumed.generationId, prepared.generationId);
  const reopened = new LocalMaterialCustody({ ...base, rootDirectory, vaultPath, pythonPath,
    credentialProfileFile: join(vaultPath, '.ava-custody-profile.json') });
  assert.equal((await reopened.read(record)).payload.toString(), 'Synthetic crash-recovery material');
  assert.deepEqual(await readFile(recordPath), before);
});

test('a foreign profile is refused before taking over historical material, then legitimate rotation works', async t => {
  const { randomBytes } = await import('node:crypto');
  const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
  const { resolve, join } = await import('node:path');
  const { runCustodyOperator } = await import('@ava-protocol/local-service/custody');
  const rootDirectory = await mkdtemp(resolve(process.env.AVA_TEST_OUTPUT_ROOT ?? '.tmp', 'custody-foreign-'));
  t.after(() => rm(rootDirectory, { recursive: true, force: true }));
  const pythonPath = resolve('.local/privacy-venv/bin/python'), aKey = join(rootDirectory, 'a.key'),
    bKey = join(rootDirectory, 'b.key'), bNext = join(rootDirectory, 'b-next.key'), aNext = join(rootDirectory, 'a-next.key');
  for (const key of [aKey, bKey, bNext, aNext]) await writeFile(key, randomBytes(32), { mode: 0o600 });
  const aPath = join(rootDirectory, 'a'), bPath = join(rootDirectory, 'b'),
    a = new LocalMaterialCustody({ ...base, rootDirectory, pythonPath, vaultPath: aPath, masterKeyFile: aKey }),
    b = new LocalMaterialCustody({ ...base, rootDirectory, pythonPath, vaultPath: bPath, masterKeyFile: bKey });
  const id = `0x${'02'.repeat(32)}` as const;
  const aReceipt = await a.stage(id, id, Buffer.from('Historical A must survive wrong import'), {});
  const bReceipt = await b.stage(id, id, Buffer.from('Unrelated B'), {});
  const bOptions = { rootDirectory, pythonPath, vaultPath: bPath }, aOptions = { rootDirectory, pythonPath, vaultPath: aPath };
  const candidateB = await runCustodyOperator(bOptions, { operation: 'prepare', masterKeyFile: bKey,
    newMasterKeyFile: bNext, expectedReceipts: [bReceipt] });
  await runCustodyOperator(bOptions, { operation: 'activate', generationId: candidateB.generationId! });
  const portable = await runCustodyOperator(bOptions, { operation: 'export-profile', credentialProfileFile: join(bPath, '.ava-custody-profile.json') });
  await assert.rejects(runCustodyOperator(aOptions, { operation: 'install-profile', activeKeyFile: bNext,
    profile: portable.profile! }), MaterialCustodyUnavailableError);
  assert.equal((await a.read(aReceipt)).payload.toString(), 'Historical A must survive wrong import');
  const candidateA = await runCustodyOperator(aOptions, { operation: 'prepare', masterKeyFile: aKey,
    newMasterKeyFile: aNext, expectedReceipts: [aReceipt] });
  await runCustodyOperator(aOptions, { operation: 'activate', generationId: candidateA.generationId! });
  const reopened = new LocalMaterialCustody({ ...base, rootDirectory, pythonPath, vaultPath: aPath,
    credentialProfileFile: join(aPath, '.ava-custody-profile.json') });
  assert.equal((await reopened.read(aReceipt)).payload.toString(), 'Historical A must survive wrong import');
});
