import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, stat, symlink, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { test } from 'node:test';
import { LocalMaterialCustody, MaterialCustodyUnavailableError, type MaterialCustody, type MaterialReceipt }
  from '@ava-protocol/local-service/custody';

const pythonPath = resolve('.local/privacy-venv/bin/python');
const id = (value: number): `0x${string}` => `0x${value.toString(16).padStart(64, '0')}`;
async function fixture() {
  const parent = resolve(process.env.AVA_TEST_OUTPUT_ROOT ?? '.tmp');
  await mkdir(parent, { recursive: true, mode: 0o700 });
  const rootDirectory = await realpath(await mkdtemp(resolve(parent, 'custody-host-')));
  const vaultPath = join(rootDirectory, 'vault'), masterKeyFile = join(rootDirectory, 'master.key');
  await writeFile(masterKeyFile, randomBytes(32), { mode: 0o600 });
  return { rootDirectory, vaultPath, masterKeyFile, appId: id(1), pythonPath };
}

test('public custody stages encrypted material in its host directory and reads it after reopening', async t => {
  const options = await fixture();
  t.after(() => rm(options.rootDirectory, { recursive: true, force: true }));
  const body = Buffer.from('Synthetic private statement for the installed custody adapter.');
  const metadata = { title: 'Synthetic private title', scope: ['local-fixture'] };
  const first: MaterialCustody = new LocalMaterialCustody(options);
  const receipt = await first.stage(id(2), id(3), body, metadata);
  assert.deepEqual(Object.keys(receipt).sort(), ['appId', 'caseId', 'ciphertextHash', 'materialClass', 'policyId', 'resourceId', 'uri']);
  assert.equal(receipt.appId, id(1));
  assert.equal(receipt.caseId, id(2));
  assert.equal(receipt.materialClass, id(3));
  assert.equal(receipt.policyId, 1);
  assert.equal(receipt.uri, `ava-private:v1:${receipt.resourceId.slice(2)}`);
  const encrypted = await readFile(join(options.vaultPath, `${receipt.resourceId.slice(2)}.json`));
  assert.equal(encrypted.includes(body), false);
  assert.equal(encrypted.includes(Buffer.from(metadata.title)), false);
  assert.equal(createHash('sha256').update(encrypted).digest('hex'), receipt.ciphertextHash.slice(2));
  const envelope = JSON.parse(encrypted.toString('utf8'));
  assert.equal(envelope.version, 1);
  assert.deepEqual(envelope.context, { resourceId: receipt.resourceId, appId: id(1), caseId: id(2), policyId: 1, materialClass: id(3) });
  const reopened = await new LocalMaterialCustody(options).read(receipt);
  assert.deepEqual(reopened.payload, body);
  assert.deepEqual(reopened.metadata, metadata);
});

test('receipt app, case, class and ciphertext changes refuse without breaking the original read', async t => {
  const options = await fixture();
  t.after(() => rm(options.rootDirectory, { recursive: true, force: true }));
  const store = new LocalMaterialCustody(options);
  const receipt = await store.stage(id(2), id(3), Buffer.from('Synthetic scoped statement'), {});
  const invalid: MaterialReceipt[] = [
    { ...receipt, appId: id(9) }, { ...receipt, caseId: id(9) }, { ...receipt, materialClass: id(9) },
    { ...receipt, ciphertextHash: id(9) }, { ...receipt, policyId: 2 as 1 }, { ...receipt, uri: 'file:///private-data' },
  ];
  for (const forged of invalid) await assert.rejects(store.read(forged), MaterialCustodyUnavailableError);
  assert.equal((await store.read(receipt)).payload.toString(), 'Synthetic scoped statement');
});

test('wrong keys, unsafe key and Vault modes refuse and a corrected host can still read', async t => {
  const options = await fixture();
  t.after(() => rm(options.rootDirectory, { recursive: true, force: true }));
  const store = new LocalMaterialCustody(options);
  const receipt = await store.stage(id(2), id(3), Buffer.from('Synthetic recoverable statement'), {});
  const wrongKey = join(options.rootDirectory, 'wrong.key');
  await writeFile(wrongKey, randomBytes(32), { mode: 0o600 });
  await assert.rejects(new LocalMaterialCustody({ ...options, masterKeyFile: wrongKey }).read(receipt), MaterialCustodyUnavailableError);
  await chmod(options.masterKeyFile, 0o644);
  await assert.rejects(store.read(receipt), error => {
    assert(error instanceof MaterialCustodyUnavailableError);
    assert.equal(error.name, 'DraftCustodyUnavailableError');
    assert.equal(error.message, 'Draft custody request failed (E_CUSTODY)');
    assert.equal(error.cause, undefined);
    assert(!JSON.stringify(error).includes(options.masterKeyFile));
    return true;
  });
  await chmod(options.masterKeyFile, 0o600);
  await chmod(options.vaultPath, 0o755);
  await assert.rejects(store.read(receipt), MaterialCustodyUnavailableError);
  await chmod(options.vaultPath, 0o700);
  const ciphertext = join(options.vaultPath, `${receipt.resourceId.slice(2)}.json`);
  await chmod(ciphertext, 0o644);
  await assert.rejects(store.read(receipt), MaterialCustodyUnavailableError);
  await chmod(ciphertext, 0o600);
  assert.equal((await store.read(receipt)).payload.toString(), 'Synthetic recoverable statement');
});

test('the host root confines Vault and key paths, rejects symlink escapes and overrides inherited environment', async t => {
  const options = await fixture(), outside = await fixture();
  t.after(() => Promise.all([options, outside].map(f => rm(f.rootDirectory, { recursive: true, force: true }))));
  const outsideVault = new LocalMaterialCustody({ ...options, vaultPath: outside.vaultPath });
  await assert.rejects(outsideVault.stage(id(2), id(3), Buffer.from('Never written outside root'), {}), MaterialCustodyUnavailableError);
  await assert.rejects(stat(outside.vaultPath), { code: 'ENOENT' });
  const store = new LocalMaterialCustody(options);
  const receipt = await store.stage(id(2), id(3), Buffer.from('Synthetic confined statement'), { rootDirectory: outside.rootDirectory });
  await assert.rejects(new LocalMaterialCustody({ ...options, masterKeyFile: outside.masterKeyFile }).read(receipt), MaterialCustodyUnavailableError);
  await assert.rejects(new LocalMaterialCustody({ ...options, vaultPath: '../outside-vault' })
    .stage(id(2), id(3), Buffer.from('Never written through traversal'), {}), MaterialCustodyUnavailableError);
  const linked = join(options.rootDirectory, 'linked');
  await symlink(outside.rootDirectory, linked);
  await assert.rejects(new LocalMaterialCustody({ ...options, vaultPath: join(linked, 'vault') })
    .stage(id(2), id(3), Buffer.from('Never written through symlink'), {}), MaterialCustodyUnavailableError);
  const inherited = process.env.AVA_CUSTODY_ROOT;
  try {
    process.env.AVA_CUSTODY_ROOT = outside.rootDirectory;
    assert.equal((await store.read(receipt)).payload.toString(), 'Synthetic confined statement');
  } finally {
    if (inherited === undefined) delete process.env.AVA_CUSTODY_ROOT;
    else process.env.AVA_CUSTODY_ROOT = inherited;
  }
});

test('the default host root is captured from cwd and accepts relative data paths', async t => {
  const options = await fixture();
  t.after(() => rm(options.rootDirectory, { recursive: true, force: true }));
  const cwd = process.cwd();
  let store: LocalMaterialCustody;
  try {
    process.chdir(options.rootDirectory);
    store = new LocalMaterialCustody({ appId: id(1), vaultPath: 'vault', masterKeyFile: 'master.key', pythonPath });
  } finally { process.chdir(cwd); }
  const receipt = await store.stage(id(2), id(3), Buffer.from('Synthetic cwd-scoped statement'), {});
  assert.equal((await store.read(receipt)).payload.toString(), 'Synthetic cwd-scoped statement');
  await assert.rejects(store.stage(id(2), id(3), Buffer.alloc(2 * 1024 * 1024 + 1), {}), MaterialCustodyUnavailableError);
  assert.equal((await store.read(receipt)).payload.toString(), 'Synthetic cwd-scoped statement');
});
