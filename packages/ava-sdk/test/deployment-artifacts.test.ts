import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { type Hex, type PublicClient } from 'viem';
import { exportPublicDeployment, foundryArtifactLoader } from '../src/deployment.js';
import { AvaReceiptError } from '../src/receipts.js';

test('loads named contracts from independent Foundry output and rejects ambiguous and invalid names', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'ava-artifacts-'));
  try {
    await mkdir(join(dir, 'Bindings.sol'));
    await writeFile(join(dir, 'Bindings.sol', 'Policy.json'), JSON.stringify({ abi: [], bytecode: '0x01' }));
    const load = foundryArtifactLoader(dir);
    assert.deepEqual(await load('Policy'), { abi: [], bytecode: '0x01' });
    await assert.rejects(load('../Policy'), /Invalid contract name/);
    await mkdir(join(dir, 'Other.sol'));
    await writeFile(join(dir, 'Other.sol', 'Policy.json'), JSON.stringify({ abi: [] }));
    await assert.rejects(foundryArtifactLoader(dir)('Policy'), /Ambiguous/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

const hex = (n: number, bytes: number) => `0x${n.toString(16).padStart(bytes * 2, '0')}` as Hex;
const names = ['AVAApplicationRegistry', 'AVAIdentityRegistry', 'AVAAuthorityMatrix', 'AVACoreRulePackageRegistry',
  'AVADisclosurePolicyRegistry', 'AVAEvidenceRegistry', 'AVAGovernanceKernel', 'AVARequestAllocation', 'AVAChallengeExtension'];

test('verified deployment export rejects wrong associations and ordering without changing offline output', async () => {
  const from = hex(1, 20), blockHash = hex(10, 32), headHash = hex(12, 32);
  const transactions = names.map((contractName, index) => ({ hash: hex(index + 1, 32), transactionType: 'CREATE', contractName,
    contractAddress: hex(index + 30, 20), transaction: { from, input: hex(index + 10, 1), nonce: hex(index, 1), chainId: '0x7a69' } }));
  const broadcasts = { chain: 31337, transactions, receipts: transactions.map(tx => ({ transactionHash: tx.hash, status: '0x1', logs: [] })) };
  let wrongInput = true, reverted = false, orphaned = false, wrongBlockOrder = false, replacedHead = false;
  const locate = (hash: Hex) => transactions.findIndex(tx => tx.hash === hash);
  const client = {
    getChainId: async () => 31337,
    getBlock: async ({ blockNumber }: { blockNumber?: bigint }) => ({
      number: blockNumber ?? 12n,
      hash: blockNumber === 10n ? (orphaned ? hex(19, 32) : blockHash)
        : blockNumber === 12n && replacedHead ? hex(20, 32) : headHash,
      timestamp: 10n,
      transactions: blockNumber === 10n ? (wrongBlockOrder ? [...transactions].reverse() : transactions).map(tx => tx.hash) : [],
    }),
    getTransaction: async ({ hash }: { hash: Hex }) => ({ hash, blockHash, blockNumber: 10n, transactionIndex: locate(hash),
      from, to: null, value: 0n, nonce: locate(hash), chainId: 31337,
      input: wrongInput && locate(hash) === 0 ? '0x1234' : transactions[locate(hash)].transaction.input }),
    getTransactionReceipt: async ({ hash }: { hash: Hex }) => ({ transactionHash: hash, blockHash, blockNumber: 10n,
      transactionIndex: locate(hash), from, to: null, status: reverted ? 'reverted' : 'success',
      contractAddress: transactions[locate(hash)].contractAddress, logs: [] }),
    getCode: async () => '0x6000',
  } as unknown as PublicClient;
  const options = { broadcasts, artifact: async () => ({ abi: [] }), allowCoreOnly: true };
  const live = { ...options, verification: { client, confirmations: 3 } };
  const code = (wanted: AvaReceiptError['code']) => (error: unknown) => error instanceof AvaReceiptError && error.code === wanted;
  const offline = await exportPublicDeployment(options);
  await assert.rejects(exportPublicDeployment({ ...options, verification: false as never }), code('invalid_request'));
  const incomplete = { ...broadcasts, transactions: [{ ...transactions[0], transaction: undefined }, ...transactions.slice(1)] };
  await assert.rejects(exportPublicDeployment({ ...live, broadcasts: incomplete as unknown as typeof broadcasts }),
    code('invalid_request'));
  await assert.rejects(exportPublicDeployment({ ...live, broadcasts: { ...broadcasts, pending: ['pending'] } }),
    code('invalid_request'));
  await assert.rejects(exportPublicDeployment({ ...live, broadcasts: [broadcasts, { ...broadcasts, chain: 1 }] }),
    code('chain_mismatch'));
  await assert.rejects(exportPublicDeployment(live), code('receipt_mismatch'));
  wrongInput = false;
  assert.deepEqual(await exportPublicDeployment(live), offline);
  wrongBlockOrder = true;
  await assert.rejects(exportPublicDeployment(live), code('receipt_mismatch'));
  wrongBlockOrder = false;
  for (const override of [{ from: hex(2, 20) }, { nonce: '0x2' }, { value: '0x1' }, { to: hex(3, 20) }]) {
    const changed = { ...transactions[0], transaction: { ...transactions[0].transaction, ...override } };
    await assert.rejects(exportPublicDeployment({ ...live, broadcasts: { ...broadcasts, transactions: [changed, ...transactions.slice(1)] } }),
      code('receipt_mismatch'));
  }
  const wrongAddress = { ...transactions[0], contractAddress: hex(33, 20) };
  await assert.rejects(exportPublicDeployment({ ...live, broadcasts: { ...broadcasts, transactions: [wrongAddress, ...transactions.slice(1)] } }),
    code('receipt_mismatch'));
  await assert.rejects(exportPublicDeployment({ ...live, verification: { client, confirmations: 4 } }), code('not_confirmed'));
  await assert.rejects(exportPublicDeployment({ ...live, broadcasts: { ...broadcasts, transactions: [...transactions].reverse() } }),
    code('receipt_mismatch'));
  reverted = true;
  await assert.rejects(exportPublicDeployment(live), code('reverted'));
  reverted = false;
  orphaned = true;
  await assert.rejects(exportPublicDeployment(live), code('orphaned'));
  orphaned = false;
  replacedHead = true;
  await assert.rejects(exportPublicDeployment(live), code('orphaned'));
});
