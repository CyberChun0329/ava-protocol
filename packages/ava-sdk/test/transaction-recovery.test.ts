import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, type Address, type Hex } from 'viem';
import { AvaReceiptError, AvaServiceError, submissionFailure, verifyNonceReplacement } from '../src/index.ts';

test('only explicit local relay rejections have known safe codes', () => {
  for (const [status, code] of [[400, 'invalid_request'], [400, 'invalid_transaction'], [409, 'transaction_conflict'],
    [401, 'bearer_token_required'], [403, 'local_host_required'], [429, 'work_queue_full']] as const) {
    assert.deepEqual(submissionFailure(new AvaServiceError('http', code, status)), { status: 'relay-rejected', code });
  }
  for (const error of [new AvaServiceError('http', 'SECRET', 400), new AvaServiceError('http', 'invalid_request', 500),
    new AvaServiceError('transport', 'SECRET'), new AvaServiceError('malformed_response', 'SECRET')]) {
    assert.deepEqual(submissionFailure(error), { status: 'submission-uncertain', code: 'relay_unavailable' });
  }
  assert.equal(submissionFailure(new Error('SECRET')), undefined);
});

const hash = (value: string): Hex => `0x${value.repeat(64)}`;
const originalHash = hash('1'), replacementHash = hash('2'), blockHash = hash('3'), headHash = hash('4');
const account: Address = '0x1111111111111111111111111111111111111111';
const other: Address = '0x2222222222222222222222222222222222222222';
const input = { chainId: 31337, account, nonce: 7, originalHash, replacementHash };
function fixture() {
  const state = { chainId: '0x7a69', receipt: true, transaction: true, from: account, receiptFrom: account,
    nonce: '0x7', txHash: replacementHash, receiptHash: replacementHash, txBlock: blockHash as Hex | null, receiptBlock: blockHash,
    blockNumber: '0x2a', receiptNumber: '0x2a', txIndex: '0x1', receiptIndex: '0x1', canonical: blockHash,
    status: '0x1', headCanonical: headHash, transactions: [originalHash, replacementHash] as Hex[], fail: '', headReads: 0 };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (state.fail === method) throw new Error('SECRET RPC failure');
    if (method === 'eth_chainId') return state.chainId;
    if (method === 'eth_getBlockByNumber') {
      const [number] = params as [string, boolean];
      if (number === 'latest') return { number: '0x2b', hash: headHash, timestamp: '0x1' };
      if (number === '0x2b') { state.headReads++; return { number: '0x2b', hash: state.headCanonical, timestamp: '0x1' }; }
      if (number === '0x2a') return { number: '0x2a', hash: state.canonical, timestamp: '0x1', transactions: state.transactions };
      throw new Error('SECRET unexpected block');
    }
    if (method === 'eth_getTransactionReceipt') return state.receipt ? {
      transactionHash: state.receiptHash, from: state.receiptFrom, to: other, blockHash: state.receiptBlock,
      blockNumber: state.receiptNumber, transactionIndex: state.receiptIndex, status: state.status,
      logs: [], cumulativeGasUsed: '0x5208', gasUsed: '0x5208', effectiveGasPrice: '0x1',
      logsBloom: `0x${'00'.repeat(256)}`, contractAddress: null, type: '0x2',
    } : null;
    if (method === 'eth_getTransactionByHash') return state.transaction ? {
      hash: state.txHash, from: state.from, to: other, nonce: state.nonce, blockHash: state.txBlock,
      blockNumber: state.blockNumber, transactionIndex: state.txIndex, type: '0x2', chainId: state.chainId,
      gas: '0x5208', value: '0x0', input: '0x', maxFeePerGas: '0x2', maxPriorityFeePerGas: '0x1',
    } : null;
    throw new Error(`SECRET unexpected method ${method}`);
  } }, { retryCount: 0 }) });
  return { client, state };
}

test('mined same-actor same-nonce replacement is verified, including a revert', async () => {
  const f = fixture();
  assert.deepEqual(await verifyNonceReplacement(f.client, input), { transactionHash: replacementHash, from: account,
    nonce: 7, blockNumber: 42n, blockHash, status: 'success' });
  f.state.status = '0x0';
  assert.equal((await verifyNonceReplacement(f.client, input)).status, 'reverted');
  assert.equal(f.state.headReads, 2);
});

test('refuses missing, pending, mismatched, orphaned and unavailable evidence then recovers', async () => {
  const cases: [string, (state: ReturnType<typeof fixture>['state']) => void, string][] = [
    ['chain', s => { s.chainId = '0x1'; }, 'chain_mismatch'],
    ['receipt missing', s => { s.receipt = false; }, 'not_mined'],
    ['transaction missing', s => { s.transaction = false; }, 'not_mined'],
    ['pending transaction', s => { s.txBlock = null; }, 'not_mined'],
    ['different actor', s => { s.from = other; }, 'receipt_mismatch'],
    ['receipt actor', s => { s.receiptFrom = other; }, 'receipt_mismatch'],
    ['nonce', s => { s.nonce = '0x8'; }, 'receipt_mismatch'],
    ['tx hash', s => { s.txHash = hash('5'); }, 'receipt_mismatch'],
    ['receipt hash', s => { s.receiptHash = hash('5'); }, 'receipt_mismatch'],
    ['tx block', s => { s.txBlock = hash('5'); }, 'receipt_mismatch'],
    ['block number', s => { s.blockNumber = '0x29'; }, 'receipt_mismatch'],
    ['transaction index', s => { s.txIndex = '0x2'; }, 'receipt_mismatch'],
    ['missing block transaction', s => { s.transactions = [originalHash]; }, 'receipt_mismatch'],
    ['different block transaction', s => { s.transactions = [originalHash, hash('5')]; }, 'receipt_mismatch'],
    ['beyond captured head', s => { s.blockNumber = s.receiptNumber = '0x2c'; }, 'not_confirmed'],
    ['orphan', s => { s.canonical = hash('5'); }, 'orphaned'],
    ['head reorg', s => { s.headCanonical = hash('5'); }, 'rpc_unavailable'],
    ['provider failure', s => { s.fail = 'eth_getTransactionByHash'; }, 'rpc_unavailable'],
    ['invalid status', s => { s.status = '0x2'; }, 'invalid_receipt'],
  ];
  for (const [name, mutate, code] of cases) {
    const f = fixture(); mutate(f.state);
    await assert.rejects(verifyNonceReplacement(f.client, input), error => {
      assert(error instanceof AvaReceiptError, name);
      assert.equal(error.code, code, name);
      assert.equal(error.cause, undefined);
      assert(!String(error).includes('SECRET'));
      return true;
    });
    const repaired = fixture();
    assert.equal((await verifyNonceReplacement(repaired.client, input)).transactionHash, replacementHash, name);
  }
});

test('rejects identical hash and malformed inputs and captures intent before asynchronous reads', async () => {
  const f = fixture();
  for (const bad of [{ ...input, replacementHash: originalHash }, { ...input, nonce: -1 },
    { ...input, replacementHash: '0x12' as Hex }, { ...input, account: '0x12' as Address }]) {
    await assert.rejects(verifyNonceReplacement(f.client, bad), error => error instanceof AvaReceiptError && error.code === 'invalid_request');
  }
  const mutable = { ...input };
  const pending = verifyNonceReplacement(f.client, mutable);
  mutable.account = other;
  mutable.nonce = 10;
  assert.equal((await pending).from, account);
});
