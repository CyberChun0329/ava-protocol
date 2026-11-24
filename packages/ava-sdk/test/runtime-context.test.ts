import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, type Hex } from 'viem';
import type { QueryHealth } from '../src/service-types.ts';
import { AvaRuntimeError, readRuntimeContext } from '../src/runtime-context.ts';

const hash = (byte: string): Hex => `0x${byte.repeat(64)}`;
const genesis = hash('1'), indexed = hash('2'), head = hash('3');
function fixture() {
  const state = { rpcChain: 31337, head: 10n, genesis, indexed, status: 'synced' as QueryHealth['status'],
    previous: hash('5'), relayChain: 31337, relayGenesis: genesis, relayHeight: '8', relayHash: indexed,
    calls: [] as string[], blocks: [] as string[], onLatest: undefined as (() => void) | undefined };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') return `0x${state.rpcChain.toString(16)}`;
    assert.equal(method, 'eth_getBlockByNumber');
    const [height] = params as [string, boolean];
    state.blocks.push(height);
    if (height === 'latest') { const number = state.head; state.onLatest?.(); return { number: `0x${number.toString(16)}`, hash: head }; }
    if (height === '0x0') return { number: '0x0', hash: state.genesis };
    if (height === '0xb') return { number: '0xb', hash: state.indexed };
    if (height === '0x8') return { number: '0x8', hash: state.indexed };
    if (height === '0x7') return { number: '0x7', hash: state.previous };
    throw new Error('SECRET RPC failure');
  } }, { retryCount: 0 }) });
  const health = (): QueryHealth => ({ status: state.status, chainId: state.relayChain, genesisHash: state.relayGenesis,
    indexedBlock: state.relayHeight, indexedBlockHash: state.relayHash, confirmations: 1 });
  const remote = { health: async () => { state.calls.push('health'); return health(); },
    sync: async () => { state.calls.push('sync'); return health(); } };
  return { state, client, remote };
}

test('returns the shared verified indexed checkpoint, synchronizing by default', async () => {
  const f = fixture();
  assert.deepEqual(await readRuntimeContext(f.client, f.remote, { chainId: 31337 }),
    { chainId: 31337, genesisHash: genesis, checkpoint: { blockNumber: 8n, blockHash: indexed } });
  assert.deepEqual(f.state.calls, ['sync']);
  assert.equal(f.state.blocks.filter(height => height === 'latest').length, 1);
});

test('accepts a relay checkpoint reached after the first head read, including a saved checkpoint', async () => {
  for (const saved of [false, true]) {
    const f = fixture();
    let firstHeadRead!: () => void;
    const firstHead = new Promise<void>(resolve => { firstHeadRead = resolve; });
    f.state.onLatest = firstHeadRead;
    f.remote.sync = async () => {
      await firstHead;
      f.state.head = 11n;
      f.state.relayHeight = '11';
      return { status: 'synced', chainId: 31337, genesisHash: genesis,
        indexedBlock: '11', indexedBlockHash: indexed, confirmations: 1 };
    };
    const checkpoint = { blockNumber: 11n, blockHash: indexed };
    assert.deepEqual((await readRuntimeContext(f.client, f.remote,
      { chainId: 31337, ...(saved ? { checkpoint } : {}) })).checkpoint, checkpoint);
    assert.equal(f.state.blocks.filter(height => height === 'latest').length, 2);
    assert.equal(f.state.blocks.filter(height => height === '0xb').length, 1);
  }
});

const rejectsCode = (code: AvaRuntimeError['code']) => (error: unknown) => {
  assert(error instanceof AvaRuntimeError);
  assert.equal(error.code, code);
  assert.equal(error.cause, undefined);
  assert(!JSON.stringify(error).includes('SECRET'));
  return true;
};

test('matching checkpoints share one fresh lookup while both identities are checked on every invocation', async () => {
  const f = fixture();
  f.state.head = 8n;
  const expected = { chainId: 31337, checkpoint: { blockNumber: 8n, blockHash: indexed } };
  assert.deepEqual((await readRuntimeContext(f.client, f.remote, expected)).checkpoint, expected.checkpoint);
  assert.equal(f.state.blocks.filter(height => height === '0x8').length, 1);
  f.state.indexed = hash('4');
  await assert.rejects(readRuntimeContext(f.client, f.remote, expected), rejectsCode('runtime_mismatch'));
  expected.checkpoint.blockHash = f.state.indexed;
  await assert.rejects(readRuntimeContext(f.client, f.remote, expected), rejectsCode('runtime_mismatch'));
  f.state.relayHash = f.state.indexed;
  assert.deepEqual((await readRuntimeContext(f.client, f.remote, expected)).checkpoint, expected.checkpoint);
  assert.equal(f.state.blocks.filter(height => height === '0x8').length, 4);
});

test('different checkpoint heights retain independent hash checks and recover after a stale saved hash', async () => {
  const f = fixture();
  const expected = { chainId: 31337, checkpoint: { blockNumber: 7n, blockHash: f.state.previous } };
  assert.equal((await readRuntimeContext(f.client, f.remote, expected)).checkpoint.blockHash, indexed);
  assert.deepEqual(f.state.blocks.filter(height => height === '0x7' || height === '0x8'), ['0x7', '0x8']);
  expected.checkpoint.blockHash = hash('4');
  await assert.rejects(readRuntimeContext(f.client, f.remote, expected), rejectsCode('runtime_mismatch'));
  expected.checkpoint.blockHash = f.state.previous;
  assert.equal((await readRuntimeContext(f.client, f.remote, expected)).checkpoint.blockHash, indexed);
});

test('rejects differing chain identity or canonical history and recovers after correction', async () => {
  for (const variant of ['rpc chain', 'relay chain', 'expected genesis', 'relay genesis', 'checkpoint', 'relay fork', 'rewind']) {
    const f = fixture();
    let expected = { chainId: 31337, genesisHash: genesis, checkpoint: { blockNumber: 8n, blockHash: indexed } };
    if (variant === 'rpc chain') f.state.rpcChain = 1;
    if (variant === 'relay chain') f.state.relayChain = 1;
    if (variant === 'expected genesis') expected = { ...expected, genesisHash: hash('4') };
    if (variant === 'relay genesis') f.state.relayGenesis = hash('4');
    if (variant === 'checkpoint') expected = { ...expected, checkpoint: { blockNumber: 8n, blockHash: hash('4') } };
    if (variant === 'relay fork') f.state.relayHash = hash('4');
    if (variant === 'rewind') f.state.head = 7n;
    await assert.rejects(readRuntimeContext(f.client, f.remote, expected), rejectsCode('runtime_mismatch'), variant);
    const legal = fixture();
    assert.equal((await readRuntimeContext(legal.client, legal.remote,
      { chainId: 31337, genesisHash: genesis, checkpoint: { blockNumber: 8n, blockHash: indexed } })).checkpoint.blockHash, indexed);
  }
});

test('unready or malformed relay and RPC failures stay unavailable without leaking details', async () => {
  for (const variant of ['unready', 'missing index', 'malformed hash', 'ahead', 'rpc failure', 'relay failure']) {
    const f = fixture();
    if (variant === 'unready') f.state.status = 'unavailable';
    if (variant === 'missing index') f.state.relayHeight = '';
    if (variant === 'malformed hash') f.state.relayHash = '0x01';
    if (variant === 'ahead') f.state.relayHeight = '11';
    if (variant === 'rpc failure') f.state.relayHeight = '9';
    if (variant === 'relay failure') f.remote.sync = async () => { throw new Error('SECRET relay failure'); };
    await assert.rejects(readRuntimeContext(f.client, f.remote, { chainId: 31337 }), rejectsCode('runtime_unavailable'), variant);
  }
});

test('health reports an index behind the saved checkpoint; synchronization can recover', async () => {
  const f = fixture();
  f.state.relayHeight = '7';
  const expected = { chainId: 31337, checkpoint: { blockNumber: 8n, blockHash: indexed } };
  await assert.rejects(readRuntimeContext(f.client, f.remote, expected, { synchronize: false }), rejectsCode('runtime_unavailable'));
  f.remote.sync = async () => { f.state.calls.push('sync'); f.state.relayHeight = '8';
    return { status: 'synced', chainId: 31337, genesisHash: genesis, indexedBlock: '8', indexedBlockHash: indexed, confirmations: 1 }; };
  assert.deepEqual((await readRuntimeContext(f.client, f.remote, expected)).checkpoint, expected.checkpoint);
  assert.deepEqual(f.state.calls, ['health', 'sync']);
});

test('captures expected identity and checkpoint before asynchronous reads', async () => {
  const f = fixture();
  const expected = { chainId: 31337, genesisHash: genesis, checkpoint: { blockNumber: 8n, blockHash: indexed } };
  const pending = readRuntimeContext(f.client, f.remote, expected);
  expected.chainId = 1;
  expected.checkpoint.blockHash = hash('4');
  assert.deepEqual(await pending, { chainId: 31337, genesisHash: genesis,
    checkpoint: { blockNumber: 8n, blockHash: indexed } });
});
