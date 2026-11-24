import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import { toHex } from 'viem';
import { AvaServiceClient, AvaServiceError, type ServiceEventQuery, type ServicePage, type QueryEvent } from '../src/index.ts';

const address = toHex(100n, { size: 20 }), hash = toHex(3n, { size: 32 });
const page = (): ServicePage<QueryEvent> => ({ asOf: { status: 'synced', confirmations: 2, startBlock: '1',
  indexedBlock: '3', indexedBlockHash: toHex(4n, { size: 32 }) }, items: [
  { source: 'peerJournal', address, event: 'SubmissionReceived', args: { submissionId: '2' },
    blockNumber: '2', blockHash: hash, parentHash: toHex(2n, { size: 32 }),
    transactionHash: toHex(200n, { size: 32 }), logIndex: 1 },
] });
const filter = (): ServiceEventQuery => ({ source: 'peerJournal', expectedSourceAddress: address,
  event: 'SubmissionReceived', arg: { name: 'submissionId', value: '2' }, order: 'desc', fromBlock: '1',
  before: { blockNumber: '2', logIndex: 2 }, at: { blockNumber: '2', blockHash: hash }, limit: 2 });

test('typed event discovery encodes flat filters and captures nested caller input before awaiting HTTP', async () => {
  let release!: () => void;
  let observed: URL | undefined;
  const responseReady = new Promise<void>(resolve => { release = resolve; });
  const server = createServer(async (request, response) => {
    observed = new URL(request.url!, 'http://localhost');
    await responseReady;
    response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(page()));
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  try {
    const client = new AvaServiceClient(`http://127.0.0.1:${(server.address() as { port: number }).port}`);
    const query = filter();
    const result = client.events(query);
    query.arg!.value = '999'; query.at!.blockNumber = '99'; query.before!.logIndex = 0;
    release();
    assert.deepEqual(await result, page(), 'generic SDK accepts the configured start/confirmation profile');
    assert.equal(observed?.pathname, '/v1/events');
    assert.equal(observed?.searchParams.get('expectedSourceAddress'), address);
    assert.equal(observed?.searchParams.get('argName'), 'submissionId');
    assert.equal(observed?.searchParams.get('argValue'), '2');
    assert.equal(observed?.searchParams.get('beforeBlock'), '2');
    assert.equal(observed?.searchParams.get('beforeLogIndex'), '2');
    assert.equal(observed?.searchParams.get('atBlock'), '2');
    assert.equal(observed?.searchParams.get('atHash'), hash);
    assert.equal(observed?.searchParams.has('arg'), false);
  } finally { release(); await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('typed discovery rejects malformed, wrong-source and snapshot/filter-inconsistent pages as service failures', async t => {
  const client = new AvaServiceClient('http://localhost:3000');
  const changes: [string, (value: any) => unknown][] = [
    ['missing page', () => null],
    ['missing health', value => { delete value.asOf; return value; }],
    ['unavailable snapshot', value => { value.asOf.status = 'unavailable'; return value; }],
    ['invalid confirmations', value => { value.asOf.confirmations = 0; return value; }],
    ['invalid chain identity', value => { value.asOf.chainId = 1.5; return value; }],
    ['invalid health hash', value => { value.asOf.indexedBlockHash = '0x12'; return value; }],
    ['index behind snapshot', value => { value.asOf.indexedBlock = '1'; return value; }],
    ['invalid deployment start', value => { value.asOf.startBlock = '01'; return value; }],
    ['missing indexed hash', value => { delete value.asOf.indexedBlockHash; return value; }],
    ['items is not a list', value => { value.items = {}; return value; }],
    ['wrong named source', value => { value.items[0].source = 'otherJournal'; return value; }],
    ['wrong source address', value => { value.items[0].address = toHex(101n, { size: 20 }); return value; }],
    ['wrong event', value => { value.items[0].event = 'DifferentEvent'; return value; }],
    ['wrong scalar argument', value => { value.items[0].args.submissionId = '3'; return value; }],
    ['non-scalar argument', value => { value.items[0].args.submissionId = {}; return value; }],
    ['bad event hash', value => { value.items[0].transactionHash = '0x1234'; return value; }],
    ['bad log position', value => { value.items[0].logIndex = 1.5; return value; }],
    ['beyond requested snapshot', value => { value.items[0].blockNumber = '3'; return value; }],
    ['wrong canonical snapshot hash', value => { value.items[0].blockHash = toHex(99n, { size: 32 }); return value; }],
    ['inclusive before position', value => { value.items[0].logIndex = 2; return value; }],
    ['before requested lower block', value => { value.items[0].blockNumber = '0'; return value; }],
    ['repeated event position', value => { value.items.push(value.items[0]); return value; }],
    ['malformed cursor', value => { value.nextCursor = 1; return value; }],
  ];
  for (const [name, change] of changes) {
    t.mock.method(globalThis, 'fetch', async () => Response.json(change(page())));
    await assert.rejects(client.events(filter()), error => error instanceof AvaServiceError
      && error.kind === 'malformed_response', name);
    t.mock.restoreAll();
  }
  t.mock.method(globalThis, 'fetch', async () => Response.json(page()));
  assert.deepEqual(await client.events(filter()), page(), 'a legitimate request recovers after malformed responses');
});

test('typed discovery keeps cancellation, transport and HTTP failures as AvaServiceError', async t => {
  const client = new AvaServiceClient('http://localhost:3000');
  const controller = new AbortController(); controller.abort();
  await assert.rejects(client.events(filter(), { signal: controller.signal }), error =>
    error instanceof AvaServiceError && error.kind === 'cancelled');
  t.mock.method(globalThis, 'fetch', async () => { throw new Error('private provider failure'); });
  await assert.rejects(client.events(filter()), error => error instanceof AvaServiceError && error.kind === 'transport');
  t.mock.restoreAll();
  t.mock.method(globalThis, 'fetch', async () => Response.json({ error: 'chain_or_query_unavailable' }, { status: 503 }));
  await assert.rejects(client.events(filter()), error => error instanceof AvaServiceError
    && error.kind === 'http' && error.code === 'chain_or_query_unavailable');
});
