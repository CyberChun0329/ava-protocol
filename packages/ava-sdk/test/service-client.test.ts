import assert from 'node:assert/strict';
import test from 'node:test';
import { createServer } from 'node:http';
import { once } from 'node:events';
import type { AddressInfo } from 'node:net';
import { AvaServiceClient, AvaServiceError } from '../src/index.ts';
import type { JsonWire, QueryHealth, QueryEvent, TransactionRecord, ServicePage,
  GovernedObjectWire, RecognitionWire, RequestWire, CorrectionCaseWire } from '../src/index.ts';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
type HealthResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['health']>>, QueryHealth>>;
type SyncResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['sync']>>, QueryHealth>>;
type EventsResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['events']>>, ServicePage<QueryEvent>>>;
type ObjectsResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['objects']>>, ServicePage<GovernedObjectWire>>>;
type RecognitionsResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['recognitions']>>, ServicePage<RecognitionWire>>>;
type RequestsResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['requests']>>, ServicePage<RequestWire>>>;
type CorrectionsResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['corrections']>>, ServicePage<CorrectionCaseWire>>>;
type SubmitResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['submit']>>, TransactionRecord>>;
type TransactionResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['transaction']>>, TransactionRecord>>;
type RawResult = Assert<Equal<Awaited<ReturnType<AvaServiceClient['call']>>, unknown>>;
type RequestId = Assert<Equal<RequestWire['record']['id'], `${bigint}`>>;
type CorrectionOrigins = Assert<Equal<NonNullable<CorrectionCaseWire['originRecord']>['family'], 'source' | 'request' | 'procedure'>>;

test('service redirects never forward credentials or calls and a direct healthy request still works', async () => {
  let redirect = true, forwarded = 0;
  const server = createServer((request, response) => {
    if (request.url === '/forwarded') forwarded++;
    if (redirect && request.url !== '/forwarded') {
      response.writeHead(307, { location: '/forwarded' }); response.end();
    } else {
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ status: 'synced', confirmations: 1 }));
    }
  });
  server.listen(0, '127.0.0.1'); await once(server, 'listening');
  const client = new AvaServiceClient(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, 'private-credential');
  try {
    await assert.rejects(client.health(), error => error instanceof AvaServiceError
      && error.kind === 'transport' && !JSON.stringify(error).includes('private-credential'));
    assert.equal(forwarded, 0);
    redirect = false;
    assert.deepEqual(await client.health(), { status: 'synced', confirmations: 1 });
  } finally { await new Promise<void>(resolve => server.close(() => resolve())); }
});

// Compile-time contract checks: JSON wire integers differ from native contract reads.
const wireExample: JsonWire<{ id: bigint; nested: readonly [bigint, { amount: bigint | null }] }> = {
  id: '9007199254740993', nested: ['2', { amount: null }],
};
// @ts-expect-error Wire integers are strings, never native bigint.
const nativeWireId: JsonWire<bigint> = 1n;
// @ts-expect-error Query status does not promise a transaction outcome.
const transactionAsHealth: QueryHealth['status'] = 'confirmed';
// @ts-expect-error Confirmed and reverted remain distinct transaction statuses.
const unknownTransactionStatus: TransactionRecord['status'] = 'succeeded';
// @ts-expect-error A list of objects contains the raw governed object, not recognition state.
type ObjectState = GovernedObjectWire['state'];

test('successful pages retain their own snapshot and raw JSON wire records', async t => {
  const client = new AvaServiceClient('http://localhost:3000');
  t.mock.method(globalThis, 'fetch', async () => Response.json({
    asOf: { status: 'not_synced', confirmations: 2 }, items: [],
  }));
  assert.deepEqual(await client.objects('0x01'), {
    asOf: { status: 'not_synced', confirmations: 2 }, items: [],
  });
  t.mock.restoreAll();

  t.mock.method(globalThis, 'fetch', async (url: URL) => {
    assert.equal(url.pathname, '/v1/events');
    assert.equal(url.searchParams.get('after'), 'opaque+cursor/=');
    return Response.json({ asOf: { status: 'synced', confirmations: 2, indexedBlock: '12',
      indexedBlockHash: '0x1234' }, items: [{ source: 'custom', address: '0xabcd', event: 'ApplicationEvent',
      args: { value: '9007199254740993', custom: { enabled: true } }, blockNumber: '12',
      blockHash: '0x1234', parentHash: '0x1122', transactionHash: '0x3344', logIndex: 3 }], nextCursor: 'next' });
  });
  const page = await client.events('after=opaque%2Bcursor%2F%3D');
  assert.equal(page.asOf.indexedBlock, '12');
  assert.equal(page.items[0]?.args.value, '9007199254740993');
  assert.deepEqual(page.items[0]?.args.custom, { enabled: true });
  assert.equal(page.nextCursor, 'next');
});

test('HTTP failures retain the service code and status without exposing request secrets', async t => {
  const cases = [
    [403, 'local_host_required'],
    [401, 'bearer_token_required'],
    [400, 'invalid_request'],
    [400, 'invalid_cursor'],
    [400, 'invalid_transaction'],
    [409, 'transaction_conflict'],
    [404, 'transaction_not_found'],
    [503, 'chain_or_query_unavailable'],
  ] as const;
  for (const [status, code] of cases) {
    t.mock.method(globalThis, 'fetch', async () => Response.json({ error: code }, { status }));
    const client = new AvaServiceClient('http://localhost:3000', 'private-test-token');
    await assert.rejects(client.submit('operation', '0xabcd'), error => {
      assert.ok(error instanceof AvaServiceError);
      assert.equal(error.kind, 'http');
      assert.equal(error.status, status);
      assert.equal(error.code, code);
      assert.match(error.message, new RegExp(String(status)));
      assert.doesNotMatch(JSON.stringify(error), /private-test-token|0xabcd/);
      return true;
    });
    t.mock.restoreAll();
  }
});

test('unrecognized HTTP error bodies are discarded and a later known service rejection remains actionable', async t => {
  const client = new AvaServiceClient('http://localhost:3000', 'private-test-token');
  for (const error of ['Bearer private-test-token; transaction 0xabcdef', 'private_provider_credential']) {
    t.mock.method(globalThis, 'fetch', async () => Response.json({ error }, { status: 503 }));
    await assert.rejects(client.submit('operation', '0xabcdef'), failure => {
      assert(failure instanceof AvaServiceError);
      assert.equal(failure.code, 'http_error');
      assert.equal(failure.status, 503);
      assert.doesNotMatch(`${failure.message} ${JSON.stringify(failure)}`, /private|abcdef|Bearer/);
      return true;
    });
  }
  t.mock.method(globalThis, 'fetch', async () => Response.json({ error: 'work_queue_full' }, { status: 429 }));
  await assert.rejects(client.submit('operation', '0xabcdef'), failure =>
    failure instanceof AvaServiceError && failure.code === 'work_queue_full' && failure.status === 429);
});

test('network failures expose a structured transport error without retaining the provider cause', async t => {
  t.mock.method(globalThis, 'fetch', async () => {
    throw new Error('connection refused at http://private-provider/?token=credential');
  });
  await assert.rejects(new AvaServiceClient('http://localhost:3000').sync(), error => {
    assert.ok(error instanceof AvaServiceError);
    assert.equal(error.kind, 'transport');
    assert.equal(error.code, 'transport_error');
    assert.equal(error.status, undefined);
    assert.equal(error.cause, undefined);
    assert.doesNotMatch(`${error.message} ${JSON.stringify(error)}`, /private-provider|credential|refused/);
    return true;
  });
});

test('non-JSON replies distinguish HTTP failure from malformed success', async t => {
  for (const [status, kind, code] of [
    [502, 'http', 'http_error'],
    [200, 'malformed_response', 'malformed_response'],
  ] as const) {
    t.mock.method(globalThis, 'fetch', async () => new Response('<html>upstream unavailable</html>', { status }));
    await assert.rejects(new AvaServiceClient('http://localhost:3000').health(), error => {
      assert.ok(error instanceof AvaServiceError);
      assert.equal(error.kind, kind);
      assert.equal(error.status, status);
      assert.equal(error.code, code);
      assert.doesNotMatch(error.message, /<html>|upstream/);
      return true;
    });
    t.mock.restoreAll();
  }
});

test('body transport failure keeps the known status without being labelled malformed JSON', async t => {
  t.mock.method(globalThis, 'fetch', async () => new Response(new ReadableStream({
    start(controller) { controller.error(new Error('SECRET-body-network-failure')); },
  }), { status: 200 }));
  await assert.rejects(new AvaServiceClient('http://localhost:3000').health(), error => {
    assert(error instanceof AvaServiceError);
    assert.equal(error.kind, 'transport');
    assert.equal(error.status, 200);
    assert.equal(error.code, 'transport_error');
    assert.equal(error.cause, undefined);
    assert.equal(JSON.stringify(error).includes('SECRET'), false);
    return true;
  });
});

test('a pre-aborted request is cancelled without sending or exposing its reason', async t => {
  let sent = false;
  t.mock.method(globalThis, 'fetch', async () => { sent = true; return Response.json({}); });
  const controller = new AbortController();
  controller.abort(new Error('SYNTHETIC_PRIVATE_ABORT_REASON'));
  await assert.rejects(new AvaServiceClient('http://localhost:3000').health({ signal: controller.signal }), error => {
    assert(error instanceof AvaServiceError);
    assert.equal(error.kind, 'cancelled');
    assert.equal(error.code, 'request_cancelled');
    assert.equal(error.cause, undefined);
    assert(!JSON.stringify(error).includes('SYNTHETIC_PRIVATE'));
    return true;
  });
  assert.equal(sent, false);
});

test('cancellation interrupts response body reading, retains known status and permits a later query', async t => {
  const controller = new AbortController();
  let started!: () => void;
  const reading = new Promise<void>(resolve => { started = resolve; });
  t.mock.method(globalThis, 'fetch', async (_url: unknown, options: RequestInit) => new Response(new ReadableStream({
    start(stream) {
      options.signal!.addEventListener('abort', () => stream.error(options.signal!.reason), { once: true });
      started();
    },
  }), { status: 200 }));
  const service = new AvaServiceClient('http://localhost:3000');
  const pending = service.health({ signal: controller.signal });
  await reading;
  controller.abort(new Error('SYNTHETIC_PRIVATE_BODY_REASON'));
  await assert.rejects(pending, error => error instanceof AvaServiceError && error.kind === 'cancelled'
    && error.code === 'request_cancelled' && error.status === 200 && error.cause === undefined);
  t.mock.method(globalThis, 'fetch', async () => Response.json({ status: 'synced', confirmations: 1 }));
  assert.equal((await service.health()).status, 'synced');
});

test('every HTTP entrypoint forwards the caller signal without putting it in query parameters', async t => {
  const controller = new AbortController(), options = { signal: controller.signal };
  t.mock.method(globalThis, 'fetch', async (url: URL, request: RequestInit) => {
    assert.equal(request.signal, controller.signal);
    assert.equal(url.searchParams.has('signal'), false);
    return Response.json(url.pathname === '/v1/transactions'
      ? { key: 'operation', hash: '0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a' }
      : {});
  });
  const service = new AvaServiceClient('http://localhost:3000');
  await service.call('/health', undefined, options);
  await service.submit('operation', '0x00', options);
  await service.transaction('operation', options);
  await service.sync(options);
  await service.health(options);
  await service.events('', options);
  for (const kind of ['objects', 'recognitions', 'requests', 'corrections'] as const) {
    await service[kind]('0x01', { ...options, limit: 1, after: 'opaque' });
  }
});

test('a caller deadline is distinguishable without exposing its arbitrary timeout message', async () => {
  const controller = new AbortController();
  controller.abort(new DOMException('SYNTHETIC_PRIVATE_TIMEOUT', 'TimeoutError'));
  await assert.rejects(new AvaServiceClient('http://localhost:3000').health({ signal: controller.signal }), error =>
    error instanceof AvaServiceError && error.kind === 'cancelled' && error.code === 'request_timeout'
      && !String(error).includes('SYNTHETIC_PRIVATE'));
});

test('typed cross-event scalar pages reject wrong asset and source rows then allow the next legal page', async t => {
  const source = 'ResearchRegistry', address = `0x${'11'.repeat(20)}` as const, blockHash = `0x${'22'.repeat(32)}` as const;
  const query = { source, expectedSourceAddress: address, arg: { name: 'assetId', value: '1' }, limit: 2,
    at: { blockNumber: '3', blockHash } };
  const rows = [
    { source, address, event: 'Created', args: { assetId: '1' }, blockNumber: '2', blockHash,
      parentHash: blockHash, transactionHash: blockHash, logIndex: 1 },
    { source, address, event: 'Updated', args: { assetId: '1' }, blockNumber: '2', blockHash,
      parentHash: blockHash, transactionHash: blockHash, logIndex: 2 },
  ];
  const page = { asOf: { status: 'synced', confirmations: 1, indexedBlock: '3', indexedBlockHash: blockHash }, items: rows };
  let result: unknown = page;
  t.mock.method(globalThis, 'fetch', async (url: URL) => {
    assert.equal(url.searchParams.has('event'), false);
    assert.equal(url.searchParams.get('argName'), 'assetId');
    assert.equal(url.searchParams.get('argValue'), '1');
    return Response.json(result);
  });
  const client = new AvaServiceClient('http://localhost:3000');
  assert.deepEqual((await client.events(query)).items.map(item => item.event), ['Created', 'Updated']);
  for (const changed of [{ ...rows[0], args: { assetId: '2' } }, { ...rows[0], source: 'OtherRegistry' },
    { ...rows[0], address: `0x${'33'.repeat(20)}` }]) {
    result = { ...page, items: [changed] };
    await assert.rejects(client.events(query), error => error instanceof AvaServiceError && error.kind === 'malformed_response');
  }
  result = page;
  assert.equal((await client.events(query)).items.length, 2);
});
