import assert from 'node:assert/strict';
import test from 'node:test';
import { AvaServiceClient, AvaServiceError, type TransactionRecord } from '../src/index.ts';

const identity = { key: 'operation/a b', hash: `0x${'ab'.repeat(32)}` as const };
const record = (status: TransactionRecord['status']): TransactionRecord => ({ ...identity,
  from: '0x1111111111111111111111111111111111111111',
  to: '0x2222222222222222222222222222222222222222', nonce: '7', status,
  confirmations: status === 'confirmed' || status === 'reverted' ? 2 : 0,
  ...(status === 'confirmed' || status === 'reverted'
    ? { blockNumber: '42', blockHash: `0x${'cd'.repeat(32)}` as const } : {}),
  updatedAt: '2026-10-25T00:00:00Z' });

test('observe an existing identity from unknown through pending to confirmed using queries only', async t => {
  const replies = [record('unknown'), record('pending'), record('confirmed')];
  t.mock.method(globalThis, 'fetch', async (url: URL, options: RequestInit) => {
    assert.equal(options.method, 'GET');
    assert.equal(options.body, undefined);
    assert.equal(decodeURIComponent(url.pathname), `/v1/transactions/${identity.key}`);
    assert.ok(replies.length, 'stop querying after confirmation');
    return Response.json(replies.shift());
  });
  const result = await new AvaServiceClient('http://localhost:3000').observeTransaction(identity,
    { timeoutMs: 1000, pollIntervalMs: 1 });
  assert.deepEqual(result, record('confirmed'));
  assert.equal(replies.length, 0);
});

test('cancel an in-flight observation without leaking the reason, then query and observe the same identity', async t => {
  const controller = new AbortController();
  let started!: () => void;
  const reading = new Promise<void>(resolve => { started = resolve; });
  t.mock.method(globalThis, 'fetch', async (_url: URL, options: RequestInit) => {
    started();
    return await new Promise<Response>((_resolve, reject) => {
      if (!options.signal) return reject(new Error('fixture requires a cancellable HTTP request'));
      options.signal.addEventListener('abort', () => reject(options.signal!.reason), { once: true });
    });
  });
  const service = new AvaServiceClient('http://localhost:3000');
  const pending = service.observeTransaction(identity, { signal: controller.signal });
  await reading;
  controller.abort(new Error('PRIVATE_CANCELLATION_REASON'));
  await assert.rejects(pending, error => error instanceof AvaServiceError && error.kind === 'cancelled'
    && error.code === 'observation_cancelled' && !JSON.stringify(error).includes('PRIVATE'));
  t.mock.method(globalThis, 'fetch', async (_url: URL, options: RequestInit) => {
    assert.equal(options.method, 'GET');
    return Response.json(record('confirmed'));
  });
  assert.equal((await service.transaction(identity.key)).hash, identity.hash);
  assert.deepEqual(await service.observeTransaction(identity), record('confirmed'));
});

test('a deadline interrupts a response body and a later observation completes the original identity', { timeout: 500 }, async t => {
  t.mock.method(globalThis, 'fetch', async (_url: URL, options: RequestInit) => new Response(new ReadableStream({
    start(stream) { options.signal!.addEventListener('abort', () => stream.error(options.signal!.reason), { once: true }); },
  })));
  const service = new AvaServiceClient('http://localhost:3000');
  await assert.rejects(service.observeTransaction(identity, { timeoutMs: 10 }), error =>
    error instanceof AvaServiceError && error.kind === 'cancelled' && error.code === 'observation_timeout');
  t.mock.method(globalThis, 'fetch', async () => Response.json(record('confirmed')));
  assert.deepEqual(await service.observeTransaction(identity), record('confirmed'));
});

test('capture caller identity and reject a different response identity before accepting any status', async t => {
  const input = { ...identity };
  t.mock.method(globalThis, 'fetch', async () => {
    input.hash = `0x${'cd'.repeat(32)}`;
    return Response.json({ ...record('confirmed'), hash: input.hash });
  });
  const service = new AvaServiceClient('http://localhost:3000');
  await assert.rejects(service.observeTransaction(input), error => error instanceof AvaServiceError
    && error.kind === 'malformed_response' && error.code === 'transaction_identity_mismatch');
  t.mock.method(globalThis, 'fetch', async () => Response.json(record('confirmed')));
  assert.deepEqual(await service.observeTransaction(identity), record('confirmed'));
});

test('immediate stops and invalid timer configuration send no request', async t => {
  let queried = false;
  t.mock.method(globalThis, 'fetch', async () => { queried = true; return Response.json(record('confirmed')); });
  const service = new AvaServiceClient('http://localhost:3000');
  const controller = new AbortController();
  controller.abort(new Error('PRIVATE_ABORT_REASON'));
  await assert.rejects(service.observeTransaction(identity, { signal: controller.signal }), error =>
    error instanceof AvaServiceError && error.code === 'observation_cancelled');
  await assert.rejects(service.observeTransaction(identity, { timeoutMs: 0 }), error =>
    error instanceof AvaServiceError && error.code === 'observation_timeout');
  for (const options of [{ timeoutMs: -1 }, { timeoutMs: Infinity }, { timeoutMs: 2 ** 31 },
    { timeoutMs: 0.5 }, { pollIntervalMs: 0 }, { pollIntervalMs: NaN }, { pollIntervalMs: 2 ** 31 }]) {
    await assert.rejects(service.observeTransaction(identity, options), RangeError);
  }
  await assert.rejects(service.observeTransaction({ ...identity, hash: '0x00' }), TypeError);
  await assert.rejects(service.observeTransaction({ ...identity, key: '' }), TypeError);
  assert.equal(queried, false);
});

test('reverted is a terminal record, malformed status is refused, and a read fault never triggers automatic retry', async t => {
  const service = new AvaServiceClient('http://localhost:3000');
  t.mock.method(globalThis, 'fetch', async () => Response.json(record('reverted')));
  assert.deepEqual(await service.observeTransaction(identity), record('reverted'));
  let attempts = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    attempts++;
    return Response.json({ ...record('confirmed'), status: 'succeeded' });
  });
  await assert.rejects(service.observeTransaction(identity, { timeoutMs: 10, pollIntervalMs: 1 }), error =>
    error instanceof AvaServiceError && error.kind === 'malformed_response' && error.code === 'malformed_response');
  assert.equal(attempts, 1);
  attempts = 0;
  t.mock.method(globalThis, 'fetch', async () => { attempts++; throw new Error('PRIVATE_PROVIDER_DETAIL'); });
  await assert.rejects(service.observeTransaction(identity), error => error instanceof AvaServiceError
    && error.kind === 'transport' && error.code === 'transport_error' && !JSON.stringify(error).includes('PRIVATE'));
  assert.equal(attempts, 1);
  t.mock.method(globalThis, 'fetch', async () => Response.json(record('confirmed')));
  assert.deepEqual(await service.observeTransaction(identity), record('confirmed'));
});

test('cancellation and deadline interrupt a long poll delay; another observer remains independent', { timeout: 1000 }, async t => {
  const service = new AvaServiceClient('http://localhost:3000');
  for (const interruption of ['cancel', 'timeout'] as const) {
    const controller = new AbortController();
    let reads = 0;
    t.mock.method(globalThis, 'fetch', async () => { reads++; return Response.json(record('pending')); });
    const pending = service.observeTransaction(identity, { signal: controller.signal,
      pollIntervalMs: 10_000, timeoutMs: interruption === 'cancel' ? 500 : 10 });
    const cancel = interruption === 'cancel' ? setTimeout(() => controller.abort(new Error('PRIVATE')), 10) : undefined;
    await assert.rejects(pending, error => error instanceof AvaServiceError
      && error.code === (interruption === 'cancel' ? 'observation_cancelled' : 'observation_timeout'));
    clearTimeout(cancel);
    assert.equal(reads, 1);
  }
  const controller = new AbortController();
  const alreadyCancelled = service.observeTransaction(identity, { signal: controller.signal });
  controller.abort();
  t.mock.method(globalThis, 'fetch', async () => Response.json(record('confirmed')));
  const unaffected = service.observeTransaction(identity);
  await assert.rejects(alreadyCancelled, error => error instanceof AvaServiceError && error.code === 'observation_cancelled');
  assert.deepEqual(await unaffected, record('confirmed'));
});

test('caller TimeoutError signals are timeouts, and a mismatched key is refused even while pending', async t => {
  const service = new AvaServiceClient('http://localhost:3000');
  const controller = new AbortController();
  controller.abort(new DOMException('PRIVATE_TIMEOUT_REASON', 'TimeoutError'));
  await assert.rejects(service.observeTransaction(identity, { signal: controller.signal }), error =>
    error instanceof AvaServiceError && error.code === 'observation_timeout' && !JSON.stringify(error).includes('PRIVATE'));
  t.mock.method(globalThis, 'fetch', async () => Response.json({ ...record('pending'), key: 'foreign-key' }));
  await assert.rejects(service.observeTransaction(identity), error => error instanceof AvaServiceError
    && error.code === 'transaction_identity_mismatch');
  t.mock.method(globalThis, 'fetch', async () => Response.json({ ...record('confirmed'), hash: identity.hash.toUpperCase() }));
  assert.equal((await service.observeTransaction(identity)).status, 'confirmed');
});

test('incomplete or malformed records cannot claim confirmation; a later complete original record still works', async t => {
  const service = new AvaServiceClient('http://localhost:3000');
  const malformed = [
    { ...identity, status: 'confirmed' },
    { ...record('confirmed'), from: 123 }, { ...record('confirmed'), to: '0x00' },
    { ...record('confirmed'), nonce: 7 }, { ...record('confirmed'), nonce: '-1' },
    { ...record('confirmed'), confirmations: '2' }, { ...record('confirmed'), confirmations: -1 },
    { ...record('confirmed'), confirmations: 0 }, { ...record('reverted'), confirmations: 0 },
    { ...record('confirmed'), blockNumber: undefined, blockHash: undefined },
    { ...record('reverted'), blockNumber: undefined, blockHash: undefined },
    { ...record('pending'), blockNumber: '42' },
    { ...record('confirmed'), updatedAt: null }, { ...record('confirmed'), blockNumber: 3 },
    { ...record('confirmed'), blockHash: '0x00' }, { ...record('confirmed'), error: { private: 'PRIVATE' } },
  ];
  for (const response of malformed) {
    t.mock.method(globalThis, 'fetch', async () => Response.json(response));
    await assert.rejects(service.observeTransaction(identity), error => error instanceof AvaServiceError
      && error.kind === 'malformed_response' && error.code === 'malformed_response'
      && !JSON.stringify(error).includes('PRIVATE'));
  }
  t.mock.method(globalThis, 'fetch', async () => Response.json(record('confirmed')));
  assert.deepEqual(await service.observeTransaction(identity), record('confirmed'));
});
