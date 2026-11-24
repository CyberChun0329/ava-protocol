import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AvaServiceClient, AvaServiceError } from '../src/service-client.js';

// Keccak-256 of the fixture's two bytes, ab cd.
const originalHash = '0xdbe576b4818846aa77e82f4ed5fa78f92766b141f282d36703886d196df39322';

test('submission and explicit recovery accept only the original key and signed bytes', async t => {
  const original = { key: 'original:key', hash: originalHash, status: 'unknown' };
  let response = original, requests = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    requests++;
    return Response.json(response);
  });
  const service = new AvaServiceClient('http://localhost:3000');
  for (const send of [service.submit.bind(service), service.recoverSubmit.bind(service)]) {
    for (const mismatched of [{ ...original, key: 'other' }, { ...original, hash: `0x${'11'.repeat(32)}` }]) {
      response = mismatched;
      await assert.rejects(send(original.key, '0xabcd'), error => error instanceof AvaServiceError
        && error.kind === 'malformed_response' && error.code === 'transaction_identity_mismatch');
    }
    response = original;
    assert.deepEqual(await send(original.key, '0xabcd'), original);
  }
  assert.equal(requests, 6);
});

test('explicit recovery posts original bytes at the existing key with bearer and cancellation context', async t => {
  const signal = new AbortController().signal;
  const transaction = { key: 'original:key', hash: originalHash, status: 'unknown' };
  let requests = 0;
  t.mock.method(globalThis, 'fetch', async (url: URL, request: RequestInit) => {
    requests++;
    assert.equal(url.pathname, '/v1/transactions/original%3Akey/recover');
    assert.equal(request.method, 'POST');
    assert.equal(request.signal, signal);
    assert.equal((request.headers as Record<string, string>).authorization, 'Bearer synthetic-local-token');
    assert.equal(request.body, JSON.stringify({ serializedTransaction: '0xabcd' }));
    return Response.json(transaction);
  });
  const result = await new AvaServiceClient('http://localhost:3000', 'synthetic-local-token')
    .recoverSubmit('original:key', '0xabcd', { signal });
  assert.deepEqual(result, transaction);
  assert.equal(requests, 1);
});

test('explicit recovery preserves safe HTTP errors and never retries a failed request', async t => {
  let requests = 0;
  t.mock.method(globalThis, 'fetch', async () => {
    requests++;
    return Response.json({ error: 'transaction_conflict', diagnostic: 'SYNTHETIC_PRIVATE_RESPONSE' }, { status: 409 });
  });
  await assert.rejects(new AvaServiceClient('http://localhost:3000', 'SYNTHETIC_PRIVATE_TOKEN')
    .recoverSubmit('original', '0xabcd'), error => {
    assert(error instanceof AvaServiceError);
    assert.equal(error.kind, 'http');
    assert.equal(error.code, 'transaction_conflict');
    assert.equal(error.status, 409);
    assert.doesNotMatch(`${error} ${JSON.stringify(error)}`, /SYNTHETIC_PRIVATE|0xabcd/);
    return true;
  });
  assert.equal(requests, 1);
});

test('pre-cancelled explicit recovery sends no bytes and exposes no private cancellation reason', async t => {
  let requests = 0;
  t.mock.method(globalThis, 'fetch', async () => { requests++; return Response.json({}); });
  const controller = new AbortController(); controller.abort(new Error('SYNTHETIC_PRIVATE_ABORT'));
  await assert.rejects(new AvaServiceClient('http://localhost:3000').recoverSubmit('original', '0xabcd',
    { signal: controller.signal }), error => error instanceof AvaServiceError
      && error.kind === 'cancelled' && error.code === 'request_cancelled'
      && !`${error} ${JSON.stringify(error)}`.includes('SYNTHETIC_PRIVATE'));
  assert.equal(requests, 0);
});
