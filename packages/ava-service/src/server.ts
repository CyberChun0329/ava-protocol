import Fastify, { type FastifyRequest, type FastifyReply } from 'fastify';
import { timingSafeEqual } from 'node:crypto';
import { chmod, mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';
import type { Abi, Address, Hex, PublicClient } from 'viem';
import { AvaSdk, AvaExtensions, avaAbis, avaExtensionAbis, correctionsAbi, executionAbi,
  jsonValue } from '@ava-protocol/sdk';
import { AvaQuery, QueryCursorError, QueryFilterError } from './query.ts';
import { AvaTransactions, TransactionConflictError, TransactionValidationError } from './transactions.ts';
import { WorkQueue, WorkQueueFullError, WorkQueueCancelledError } from './work-queue.ts';

export interface ServiceOptions {
  client: PublicClient;
  sdk: AvaSdk;
  extensions?: AvaExtensions;
  databasePath: string;
  token: string;
  confirmations?: number;
  startBlock?: bigint;
  syncBatchSize?: number;
  projectionConcurrency?: number;
  queryConcurrency?: number;
  queryQueueLimit?: number;
  recordQueryConcurrency?: number;
  recordQueryQueueLimit?: number;
  transactionConcurrency?: number;
  transactionQueueLimit?: number;
  /** indexedArgs creates indexes only; removal retains them and does not change stored query identity. */
  additionalSources?: Record<string, { address: Address; abi: Abi; indexedArgs?: readonly string[] }>;
}
const decimal = { type: 'string', pattern: '^(0|[1-9][0-9]{0,18})$' } as const;
const appId = { type: 'string', pattern: '^0x[0-9a-fA-F]{64}$' } as const;
const listSchema = { type: 'object', additionalProperties: false,
  properties: { appId, after: { type: 'string', minLength: 1, maxLength: 2000 },
    limit: { type: 'integer', minimum: 1, maximum: 100, default: 50 } } };

/** One local process, one durable file; signed commands and public projections stay separate. */
export async function buildAvaService(options: ServiceOptions) {
  const projectionConcurrency = options.projectionConcurrency ?? 8;
  if (!Number.isSafeInteger(projectionConcurrency) || projectionConcurrency < 1 || projectionConcurrency > 100) {
    throw new Error('projectionConcurrency must be an integer between 1 and 100');
  }
  const queryConcurrency = options.queryConcurrency ?? 64;
  const queryWork = new WorkQueue(queryConcurrency, options.queryQueueLimit ?? 64);
  const recordQueryConcurrency = options.recordQueryConcurrency ?? queryConcurrency;
  const recordQueryWork = new WorkQueue(recordQueryConcurrency,
    options.recordQueryQueueLimit ?? options.queryQueueLimit ?? 64);
  const projections = new WorkQueue(projectionConcurrency, recordQueryConcurrency * projectionConcurrency);
  if (!/^[A-Za-z0-9_-]{32,128}$/.test(options.token)) throw new Error('A random local bearer token is required');
  if (await options.client.getChainId() !== 31337 || options.sdk.deployment.chainId !== 31337) {
    throw new Error('Local chain 31337 required');
  }
  await options.sdk.verify(options.client);
  if (options.extensions) {
    const configured = options.extensions.sdk.deployment;
    if (configured.chainId !== options.sdk.deployment.chainId || Object.entries(options.sdk.deployment.addresses)
        .some(([name, address]) => configured.addresses[name as keyof typeof avaAbis].toLowerCase() !== address.toLowerCase())) {
      throw new Error('Optional extensions must use the service Core');
    }
    await options.extensions.verify(options.client);
  }
  await mkdir(dirname(options.databasePath), { recursive: true, mode: 0o700 });
  const sources = Object.fromEntries(Object.entries(avaAbis).map(([name, abi]) =>
    [name, { address: options.sdk.deployment.addresses[name as keyof typeof avaAbis], abi: abi as Abi }]));
  const corrections = await options.sdk.corrections(options.client);
  sources.corrections = { address: corrections.address, abi: correctionsAbi };
  const execution = await options.sdk.execution(options.client);
  sources.execution = { address: execution.address, abi: executionAbi };
  for (const [name, abi] of Object.entries(avaExtensionAbis)) {
    const address = options.extensions?.addresses[name as keyof typeof avaExtensionAbis];
    if (address) sources[name] = { address, abi };
  }
  for (const name of Object.keys(options.additionalSources ?? {})) {
    if (name in avaExtensionAbis) throw new Error('Additional source cannot replace a reserved optional AVA contract');
    if (name in sources) throw new Error('Additional source cannot replace a Core contract');
  }
  Object.assign(sources, options.additionalSources);
  const transactions = new AvaTransactions({ client: options.client, databasePath: options.databasePath,
    allowedTargets: Object.values(sources).map(source => source.address), confirmations: options.confirmations,
    concurrency: options.transactionConcurrency, maxPending: options.transactionQueueLimit });
  let query: AvaQuery;
  try {
    query = new AvaQuery({ client: options.client, databasePath: options.databasePath, sources,
      confirmations: options.confirmations, startBlock: options.startBlock, syncBatchSize: options.syncBatchSize });
  } catch (error) { transactions.close(); throw error; }
  await chmod(options.databasePath, 0o600);
  const app = Fastify({ logger: false, bodyLimit: 150_000 });
  let queue = Promise.resolve();
  function serial<T>(operation: () => Promise<T>): Promise<T> {
    const next = queue.then(operation);
    queue = next.then(() => {}, () => {});
    return next;
  }
  let syncing: ReturnType<AvaQuery['sync']> | undefined;
  const sync = () => {
    // Coalesce before serialisation: slow RPCs must not queue one sync per poll tick.
    if (!syncing) syncing = serial(() => query.sync()).finally(() => { syncing = undefined; });
    return syncing;
  };
  try {
    const initial = await sync();
    if (initial.chainId === undefined || !initial.genesisHash) throw new Error('Missing verified chain identity');
    transactions.bindChain(initial.chainId, initial.genesisHash);
  } catch (error) { query.close(); transactions.close(); throw error; }
  function waitForSync(signal: AbortSignal): ReturnType<AvaQuery['sync']> {
    if (signal.aborted) return Promise.reject(new WorkQueueCancelledError());
    // Only this request's wait is cancelled; other callers still share the refresh.
    return new Promise((resolve, reject) => {
      const cancel = () => reject(new WorkQueueCancelledError());
      signal.addEventListener('abort', cancel, { once: true });
      void sync().then(value => {
        signal.removeEventListener('abort', cancel); resolve(value);
      }, error => {
        signal.removeEventListener('abort', cancel); reject(error);
      });
    });
  }
  const readSnapshot = <T>(read: () => Promise<T>, signal: AbortSignal) => waitForSync(signal).then(() => serial(() => {
    if (signal.aborted) throw new WorkQueueCancelledError();
    return read();
  }));
  // A disconnected queued request releases admission; already-started transactions keep running.
  async function requestWork<T>(request: FastifyRequest, reply: FastifyReply,
    operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    const closed = () => { if (!reply.raw.writableFinished) abort(); };
    request.raw.once('aborted', abort);
    reply.raw.once('close', closed);
    if (request.raw.aborted || reply.raw.destroyed) abort();
    try { return await operation(controller.signal); }
    finally { request.raw.removeListener('aborted', abort); reply.raw.removeListener('close', closed); }
  }
  function admittedQuery<T>(request: FastifyRequest, reply: FastifyReply,
    work: WorkQueue, operation: (signal: AbortSignal) => Promise<T>): Promise<T> {
    return requestWork(request, reply, signal => work.run(() => operation(signal), { signal }));
  }
  async function projectPage<T, U>(values: T[], read: (value: T) => Promise<U>, signal: AbortSignal): Promise<U[]> {
    const items = new Array<U>(values.length);
    let next = 0, failure: { error: unknown } | undefined;
    await Promise.all(Array.from({ length: Math.min(projectionConcurrency, values.length) }, async () => {
      while (!failure && next < values.length) {
        const index = next++;
        try {
          await projections.run(async () => {
            if (!failure) items[index] = await read(values[index]!);
          }, { signal });
        } catch (error) { failure ??= { error }; }
      }
    }));
    if (failure) throw failure.error;
    if (signal.aborted) throw new WorkQueueCancelledError();
    return items;
  }

  app.addHook('onRequest', async (request, reply) => {
    const host = request.headers.host ?? '';
    if (!/^(127\.0\.0\.1|localhost|\[::1\])(?::\d+)?$/.test(host)) {
      return reply.code(403).send({ error: 'local_host_required' });
    }
    if (request.method !== 'GET') {
      const actual = Buffer.from(request.headers.authorization ?? '');
      const expected = Buffer.from(`Bearer ${options.token}`);
      if (actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
        return reply.code(401).send({ error: 'bearer_token_required' });
      }
    }
  });
  app.setErrorHandler((error, _request, reply) => {
    if ((error as { validation?: unknown }).validation) return reply.code(400).send({ error: 'invalid_request' });
    if (error instanceof Fastify.errorCodes.FST_ERR_CTP_BODY_TOO_LARGE
      || error instanceof Fastify.errorCodes.FST_ERR_CTP_INVALID_MEDIA_TYPE
      || error instanceof Fastify.errorCodes.FST_ERR_CTP_INVALID_CONTENT_LENGTH
      || error instanceof Fastify.errorCodes.FST_ERR_CTP_EMPTY_JSON_BODY
      || error instanceof Fastify.errorCodes.FST_ERR_CTP_INVALID_JSON_BODY) {
      return reply.code(400).send({ error: 'invalid_request' });
    }
    if (error instanceof WorkQueueFullError) return reply.code(429).send({ error: 'work_queue_full' });
    if (error instanceof WorkQueueCancelledError) return reply.code(503).send({ error: 'request_cancelled' });
    if (error instanceof QueryCursorError) return reply.code(400).send({ error: 'invalid_cursor' });
    if (error instanceof QueryFilterError) return reply.code(400).send({ error: 'invalid_request' });
    if (error instanceof TransactionConflictError) return reply.code(409).send({ error: 'transaction_conflict' });
    if (error instanceof TransactionValidationError) return reply.code(400).send({ error: 'invalid_transaction' });
    // RPC errors may contain serialized transactions or provider URLs. Keep them out of HTTP errors.
    return reply.code(503).send({ error: 'chain_or_query_unavailable' });
  });
  app.get('/health', async () => query.health());
  app.post('/v1/sync', async (request, reply) => admittedQuery(request, reply, queryWork, signal => waitForSync(signal)));
  app.get<{ Querystring: { source?: string; expectedSourceAddress?: Address; event?: string; appId?: Hex;
    fromBlock?: string; after?: string; limit?: number; argName?: string; argValue?: string;
    beforeBlock?: string; beforeLogIndex?: number; order?: 'asc' | 'desc'; atBlock?: string; atHash?: Hex } }>(
    '/v1/events', { schema: { querystring: { type: 'object', additionalProperties: false,
      dependencies: { argName: ['argValue', 'source'], argValue: ['argName'],
        beforeBlock: ['beforeLogIndex'], beforeLogIndex: ['beforeBlock'], atBlock: ['atHash'], atHash: ['atBlock'],
        expectedSourceAddress: ['source'] }, properties: {
      source: { type: 'string', minLength: 1, maxLength: 80 }, event: { type: 'string', minLength: 1, maxLength: 100 },
      expectedSourceAddress: { type: 'string', pattern: '^0x[0-9a-fA-F]{40}$' },
      argName: { type: 'string', pattern: '^[A-Za-z_][A-Za-z0-9_]{0,99}$' },
      argValue: { type: 'string', maxLength: 1024 },
      beforeBlock: decimal, beforeLogIndex: { type: 'integer', minimum: 0, maximum: Number.MAX_SAFE_INTEGER },
      order: { type: 'string', enum: ['asc', 'desc'] }, atBlock: decimal, atHash: appId,
      appId, fromBlock: decimal, after: { type: 'string', minLength: 1, maxLength: 2000 },
      limit: { type: 'integer', minimum: 1, maximum: 100, default: 50 },
    } } } }, async (request, reply) => admittedQuery(request, reply, queryWork, signal => readSnapshot(async () => {
      const q = request.query;
      return { asOf: query.health(), ...query.events({ source: q.source, expectedSourceAddress: q.expectedSourceAddress,
        event: q.event, appId: q.appId, after: q.after, limit: q.limit, order: q.order,
        fromBlock: q.fromBlock === undefined ? undefined : BigInt(q.fromBlock),
        arg: q.argName === undefined ? undefined : { name: q.argName, value: q.argValue! },
        before: q.beforeBlock === undefined ? undefined : { blockNumber: BigInt(q.beforeBlock), logIndex: q.beforeLogIndex! },
        at: q.atBlock === undefined ? undefined : { blockNumber: BigInt(q.atBlock), blockHash: q.atHash! } }) };
    }, signal)));

  app.get<{ Querystring: { appId: Hex; after?: string; limit?: number } }>(
    '/v1/corrections',
    { schema: { querystring: { type: 'object', required: ['appId'], additionalProperties: false,
      properties: { appId, after: { type: 'string', minLength: 1, maxLength: 2000 },
        limit: { type: 'integer', minimum: 1, maximum: 100, default: 50 } },
    } } }, async (request, reply) => admittedQuery(request, reply, recordQueryWork, async signal => {
      const { health, page } = await readSnapshot(async () => ({ health: query.health(),
        page: query.events({ source: 'corrections', event: 'CaseAccepted', ...request.query }) }), signal);
      if (health.indexedBlock === undefined) return { asOf: health, items: [] };
      if (!health.indexedBlockHash) throw new Error('No indexed block hash');
      const point = { blockHash: health.indexedBlockHash, requireCanonical: true as const };
      // Mutable records are read at this page's captured asOf, outside the index queue.
      const items = await projectPage(page.items, async event => {
        const caseId = BigInt(String(event.args.caseId));
        const item = await (options.extensions ?? options.sdk).correctionCase(options.client, caseId, point);
        if (item.record.id !== caseId || item.registry.toLowerCase() !== corrections.address.toLowerCase()
            || item.record.input.appId.toLowerCase() !== request.query.appId.toLowerCase()) {
          throw new Error('Inconsistent correction case projection');
        }
        return item;
      }, signal);
      const current = await options.client.getBlock({ blockNumber: BigInt(health.indexedBlock) });
      if (current.hash !== health.indexedBlockHash) throw new Error('Query snapshot changed');
      return jsonValue({ asOf: health, items, ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}) });
    }));

  for (const kind of ['objects', 'recognitions', 'requests'] as const) {
    app.get<{ Querystring: { appId?: Hex; after?: string; limit?: number } }>(`/v1/${kind}`,
      { schema: { querystring: listSchema } }, async (request, reply) => admittedQuery(request, reply, recordQueryWork, async signal => {
        const { health, page } = await readSnapshot(async () => ({ health: query.health(),
          page: query.idsPage(kind, request.query) }), signal);
        if (health.indexedBlock === undefined) return { asOf: health, items: [] };
        if (!health.indexedBlockHash) throw new Error('No indexed block hash');
        const point = { blockHash: health.indexedBlockHash, requireCanonical: true as const };
        const contracts = options.sdk.contracts(options.client);
        const items = await projectPage(page.items, async id => {
          if (kind === 'objects') return contracts.kernel.read.getGovernedObject([BigInt(id)], point);
          if (kind === 'recognitions') return options.sdk.recognition(options.client, BigInt(id), point);
          return { ...await options.sdk.request(options.client, BigInt(id), point),
            support: await options.sdk.support(options.client, BigInt(id), point) };
        }, signal);
        const current = await options.client.getBlock({ blockNumber: BigInt(health.indexedBlock) });
        if (current.hash !== health.indexedBlockHash) throw new Error('Query snapshot changed');
        return jsonValue({ asOf: health, items, ...(page.nextCursor ? { nextCursor: page.nextCursor } : {}) });
      }));
  }
  app.post<{ Body: { key: string; serializedTransaction: Hex } }>('/v1/transactions', { schema: { body: {
    type: 'object', required: ['key', 'serializedTransaction'], additionalProperties: false, properties: {
      key: { type: 'string', pattern: '^[A-Za-z0-9._:-]{1,128}$' },
      serializedTransaction: { type: 'string', pattern: '^0x[0-9a-fA-F]+$', maxLength: 140_000 },
    },
  } } }, async (request, reply) => requestWork(request, reply, signal =>
    transactions.submit(request.body.key, request.body.serializedTransaction, { signal })));
  app.post<{ Params: { key: string }; Body: { serializedTransaction: Hex } }>('/v1/transactions/:key/recover', {
    schema: {
      params: { type: 'object', required: ['key'], properties: {
        key: { type: 'string', pattern: '^[A-Za-z0-9._:-]{1,128}$' },
      } },
      body: { type: 'object', required: ['serializedTransaction'], additionalProperties: false, properties: {
        serializedTransaction: { type: 'string', pattern: '^0x[0-9a-fA-F]+$', maxLength: 140_000 },
      } },
    },
  }, async (request, reply) => requestWork(request, reply, signal =>
    transactions.recover(request.params.key, request.body.serializedTransaction, { signal })));
  app.get<{ Params: { key: string } }>('/v1/transactions/:key', { schema: { params: {
    type: 'object', required: ['key'], properties: { key: { type: 'string', pattern: '^[A-Za-z0-9._:-]{1,128}$' } },
  } } }, async (request, reply) => requestWork(request, reply, async signal => {
    const transaction = await transactions.get(request.params.key, { signal });
    return transaction ?? reply.code(404).send({ error: 'transaction_not_found' });
  }));
  app.addHook('onClose', async () => {
    await Promise.all([queryWork.idle(), recordQueryWork.idle(), transactions.drain()]);
    await queue; query.close(); transactions.close();
  });
  return { app, sync, query, transactions };
}
