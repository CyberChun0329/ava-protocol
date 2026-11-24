import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import { test } from 'node:test';
import { createPublicClient, custom, decodeFunctionData, encodeFunctionResult, zeroAddress,
  type Abi, type AbiParameter, type Address, type Hex } from 'viem';
import { AvaSdk, AvaExtensions, avaAbis, correctionsAbi, executionAbi, decisionsAbi, procedureAbi,
  type CoreAddresses, type ReadPoint } from '../src/index.ts';

const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}` as Address;
const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, i) => [name, address(i + 1)])) as CoreAddresses;
const correction = address(90), execution = address(91), decisions = address(92), procedure = address(93);
const point = { blockHash: `0x${'41'.repeat(32)}` as Hex, requireCanonical: true as const };
const sdk = new AvaSdk({ chainId: 31337, addresses });

// ABI defaults mirror the accepted synthetic audit fixture; each case supplies its relevant records.
function empty(parameter: AbiParameter): unknown {
  if (parameter.type.endsWith('[]')) return [];
  if ('components' in parameter) return Object.fromEntries(parameter.components.map(p => [p.name, empty(p)]));
  if (parameter.type === 'address') return zeroAddress;
  if (parameter.type === 'bool') return false;
  if (parameter.type === 'string') return '';
  if (parameter.type === 'bytes') return '0x';
  if (parameter.type.startsWith('bytes')) return `0x${'00'.repeat(Number(parameter.type.slice(5)))}`;
  return 0n;
}

type Override = (result: any, args: readonly unknown[]) => unknown;
function boundary(overrides: Record<string, Override>, expectedPoint: ReadPoint = point) {
  const abis: Record<string, Abi> = { ...Object.fromEntries(Object.keys(avaAbis).map(name =>
    [addresses[name as keyof CoreAddresses], avaAbis[name as keyof CoreAddresses]])),
    [correction]: correctionsAbi, [execution]: executionAbi, [decisions]: decisionsAbi, [procedure]: procedureAbi };
  const calls: { name: string; args: readonly unknown[] }[] = [];
  const pending = new Set<string>(), overlaps: string[][] = [];
  let snapshots = 0;
  const client = createPublicClient({ cacheTime: 0, transport: custom({ retryCount: 0,
    request: async ({ method, params }) => {
      if (method === 'eth_getBlockByNumber') {
        snapshots++;
        return { number: '0x2a', hash: point.blockHash, transactions: [] };
      }
      assert.equal(method, 'eth_call');
      const [call, block] = params as [{ to: Address; data: Hex }, unknown];
      assert.deepEqual(block, typeof expectedPoint === 'bigint' ? `0x${expectedPoint.toString(16)}` : expectedPoint);
      const abi = abis[call.to.toLowerCase()];
      const { functionName: name, args = [] } = decodeFunctionData({ abi, data: call.data });
      calls.push({ name, args });
      pending.add(name);
      overlaps.push([...pending]);
      await setImmediate();
      pending.delete(name);
      const item = abi.find(item => item.type === 'function' && item.name === name);
      assert.ok(item?.type === 'function');
      const values = item.outputs.map(empty);
      let result: unknown = values.length === 1 ? values[0] : values;
      if (name === 'EXECUTION') result = execution;
      if (name === 'CORRECTIONS') result = correction;
      if (overrides[name]) result = overrides[name](result, args);
      return encodeFunctionResult({ abi, functionName: name, result });
    } }) });
  return { client, calls, overlaps, snapshots: () => snapshots };
}

test('split request reuses a shared latest/live attempt within one aggregate and refreshes the next read', async () => {
  let latest = 2n, live = 2n;
  const fixture = boundary({
    isSplit: () => true,
    getRequest: result => ({ ...result, id: 1n }),
    getDeclaration: result => ({ ...result, latestAttemptId: latest, liveAttemptId: live,
      latestReportId: 3n, latestRecoveryId: 4n }),
    getAttempt: (result, args) => ({ ...result, id: args[0], previousAttemptId: 1n }),
  });
  const first = await sdk.request(fixture.client, 1n);
  assert.equal(first.execution?.latestAttempt?.id, 2n);
  assert.deepEqual(first.execution?.liveAttempt, first.execution?.latestAttempt);
  assert.equal(first.execution?.latestAttempt?.previousAttemptId, 1n);
  assert.equal(fixture.calls.filter(c => c.name === 'getAttempt').length, 1);
  assert.equal(fixture.calls.length + fixture.snapshots(), 9);

  latest = 5n;
  live = 6n;
  const second = await sdk.request(fixture.client, 1n);
  assert.equal(second.execution?.latestAttempt?.id, 5n);
  assert.equal(second.execution?.liveAttempt?.id, 6n);
  assert.equal(fixture.calls.filter(c => c.name === 'getAttempt').length, 3);
  assert.equal(fixture.snapshots(), 2);
});

test('decision request shares the latest/allocation subtree while retaining distinct decision histories', async () => {
  let allocation = 8n;
  const fixture = boundary({
    getRequest: result => ({ ...result, id: 3n, supportRevision: 1n,
      lastDecisionId: 8n, allocationDecisionId: allocation }),
    getSupportRevision: result => ({ ...result, revision: 1n }),
    getDecision: (result, args) => ({ ...result, id: args[0], previousDecisionId: 6n }),
    procedureDisposition: () => 12n,
  });
  const extensions = new AvaExtensions(sdk, { decisions });
  const first = await extensions.decisionRequest(fixture.client, 3n);
  assert.equal(first.latestDecision?.record.id, 8n);
  assert.equal(first.latestDecision?.record.previousDecisionId, 6n);
  assert.equal(first.latestDecision?.procedureDispositionId, 12n);
  assert.deepEqual(first.allocationDecision, first.latestDecision);
  assert.equal(fixture.calls.length + fixture.snapshots(), 7);

  allocation = 9n;
  const second = await extensions.decisionRequest(fixture.client, 3n);
  assert.equal(second.latestDecision?.record.id, 8n);
  assert.equal(second.allocationDecision?.record.id, 9n);
  assert.equal(fixture.calls.filter(c => c.name === 'getDecision').length, 3);
  assert.equal(fixture.snapshots(), 2);
});

test('a shared decision retains one nested execution read at the same outer snapshot', async () => {
  const fixture = boundary({
    getRequest: (result, args) => args[0] === 3n
      ? { ...result, id: 3n, supportRevision: 1n, lastDecisionId: 8n, allocationDecisionId: 8n }
      : { ...result, id: 1n, consumed: true, completed: false },
    getDecision: result => ({ ...result, id: 8n, executionRequestId: 1n }),
    isSplit: () => false,
  });
  const result = await new AvaExtensions(sdk, { decisions }).decisionRequest(fixture.client, 3n);
  assert.equal(result.latestDecision?.execution?.record.id, 1n);
  assert.equal(result.latestDecision?.execution?.record.consumed, true);
  assert.equal(result.latestDecision?.execution?.record.completed, false);
  assert.deepEqual(result.allocationDecision?.execution, result.latestDecision?.execution);
  assert.equal(fixture.calls.filter(c => c.name === 'EXECUTION').length, 1);
  assert.equal(fixture.calls.length + fixture.snapshots(), 11);
  assert.equal(fixture.snapshots(), 1);
});

test('request reads independent record, resolution head and helper branches concurrently at the supplied point', async () => {
  const fixture = boundary({
    lastResolutionIdByRequest: () => 7n,
    getRequestChallenge: result => ({ ...result, id: 7n }),
    isSplit: () => false,
  }, 0n);
  const result = await sdk.request(fixture.client, 1n, 0n);
  assert.equal(result.resolution?.id, 7n);
  assert.equal(result.execution, null);
  assert.equal(fixture.snapshots(), 0);
  assert.ok(fixture.overlaps.some(names => ['getRequest', 'lastResolutionIdByRequest', 'EXECUTION']
    .every(name => names.includes(name))), 'independent request heads must overlap');
  assert.ok(fixture.overlaps.some(names => ['getRequestChallenge', 'isSplit']
    .every(name => names.includes(name))), 'resolution and split lookup must overlap');
});

test('correction review, finding and retained origin reads overlap without conflating compensation or finding identity', async () => {
  const fixture = boundary({
    getCase: result => ({ ...result, id: 7n, origin: addresses.requests, reviewId: 3n,
      input: { ...result.input, kind: 1, originCaseId: 4n, sourceStateId: 9n } }),
    findingIdByCase: () => 11n,
    getReview: result => ({ ...result, id: 3n }),
    getFinding: result => ({ ...result, id: 11n, caseId: 7n, supersedesFindingId: 5n }),
    supersededByFindingId: () => 12n,
    getRequestChallenge: result => ({ ...result, id: 4n, outcome: 4 }),
  });
  const result = await sdk.correctionCase(fixture.client, 7n);
  assert.equal(result.record.input.sourceStateId, 9n);
  assert.equal(result.review?.id, 3n);
  assert.equal(result.finding?.id, 11n);
  assert.equal(result.finding?.supersedesFindingId, 5n);
  assert.equal(result.supersededBy, 12n);
  assert.equal(result.originRecord?.family, 'request');
  assert.equal(result.originRecord?.record.id, 4n);
  assert.ok(result.compensation);
  assert.equal(fixture.snapshots(), 1);
  assert.equal(fixture.calls.length + fixture.snapshots(), 9);
  assert.ok(fixture.overlaps.some(names => ['getReview', 'getFinding', 'supersededByFindingId', 'getRequestChallenge']
    .every(name => names.includes(name))), 'independent correction branches must overlap');
  assert.deepEqual(fixture.calls.find(c => c.name === 'getCompensation')?.args, [4n]);
});

test('procedural correction reads its retained challenge and fixed registry concurrently at the outer point', async () => {
  const fixture = boundary({
    getCase: result => ({ ...result, id: 7n, origin: procedure,
      input: { ...result.input, kind: 3, originCaseId: 4n } }),
    getChallenge: result => ({ ...result, id: 4n, decisionId: 8n, resolutionId: 12n }),
    DECISION_REGISTRY: () => decisions,
    getResolution: result => ({ ...result, id: 12n }),
    getDecision: result => ({ ...result, id: 8n }),
  });
  const result = await new AvaExtensions(sdk, { procedure }).correctionCase(fixture.client, 7n);
  assert.equal(result.finding, null);
  assert.equal(result.review, null);
  assert.equal(result.originRecord?.family, 'procedure');
  if (result.originRecord?.family === 'procedure') {
    assert.equal(result.originRecord.record.id, 4n);
    assert.equal(result.originRecord.resolution?.id, 12n);
    assert.equal(result.originRecord.decision.record.id, 8n);
  }
  assert.equal(fixture.snapshots(), 1);
  assert.ok(fixture.overlaps.some(names => ['getChallenge', 'DECISION_REGISTRY']
    .every(name => names.includes(name))), 'independent procedural origin heads must overlap');
});
