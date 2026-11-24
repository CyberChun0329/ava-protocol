import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, decodeFunctionData, encodeFunctionResult,
  keccak256, toHex, zeroHash, type Address, type Hex } from 'viem';
import { AvaSdk, AvaExtensions, DecisionKind, decisionsAbi, type CoreAddresses } from '@ava-protocol/sdk';
import { AvaDecisionAgent, adviceReceiptHash, type ChoiceProvider, type AgentInput } from '../src/index.ts';

const key = (text: string) => keccak256(toHex(text));
const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}` as Address;
const addresses = Object.fromEntries(['applications', 'identities', 'authority', 'packages',
  'disclosure', 'evidence', 'kernel', 'requests', 'challenges'].map((name, i) => [name, address(i + 1)])) as CoreAddresses;
const extensions = new AvaExtensions(new AvaSdk({ chainId: 31337, addresses }), { decisions: address(20) });
const actor = { account: address(30), roleKey: key('allocator'), authorityId: key('agent-subject') };
const positive = key('pay'), pause = key('pause');
const blockHash = key('block-42');
const options = [{ key: positive, kind: DecisionKind.Substantive, actionKey: key('allocation'),
  parametersHash: key('exact-payment'), notBefore: 0n, conditionsHash: zeroHash },
{ key: pause, kind: DecisionKind.Pause, actionKey: key('pause-action'),
  parametersHash: key('pause-terms'), notBefore: 0n, conditionsHash: zeroHash }];
const input: AgentInput = { configurationId: 'test-grants.v1', instructions: 'Choose by the declared grant terms.',
  input: 'SYNTHETIC authorised material', descriptions: { [positive]: 'Pay the accepted grant.', [pause]: 'Pause.' },
  minimumConfidence: 0.8 };

function rpc(expectedActor = actor, requestId = 7n) {
  const record = { id: requestId, input: { appId: key('app'), workflowKey: key('workflow'), packageId: 9n,
    requestHash: key('request'), executor: address(50), responseClass: key('pay'), burdenHash: key('burden'), validUntil: 99999n },
    creator: address(40), creatorRoleKey: key('creator-role'), creatorAuthorityId: key('creator-subject'),
    createdAt: 1n, supportRevision: 1n, lastDecisionId: 0n, allocationDecisionId: 0n, paused: false, closed: false };
  const state = { record, options: [...options], canonicalHash: blockHash, chainId: '0x7a69', failReads: false, hold: undefined as Promise<void> | undefined, entered: () => {} };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') return state.chainId;
    if (method === 'eth_getBlockByNumber') {
      const [tag] = params as string[];
      return { hash: tag === 'latest' ? blockHash : state.canonicalHash, number: '0x2a', timestamp: '0x640', transactions: [] };
    }
    assert.equal(method, 'eth_call');
    const [call, at] = params as [{ to: Address; data: Hex }, unknown];
    assert.equal(call.to.toLowerCase(), address(20));
    assert.deepEqual(at, { blockHash, requireCanonical: true });
    if (state.hold) { state.entered(); await state.hold; }
    if (state.failReads) throw new Error('policy unavailable');
    const decoded = decodeFunctionData({ abi: decisionsAbi, data: call.data });
    if (decoded.functionName === 'getRequest') return encodeFunctionResult({ abi: decisionsAbi,
      functionName: 'getRequest', result: state.record });
    assert.equal(decoded.functionName, 'getAdmissibleDecisions');
    assert.deepEqual([decoded.args[0], decoded.args[1].toLowerCase(), ...decoded.args.slice(2)],
      [requestId, expectedActor.account.toLowerCase(), expectedActor.roleKey, expectedActor.authorityId]);
    return encodeFunctionResult({ abi: decisionsAbi, functionName: 'getAdmissibleDecisions', result: state.options });
  } }, { retryCount: 0 }) });
  return { client, state };
}

test('authorised complete choice becomes an explicit unsigned command and a private-input commitment', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const provider: ChoiceProvider = { id: 'synthetic', model: 'fixture.v1', choose: async question => {
    assert.deepEqual(question.choices, [
      { value: positive, description: 'Pay the accepted grant.' }, { value: pause, description: 'Pause.' }]);
    assert.equal(question.input, input.input);
    return { kind: 'choice', choice: positive, confidence: 0.95, responseId: 'fixture-1' };
  } };
  const advice = await agent.advise(client, 7n, provider, input);
  assert.equal(advice.status, 'recommended');
  if (advice.status !== 'recommended') throw new Error('Missing recommendation');
  assert.equal(advice.receipt.choice, positive);
  assert.equal(advice.receipt.configurationId, 'test-grants.v1');
  assert.equal(JSON.stringify(advice.receipt, (_, v) => typeof v === 'bigint' ? String(v) : v).includes(input.input), false);
  const command = await agent.buildCommand(client, advice, 11n);
  assert.equal(command.to, address(20));
  assert.deepEqual(decodeFunctionData({ abi: decisionsAbi, data: command.data }),
    { functionName: 'choose', args: [7n, positive, 11n, 0n, actor.roleKey, actor.authorityId, advice.reasonHash] });
  assert.deepEqual(Object.keys(command).sort(), ['data', 'to']);
});

test('a command rejects a modified public snapshot, then accepts intact advice and explicit legacy receipts', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const advice = await agent.advise(client, 7n,
    { id: 'synthetic', model: 'fixture.v1', choose: async () => ({ kind: 'choice', choice: positive, confidence: 0.95 }) }, input);
  if (advice.status !== 'recommended') throw new Error('Missing recommendation');
  for (const change of [
    { actor: { ...actor, account: address(99) } }, { blockHash: key('modified-block') },
    { blockNumber: 99n }, { registry: address(99) },
  ]) {
    const modified = structuredClone(advice);
    Object.assign(modified.snapshot, change);
    await assert.rejects(agent.buildCommand(client, modified, 11n), /modified/);
  }
  assert.equal((await agent.buildCommand(client, advice, 11n)).to, address(20));
  const legacy = structuredClone(advice);
  delete legacy.receipt.snapshotHash;
  legacy.reasonHash = adviceReceiptHash(legacy.receipt);
  assert.equal((await agent.buildCommand(client, legacy, 11n)).to, address(20));
});

test('refusal and insufficient confidence remain advice without an executable command', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  for (const answer of [{ kind: 'abstain' as const },
    { kind: 'choice' as const, choice: positive, confidence: 0.79 },
    { kind: 'choice' as const, choice: positive }]) {
    const advice = await agent.advise(client, 7n,
      { id: 'synthetic', model: 'fixture.v1', choose: async () => answer }, input);
    assert.equal(advice.status, 'abstained');
    if (advice.status !== 'abstained') throw new Error('Missing abstention');
    assert.equal(advice.receipt.abstentionReason, answer.kind === 'abstain' ? 'provider_abstained'
      : answer.confidence === undefined ? 'missing_confidence' : 'low_confidence');
    await assert.rejects(agent.buildCommand(client, advice, 11n), /no actionable choice/);
  }
});

test('abstention retains provider identity metadata and technical errors retain only safe codes', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const advice = await agent.advise(client, 7n, { id: 'custom', model: 'fixture', choose: async () => ({
    kind: 'abstain', reason: 'provider_refusal', responseId: 'refusal-1', servedModel: 'fixture-served',
  }) }, input);
  assert.equal(advice.status, 'abstained');
  if (advice.status !== 'abstained') throw new Error('Missing abstention');
  assert.equal(advice.receipt.abstentionReason, 'provider_refusal');
  assert.equal(advice.receipt.responseId, 'refusal-1');
  assert.equal(advice.receipt.servedModel, 'fixture-served');
  await assert.rejects(agent.advise(client, 7n, { id: 'custom', model: 'fixture', choose: async () => {
    throw new DOMException('SYNTHETIC_PRIVATE', 'TimeoutError');
  } }, input), error => {
    assert.equal((error as { code?: string }).code, 'timeout');
    assert(!String(error).includes('SYNTHETIC_PRIVATE'));
    return true;
  });
});

test('application handoff commits the original abstention without transferring actor authority', async () => {
  const { adviceReceiptHash, linkAdvice } = await import('../src/index.ts');
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const previous = await agent.advise(client, 7n, { id: 'model', model: 'fixture', choose: async () => ({ kind: 'abstain' }) }, input);
  if (previous.status !== 'abstained') throw new Error('Missing original abstention');
  const previousHash = adviceReceiptHash(previous.receipt);
  const human = { account: address(31), roleKey: key('human-allocator'), authorityId: key('human-subject') };
  const nextRpc = rpc(human);
  const humanAgent = new AvaDecisionAgent(extensions, human);
  const next = await humanAgent.advise(nextRpc.client, 7n, { id: 'application-review', model: 'explicit.v1',
    choose: async () => ({ kind: 'choice', choice: positive }) }, { ...input, minimumConfidence: undefined,
    configurationId: 'independent-application-review.v1', parentReceiptHash: previousHash });
  if (next.status !== 'recommended') throw new Error('Missing application advice');
  assert.deepEqual(linkAdvice(previous, next), { version: 'ava.agent-handoff.v1',
    previousReceiptHash: previousHash, nextReceiptHash: next.reasonHash });
  assert.equal(previous.status, 'abstained');
  await assert.rejects(agent.buildCommand(client, previous, 11n), /no actionable choice/);
  const call = await humanAgent.buildCommand(nextRpc.client, next, 11n);
  assert.deepEqual(decodeFunctionData({ abi: decisionsAbi, data: call.data }).args,
    [7n, positive, 11n, 0n, human.roleKey, human.authorityId, next.reasonHash]);
  for (const change of ['parent', 'request', 'previous'] as const) {
    const altered = structuredClone(next), old = structuredClone(previous);
    if (change === 'parent') altered.receipt.parentReceiptHash = key('unrelated');
    if (change === 'request') altered.snapshot.requestId = 8n;
    if (change === 'previous') old.receipt.configurationId = 'altered';
    assert.throws(() => linkAdvice(old, altered), { code: 'invalid_advice' });
  }
  const anotherRequest = rpc(human, 8n);
  const crossCase = await humanAgent.advise(anotherRequest.client, 8n, { id: 'application-review', model: 'explicit.v1',
    choose: async () => ({ kind: 'choice', choice: positive }) }, { ...input, minimumConfidence: undefined,
    parentReceiptHash: previousHash });
  const relabelled = structuredClone(previous);
  relabelled.snapshot.requestId = 8n;
  assert.throws(() => linkAdvice(relabelled, crossCase), { code: 'invalid_advice' });
  const relabelledActor = structuredClone(previous);
  relabelledActor.snapshot.actor = human;
  assert.throws(() => linkAdvice(relabelledActor, next), { code: 'invalid_advice' });
  nextRpc.state.options = [];
  await assert.rejects(humanAgent.buildCommand(nextRpc.client, next, 11n), /Stale/);
  nextRpc.state.options = [...options];
  assert.equal((await humanAgent.buildCommand(nextRpc.client, next, 11n)).to, address(20));
});

test('no admissible choices never invokes a provider or invents a procedural fallback', async () => {
  const { client, state } = rpc();
  state.options = [];
  const agent = new AvaDecisionAgent(extensions, actor);
  const advice = await agent.advise(client, 7n, { id: 'synthetic', model: 'fixture.v1',
    choose: async () => { assert.fail('Provider must not see a request without admissible options'); } }, input);
  assert.equal(advice.status, 'unavailable');
  await assert.rejects(agent.buildCommand(client, advice, 0n), /no actionable choice/);
});

test('invalid or private-bearing provider failures cannot return advice or leak the input', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  for (const answer of [
    { kind: 'choice', choice: key('outside-catalogue'), confidence: 1 },
    { kind: 'choice', choice: positive, confidence: NaN },
    { kind: 'choice', choice: positive, confidence: 2 },
    { kind: 'choice', choice: positive, confidence: -0.1 },
    { kind: 'unexpected', choice: positive, confidence: 1 },
  ]) {
    await assert.rejects(agent.advise(client, 7n, { id: 'synthetic', model: 'fixture.v1',
      choose: async () => answer as never }, input), /Invalid provider/);
  }
  await assert.rejects(agent.advise(client, 7n, { id: 'synthetic', model: 'fixture.v1',
    choose: async () => { throw new Error(`SECRET-key ${input.input}`); } }, input), error => {
    assert.equal(String(error).includes('SECRET-key'), false);
    assert.equal(String(error).includes(input.input), false);
    assert.equal((error as Error).cause, undefined);
    return true;
  });
});

test('invalid app configuration and cancellation cannot expose material to a provider', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const provider: ChoiceProvider = { id: 'synthetic', model: 'fixture.v1',
    choose: async () => { assert.fail('Invalid input or aborted task must not invoke provider'); } };
  for (const bad of [{ ...input, minimumConfidence: NaN }, { ...input, minimumConfidence: -1 },
    { ...input, minimumConfidence: 1.01 }, { ...input, configurationId: '' },
    { ...input, parentReceiptHash: zeroHash }, { ...input, parentReceiptHash: '0x01' as Hex },
    { ...input, descriptions: { [positive]: 'Pay.' } }]) {
    await assert.rejects(agent.advise(client, 7n, provider, bad), /Invalid agent/);
  }
  const controller = new AbortController();
  controller.abort('SECRET cancellation');
  await assert.rejects(agent.advise(client, 7n, provider, { ...input, signal: controller.signal }), /Agent operation aborted/);
  const late = new AbortController();
  await assert.rejects(agent.advise(client, 7n, { ...provider, choose: async () => {
    late.abort(); return { kind: 'choice', choice: positive, confidence: 1 };
  } }, { ...input, signal: late.signal }), /Agent operation aborted/);
});

test('revocation, changed support, a later decision and a changed option reject old advice', async () => {
  for (const change of ['revoked', 'support', 'decision', 'terms'] as const) {
    const { client, state } = rpc();
    const agent = new AvaDecisionAgent(extensions, actor);
    const advice = await agent.advise(client, 7n, { id: 'synthetic', model: 'fixture.v1',
      choose: async () => ({ kind: 'choice', choice: positive, confidence: 1 }) }, input);
    if (change === 'revoked') state.options = [];
    if (change === 'support') state.record.supportRevision++;
    if (change === 'decision') state.record.lastDecisionId++;
    if (change === 'terms') state.options = [{ ...options[0], parametersHash: key('other-payment') }, options[1]];
    await assert.rejects(agent.buildCommand(client, advice, 11n), /Stale/);
    state.options = [...options]; state.record.supportRevision = 1n; state.record.lastDecisionId = 0n;
    assert.equal((await agent.buildCommand(client, advice, 11n)).to, address(20));
  }
});

test('noncanonical snapshots and technical validation failures do not become empty or adverse decisions', async () => {
  const { client, state } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const provider: ChoiceProvider = { id: 'synthetic', model: 'fixture.v1',
    choose: async () => { assert.fail('Unavailable trusted reads cannot invoke provider'); } };
  state.canonicalHash = key('reorg');
  await assert.rejects(agent.advise(client, 7n, provider, input), { code: 'read_unavailable' });
  state.canonicalHash = blockHash; state.failReads = true;
  await assert.rejects(agent.advise(client, 7n, provider, input), /policy unavailable/);
  state.failReads = false; state.chainId = '0x1';
  await assert.rejects(agent.advise(client, 7n, provider, input), /chain mismatch/);
});

test('altered receipts and procedural execution bindings cannot produce commands', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const advice = await agent.advise(client, 7n, { id: 'synthetic', model: 'fixture.v1',
    choose: async () => ({ kind: 'choice', choice: pause, confidence: 1 }) }, input);
  assert.equal(advice.status, 'recommended');
  if (advice.status !== 'recommended') throw new Error('Missing recommendation');
  await assert.rejects(agent.buildCommand(client, advice, 11n), /decision kind/);
  assert.equal(decodeFunctionData({ abi: decisionsAbi, data: (await agent.buildCommand(client, advice, 0n)).data }).args?.[1], pause);
  const modified = structuredClone(advice);
  modified.receipt.configurationId = 'altered-config';
  await assert.rejects(agent.buildCommand(client, modified, 0n), /modified/);
});

test('in-flight app configuration is captured before provider execution', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  const mutable = { ...input };
  const provider: ChoiceProvider = { id: 'synthetic', model: 'fixture.v1', choose: async () => {
    mutable.minimumConfidence = 0;
    mutable.configurationId = 'different-config';
    return { kind: 'choice', choice: positive, confidence: 0.5 };
  } };
  const advice = await agent.advise(client, 7n, provider, mutable);
  assert.equal(advice.status, 'abstained');
  assert.equal(advice.receipt.configurationId, 'test-grants.v1');
  assert.equal(advice.receipt.minimumConfidence, 0.8);
});

test('custom provider metadata cannot copy an unvalidated response body into the receipt', async () => {
  const { client } = rpc();
  const agent = new AvaDecisionAgent(extensions, actor);
  for (const extra of [{ responseId: { body: input.input } }, { servedModel: ['private model body'] }]) {
    await assert.rejects(agent.advise(client, 7n, { id: 'synthetic', model: 'fixture.v1',
      choose: async () => ({ kind: 'choice', choice: positive, confidence: 1, ...extra }) as never }, input), /Invalid provider metadata/);
  }
});


test('cancellation during an empty snapshot rejects without contacting the provider and permits later advice', async () => {
  const { client, state } = rpc();
  state.options = [];
  let release!: () => void, entered!: () => void;
  state.hold = new Promise<void>(resolve => { release = resolve; });
  const started = new Promise<void>(resolve => { entered = resolve; });
  state.entered = entered;
  const controller = new AbortController();
  let calls = 0;
  const provider: ChoiceProvider = { id: 'synthetic', model: 'fixture.v1', choose: async () => {
    calls++; return { kind: 'choice', choice: positive, confidence: 1 };
  } };
  const agent = new AvaDecisionAgent(extensions, actor);
  const pending = agent.advise(client, 7n, provider, { ...input, signal: controller.signal });
  await started;
  controller.abort();
  release();
  await assert.rejects(pending, /Agent operation aborted/);
  assert.equal(calls, 0);
  state.hold = undefined;
  state.options = [...options];
  assert.equal((await agent.advise(client, 7n, provider, input)).status, 'recommended');
  assert.equal(calls, 1);
});
