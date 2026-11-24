import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, decodeFunctionData, encodeFunctionResult, zeroHash,
  type Address, type Hex } from 'viem';
import { AvaSdk, AvaReadError, avaAbis, type CoreAddresses, type ReadPoint } from '../src/index.ts';

const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}` as Address;
const hash = (byte: string) => `0x${byte.repeat(32)}` as Hex;
const addresses = Object.fromEntries(Object.keys(avaAbis).map((name, i) => [name, address(i + 1)])) as CoreAddresses;
const account = address(50), appId = hash('21'), roleKey = hash('22');
// Assigned by the registry, independently of account/app/role derivation.
const subjectId = hash('f3'), actionKey = hash('31'), otherAction = hash('32');
const query = { account, appId, roleKey, actionKeys: [actionKey, otherAction] };

function fixture() {
  const state = {
    chainId: 31337, head: hash('41'), snapshots: 0,
    canonical: subjectId, context: { subjectId, account, appId, roleKey, active: true },
    identityLink: addresses.identities, authorityLink: addresses.authority,
    allowed: new Map<Hex, boolean>([[actionKey, true], [otherAction, false]]),
    calls: [] as { name: string; args: readonly unknown[]; point: unknown }[],
    expectedPoint: undefined as unknown,
    fail: undefined as string | undefined,
    malformed: undefined as string | undefined,
    beforeChain: undefined as (() => void) | undefined,
  };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (state.fail === method) throw new Error('RPC https://secret-token:password@private.invalid');
    if (method === 'eth_chainId') {
      state.beforeChain?.();
      return `0x${state.chainId.toString(16)}`;
    }
    if (method === 'eth_getBlockByNumber') {
      assert.deepEqual(params, ['latest', false]);
      state.snapshots++;
      return { hash: state.head, number: '0x2a', transactions: [] };
    }
    assert.equal(method, 'eth_call');
    const [call, point] = params as [{ to: Address; data: Hex }, unknown];
    assert.deepEqual(point, state.expectedPoint ?? { blockHash: state.head, requireCanonical: true });
    const name = Object.keys(addresses).find(key => addresses[key as keyof CoreAddresses] === call.to) as keyof CoreAddresses;
    assert.ok(name, `Unexpected target ${call.to}`);
    const abi = avaAbis[name];
    const decoded = decodeFunctionData({ abi, data: call.data });
    const args = decoded.args ?? [];
    state.calls.push({ name: decoded.functionName, args, point });
    if (state.fail === decoded.functionName) throw new Error('RPC https://secret-token:password@private.invalid');
    if (state.malformed === decoded.functionName) return '0x1234';
    let result: unknown;
    switch (decoded.functionName) {
      case 'IDENTITY_REGISTRY': result = state.identityLink; break;
      case 'AUTHORITY_MATRIX': result = state.authorityLink; break;
      case 'subjectOf': assert.deepEqual(args, [account, appId, roleKey]); result = state.canonical; break;
      case 'getSubjectContext': assert.deepEqual(args, [subjectId]); result = state.context; break;
      case 'isAuthorised':
        assert.deepEqual(args.slice(0, 3), [account, appId, roleKey]);
        result = state.allowed.get(args[3] as Hex) ?? false; break;
      default: assert.fail(`Unexpected read ${decoded.functionName}`);
    }
    return encodeFunctionResult({ abi, functionName: decoded.functionName, result: result as never });
  } }, { retryCount: 0 }) });
  return { sdk: new AvaSdk({ chainId: 31337, addresses: { ...addresses } }), client, state };
}

test('canonical actor context preserves the assigned ID and each requested permission at one point', async () => {
  const { sdk, client, state } = fixture();
  assert.deepEqual(await sdk.actorContext(client, query), {
    account, appId, roleKey, subjectId, authority: { roleKey, authorityId: subjectId },
    permissions: [{ actionKey, allowed: true }, { actionKey: otherAction, allowed: false }],
    point: { blockHash: hash('41'), requireCanonical: true },
  });
  assert.equal(state.snapshots, 1);
  assert.equal(state.calls.filter(call => call.name === 'isAuthorised').length, 2);
});

test('missing or deactivated canonical identity returns null and false permissions', async () => {
  const { sdk, client, state } = fixture();
  // Core subjectOf returns zero for both missing and deactivated assignments.
  state.canonical = zeroHash;
  const missing = await sdk.actorContext(client, query);
  assert.equal(missing.subjectId, null);
  assert.equal(missing.authority, null);
  assert.deepEqual(missing.permissions, [{ actionKey, allowed: false }, { actionKey: otherAction, allowed: false }]);
  state.canonical = subjectId;
  assert.equal((await sdk.actorContext(client, query)).subjectId, subjectId);
  state.canonical = zeroHash;
  state.context.active = false;
  const deactivated = await sdk.actorContext(client, query);
  assert.equal(deactivated.subjectId, null);
  assert.equal(deactivated.authority, null);
  assert.ok(deactivated.permissions.every(permission => !permission.allowed));
});

test('a wrong RPC chain is unavailable rather than an identity or permission result', async () => {
  const { sdk, client, state } = fixture();
  state.chainId = 1;
  await assert.rejects(sdk.actorContext(client, query), AvaReadError);
  assert.equal(state.calls.length, 0);
  state.chainId = 31337;
  assert.equal((await sdk.actorContext(client, query)).subjectId, subjectId);
});

test('Kernel identity and authority links must match before records are joined', async t => {
  for (const link of ['identityLink', 'authorityLink'] as const) await t.test(link, async () => {
    const { sdk, client, state } = fixture();
    state[link] = address(99);
    await assert.rejects(sdk.actorContext(client, query), AvaReadError);
    assert.ok(!state.calls.some(call => ['subjectOf', 'getSubjectContext', 'isAuthorised'].includes(call.name)));
    state[link] = link === 'identityLink' ? addresses.identities : addresses.authority;
    assert.equal((await sdk.actorContext(client, query)).subjectId, subjectId);
  });
});

test('a nonzero canonical ID requires the same active subject context', async t => {
  const changes = { subjectId: zeroHash, account: address(99), appId: hash('91'), roleKey: hash('92'), active: false };
  for (const field of Object.keys(changes) as (keyof typeof changes)[]) await t.test(field, async () => {
    const { sdk, client, state } = fixture();
    state.context = { ...state.context, [field]: changes[field] };
    await assert.rejects(sdk.actorContext(client, query), AvaReadError);
    assert.ok(!state.calls.some(call => call.name === 'isAuthorised'));
    state.context = { subjectId, account, appId, roleKey, active: true };
    assert.equal((await sdk.actorContext(client, query)).subjectId, subjectId);
  });
});

test('fresh contexts observe permission revoke and restore without changing identity or past results', async () => {
  const { sdk, client, state } = fixture();
  const initial = await sdk.actorContext(client, query);
  state.allowed.set(actionKey, false);
  state.head = hash('42');
  const revoked = await sdk.actorContext(client, query);
  assert.equal(revoked.subjectId, subjectId);
  assert.deepEqual(revoked.authority, initial.authority);
  assert.equal(revoked.permissions[0].allowed, false);
  assert.deepEqual(revoked.point, { blockHash: hash('42'), requireCanonical: true });
  assert.equal(initial.permissions[0].allowed, true);
  state.allowed.set(actionKey, true);
  state.head = hash('43');
  const restored = await sdk.actorContext(client, query);
  assert.equal(restored.subjectId, subjectId);
  assert.equal(restored.permissions[0].allowed, true);
  assert.equal(revoked.permissions[0].allowed, false);
  assert.equal(state.snapshots, 3);
});

test('explicit genesis and canonical hash points never acquire a latest snapshot', async () => {
  const { sdk, client, state } = fixture();
  state.expectedPoint = '0x0';
  const genesis = await sdk.actorContext(client, query, 0n);
  assert.equal(genesis.point, 0n);
  const point: ReadPoint = { blockHash: hash('44'), requireCanonical: true };
  state.expectedPoint = { ...point };
  assert.deepEqual((await sdk.actorContext(client, query, point)).point, point);
  assert.equal(state.snapshots, 0);
});

test('actor query scalars, action list, chain and explicit point are captured before awaiting RPC', async () => {
  const { sdk, client, state } = fixture();
  const callerQuery = { ...query, actionKeys: [...query.actionKeys] };
  const callerPoint = { blockHash: hash('44'), requireCanonical: true as const };
  state.expectedPoint = { ...callerPoint };
  state.beforeChain = () => {
    callerQuery.account = address(99);
    callerQuery.appId = hash('91');
    callerQuery.roleKey = hash('92');
    callerQuery.actionKeys.splice(0, 2, hash('93'));
    callerPoint.blockHash = hash('94');
    sdk.deployment.chainId = 1;
    sdk.deployment.addresses.identities = address(98);
  };
  const captured = await sdk.actorContext(client, callerQuery, callerPoint);
  assert.deepEqual(captured, {
    account, appId, roleKey, subjectId, authority: { roleKey, authorityId: subjectId },
    permissions: [{ actionKey, allowed: true }, { actionKey: otherAction, allowed: false }],
    point: { blockHash: hash('44'), requireCanonical: true },
  });
});

test('transport failures at every read are safe errors and a later valid query recovers', async t => {
  for (const stage of ['eth_chainId', 'eth_getBlockByNumber', 'IDENTITY_REGISTRY', 'AUTHORITY_MATRIX',
    'subjectOf', 'getSubjectContext', 'isAuthorised']) await t.test(stage, async () => {
    const { sdk, client, state } = fixture();
    state.fail = stage;
    await assert.rejects(sdk.actorContext(client, query), error => {
      assert.ok(error instanceof AvaReadError);
      assert.equal(error.code, 'read_unavailable');
      assert.equal(error.message, 'AVA read unavailable');
      assert.equal(error.cause, undefined);
      assert.doesNotMatch(String(error.stack) + JSON.stringify(error), /secret-token|password|private\.invalid/);
      return true;
    });
    state.fail = undefined;
    assert.equal((await sdk.actorContext(client, query)).permissions[0].allowed, true);
  });
});

test('malformed registry and matrix responses cannot become business absence or denial', async t => {
  for (const stage of ['IDENTITY_REGISTRY', 'AUTHORITY_MATRIX', 'subjectOf', 'getSubjectContext', 'isAuthorised']) {
    await t.test(stage, async () => {
      const { sdk, client, state } = fixture();
      state.malformed = stage;
      await assert.rejects(sdk.actorContext(client, query), AvaReadError);
      state.malformed = undefined;
      assert.equal((await sdk.actorContext(client, query)).subjectId, subjectId);
    });
  }
});

test('callers can query identity without actions or preserve repeated requested actions', async () => {
  const { sdk, client, state } = fixture();
  const identity = await sdk.actorContext(client, { account, appId, roleKey });
  assert.equal(identity.subjectId, subjectId);
  assert.deepEqual(identity.permissions, []);
  assert.ok(!state.calls.some(call => call.name === 'isAuthorised'));
  const repeated = await sdk.actorContext(client, { account, appId, roleKey, actionKeys: [actionKey, actionKey] });
  assert.deepEqual(repeated.permissions, [{ actionKey, allowed: true }, { actionKey, allowed: true }]);
});
