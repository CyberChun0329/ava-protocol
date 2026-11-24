import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createPublicClient, custom, decodeFunctionData, encodeErrorResult, encodeFunctionResult, keccak256, zeroAddress, zeroHash,
  type Abi, type Address, type Hex } from 'viem';
import { AvaSdk, AvaReadError, type CoreAddresses } from '../src/index.ts';
import { AvaExtensions } from '../src/extensions.ts';
import type { InstallationExpectations } from '../src/installation.ts';
import { avaAbis, requestsAbi, correctionsAbi, executionAbi, decisionsAbi, procedureAbi, ruleGovernanceAbi,
  privacyAbi, governedDisclosureAbi, evidenceBindingsAbi } from '../src/abi.ts';

const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}` as Address;
const addresses = Object.fromEntries(['applications', 'identities', 'authority', 'packages',
  'disclosure', 'evidence', 'kernel', 'requests', 'challenges'].map((name, i) => [name, address(i + 1)])) as CoreAddresses;
const sdk = new AvaSdk({ chainId: 31337, addresses });
const optional = { decisions: address(20), procedure: address(21), ruleGovernance: address(22),
  privacy: address(23), governedDisclosure: address(24), evidenceBindings: address(25) };
const authority = { roleKey: `0x${'11'.repeat(32)}` as Hex, authorityId: `0x${'12'.repeat(32)}` as Hex };
const point = { blockHash: `0x${'41'.repeat(32)}` as Hex, requireCanonical: true as const };
type RpcEntry = { abi: Abi; values: Record<string, unknown | ((args: readonly unknown[]) => unknown)> };
function rpcBoundary(entries: Record<Address, RpcEntry>, code: Record<Address, Hex> = {}, beforeBlock?: () => void,
    retryCount = 3, rawResults: Record<string, Hex> = {}, observation?: {
      at: unknown; record: (address: Address, operation: string) => void;
    }) {
  return createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') return '0x7a69';
    if (method === 'eth_getBlockByNumber') {
      beforeBlock?.();
      assert.deepEqual(params, ['latest', false]);
      return { hash: point.blockHash, number: '0x2a', transactions: [] };
    }
    if (method === 'eth_getCode') {
      const [to, block] = params as [Address, unknown];
      assert.deepEqual(block, observation?.at ?? point);
      observation?.record(to, method);
      return code[to.toLowerCase() as Address] ?? '0x6000';
    }
    assert.equal(method, 'eth_call');
    const [call, block] = params as [{ to: Address; data: Hex }, unknown];
    assert.deepEqual(block, observation?.at ?? point);
    const entry = entries[call.to.toLowerCase() as Address];
    assert.ok(entry, `Unexpected RPC target ${call.to}`);
    const decoded = decodeFunctionData({ abi: entry.abi, data: call.data });
    observation?.record(call.to, decoded.functionName);
    assert.ok(Object.hasOwn(entry.values, decoded.functionName), `Unexpected read ${decoded.functionName}`);
    if (Object.hasOwn(rawResults, decoded.functionName)) return rawResults[decoded.functionName];
    const value = entry.values[decoded.functionName];
    return encodeFunctionResult({ abi: entry.abi, functionName: decoded.functionName,
      result: typeof value === 'function' ? value(decoded.args ?? []) : value });
  } }, { retryCount }) });
}
const correctionAddress = address(90), executionAddress = address(91), policyAddress = address(92);
function verificationEntries(): Record<Address, RpcEntry> {
  const links = { APPLICATION_REGISTRY: addresses.applications, IDENTITY_REGISTRY: addresses.identities,
    AUTHORITY_MATRIX: addresses.authority, RULE_PACKAGE_REGISTRY: addresses.packages,
    EVIDENCE_REGISTRY: addresses.evidence, DISCLOSURE_REGISTRY: addresses.disclosure,
    GOVERNANCE_KERNEL: addresses.kernel, CORRECTIONS: correctionAddress, EXECUTION: executionAddress,
    REQUEST_ALLOCATION: addresses.requests };
  const entries = Object.fromEntries(Object.entries(addresses).map(([name, to]) => [to,
    { abi: avaAbis[name as keyof typeof avaAbis], values: { ...links } }])) as Record<Address, RpcEntry>;
  entries[addresses.authority].values.isAuthorisedSubject = false;
  entries[correctionAddress] = { abi: correctionsAbi, values: { GOVERNANCE_KERNEL: addresses.kernel } };
  entries[executionAddress] = { abi: executionAbi, values: { REQUEST_ALLOCATION: addresses.requests } };
  entries[optional.decisions] = { abi: decisionsAbi, values: { GOVERNANCE_KERNEL: addresses.kernel,
    REQUEST_ALLOCATION: addresses.requests } };
  entries[optional.procedure] = { abi: procedureAbi, values: { GOVERNANCE_KERNEL: addresses.kernel,
    DECISION_REGISTRY: optional.decisions, REVIEW_POLICY: policyAddress, REVIEW_POLICY_IDENTITY: point.blockHash } };
  entries[policyAddress] = { abi: decisionsAbi, values: { moduleIdentityHash: point.blockHash } };
  entries[optional.ruleGovernance] = { abi: ruleGovernanceAbi,
    values: { GOVERNANCE_KERNEL: addresses.kernel, RULE_PACKAGE_REGISTRY: addresses.packages } };
  entries[optional.privacy] = { abi: privacyAbi, values: { AUTHORITY_MATRIX: addresses.authority } };
  entries[optional.evidenceBindings] = { abi: evidenceBindingsAbi,
    values: { PRIVACY_REGISTRY: optional.privacy, EVIDENCE_REGISTRY: addresses.evidence } };
  entries[optional.governedDisclosure] = { abi: governedDisclosureAbi,
    values: { PRIVACY_REGISTRY: optional.privacy, EVIDENCE_BINDINGS: optional.evidenceBindings,
      REQUEST_ALLOCATION: addresses.requests, APP_ID: authority.authorityId, WORKFLOW_KEY: authority.roleKey } };
  return entries;
}
const decisionRecord = { id: 8n, requestId: 3n,
  option: { key: zeroHash, kind: 2, actionKey: zeroHash, parametersHash: zeroHash,
    notBefore: 0n, conditionsHash: zeroHash }, actor: address(50), ...authority,
  evaluatedAt: 7n, reasonHash: zeroHash, previousDecisionId: 6n, supportRevision: 2n,
  witnessHash: zeroHash, witness: [], executionRequestId: 0n };
const decisionRequest = { id: 3n, input: { appId: zeroHash, workflowKey: zeroHash, packageId: 7n,
  requestHash: zeroHash, executor: address(50), responseClass: zeroHash, burdenHash: zeroHash, validUntil: 1000n },
  creator: address(51), creatorRoleKey: authority.roleKey, creatorAuthorityId: authority.authorityId,
  createdAt: 1n, supportRevision: 2n, lastDecisionId: 8n, allocationDecisionId: 0n, paused: true, closed: false };
const support = { revision: 1n, revisionHash: zeroHash, previousHash: zeroHash,
  updatedBy: address(51), ...authority, updatedAt: 2n, pool: [] };

test('optional decision commands preserve request terms and caller authority without adding mandatory Core addresses', () => {
  const extension = new AvaExtensions(sdk, { decisions: optional.decisions });
  const input = { appId: zeroHash, workflowKey: zeroHash, packageId: 7n, requestHash: zeroHash,
    executor: address(50), responseClass: zeroHash, burdenHash: zeroHash,
    validUntil: 1000n };
  const call = extension.openDecisionRequest(input, [], authority);
  assert.equal(call.to, optional.decisions);
  assert.deepEqual(decodeFunctionData({ abi: decisionsAbi, data: call.data }),
    { functionName: 'openRequest', args: [input, [], authority.roleKey, authority.authorityId] });
  assert.equal(Object.keys(sdk.deployment.addresses).length, 9);
  assert.throws(() => new AvaExtensions(sdk, {}).openDecisionRequest(input, [], authority), /decisions.*configured/);
});

test('optional verification checks code and reverse host links including discovered fixed dependencies', async () => {
  const entries = verificationEntries(), code: Record<Address, Hex> = {};
  const client = rpcBoundary(entries, code);
  const x = new AvaExtensions(sdk, optional);
  await x.verify(client, point);
  entries[optional.evidenceBindings].values.EVIDENCE_REGISTRY = addresses.challenges;
  await assert.rejects(x.verify(client, point), /evidenceBindings.*EVIDENCE_REGISTRY.*mismatch/);
  entries[optional.evidenceBindings].values.EVIDENCE_REGISTRY = addresses.evidence;
  entries[optional.procedure].values.DECISION_REGISTRY = address(93);
  await assert.rejects(x.verify(client, point), /procedure.*DECISION_REGISTRY.*mismatch/);
  entries[optional.procedure].values.DECISION_REGISTRY = optional.decisions;
  entries[policyAddress].values.moduleIdentityHash = zeroHash;
  await assert.rejects(x.verify(client, point), /REVIEW_POLICY_IDENTITY.*mismatch/);
  entries[policyAddress].values.moduleIdentityHash = point.blockHash;
  code[optional.privacy] = '0x';
  await assert.rejects(x.verify(client, point), /No code at privacy/);
  code[optional.privacy] = '0x6000';
  await new AvaExtensions(sdk, { procedure: optional.procedure,
    governedDisclosure: optional.governedDisclosure }).verify(client, point);
  assert.throws(() => new AvaExtensions(sdk, { privacy: zeroAddress }), /Invalid privacy/);
});

test('installation verification shares checks only within the same block-hash read', async () => {
  const calls = new Map<string, number>();
  const observation = { at: point as unknown, record(to: Address, operation: string) {
    const key = `${to.toLowerCase()}:${operation}`;
    calls.set(key, (calls.get(key) ?? 0) + 1);
  } };
  const client = rpcBoundary(verificationEntries(), {}, undefined, 0, {}, observation);
  const extensions = new AvaExtensions(sdk, optional);
  const expectCalls = (decision: number, privacy: number, bindings: number) => {
    for (const [to, operations, count] of [
      [optional.decisions, ['eth_getCode', 'GOVERNANCE_KERNEL', 'REQUEST_ALLOCATION'], decision],
      [addresses.authority, ['isAuthorisedSubject'], decision],
      [optional.privacy, ['eth_getCode', 'AUTHORITY_MATRIX'], privacy],
      [optional.evidenceBindings, ['eth_getCode', 'EVIDENCE_REGISTRY', 'PRIVACY_REGISTRY'], bindings],
    ] as const) {
      for (const operation of operations) {
        const key = `${to}:${operation}`;
        assert.equal(calls.get(key), count, key);
      }
    }
  };
  await extensions.verify(client, point);
  expectCalls(1, 1, 1);
  await extensions.verify(client, point);
  expectCalls(2, 2, 2);

  observation.at = '0x2a';
  calls.clear();
  await extensions.verify(client, 42n);
  expectCalls(2, 3, 2);
});

test('installation readiness reports scoped package, subject, permission and origin gaps without repairs', async () => {
  const entries = verificationEntries();
  const appId = authority.authorityId, workflowKey = authority.roleKey, subjectId = point.blockHash;
  const context = { packageId: 7n, appId, workflowKey, version: 2n,
    compatibilityKey: zeroHash, authorityId: subjectId };
  const expected: InstallationExpectations = { appId, workflowKey, activePackageId: 7n,
    historicalPackageIds: [6n], modules: [{ capabilityKey: zeroHash, module: optional.decisions }],
    requiredSubjects: [{ account: address(50), roleKey: authority.roleKey, subjectId,
      actionKeys: [authority.authorityId] }], correctionOrigins: [addresses.requests] };
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: subjectId, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = (args: readonly unknown[]) => ({ ...context, packageId: args[0] });
  entries[addresses.packages].values.getVerifiedModulesCompact = [context, [optional.decisions]];
  entries[addresses.identities].values.getSubjectContext = { subjectId, appId,
    roleKey: authority.roleKey, account: address(50), active: true };
  entries[addresses.identities].values.subjectOf = subjectId;
  entries[addresses.authority].values.isAuthorised = true;
  entries[correctionAddress].values.requestOriginCodeHash = keccak256('0x6000');
  entries[correctionAddress].values.requestOriginDisabled = false;
  const x = new AvaExtensions(sdk, optional), client = rpcBoundary(entries);
  const ready = await x.verifyInstallation(client, expected, point);
  assert.equal(ready.ready, true);
  assert.deepEqual(ready.point, point);
  assert.deepEqual(ready.findings, []);
  assert.equal((await x.verifyInstallation(client, expected)).ready, true);
  const forbidden = { account: address(50), roleKey: authority.roleKey, actionKey: point.blockHash };
  const restricted = { ...expected, forbiddenPermissions: [forbidden] };
  const forbiddenCheck = `permission:forbidden:${forbidden.account}:${forbidden.roleKey}:${forbidden.actionKey}`;
  const excessive = await x.verifyInstallation(client, restricted, point);
  assert.equal(excessive.ready, false);
  assert.deepEqual(excessive.findings.map(f => [f.check, f.status]), [[forbiddenCheck, 'mismatch']]);
  entries[addresses.authority].values.isAuthorised = ([, , , action]: readonly unknown[]) => {
    if (action === forbidden.actionKey) throw { code: -32603, message: 'SYNTHETIC_PRIVATE_PERMISSION_ERROR' };
    return true;
  };
  const unavailable = await x.verifyInstallation(rpcBoundary(entries, {}, undefined, 0), restricted, point);
  assert.equal(unavailable.ready, false);
  assert.deepEqual(unavailable.findings, [{ check: forbiddenCheck, status: 'unavailable', detail: 'read_unavailable' }]);
  entries[addresses.authority].values.isAuthorised = ([, , , action]: readonly unknown[]) => action !== forbidden.actionKey;
  assert.equal((await x.verifyInstallation(client, restricted, point)).ready, true);
  entries[addresses.packages].values.getActivePackageId = 8n;
  entries[addresses.packages].values.getVerifiedModulesCompact = [context, [zeroAddress]];
  entries[addresses.identities].values.getSubjectContext = { subjectId, appId,
    roleKey: authority.roleKey, account: address(50), active: false };
  entries[addresses.authority].values.isAuthorised = false;
  entries[correctionAddress].values.requestOriginDisabled = true;
  const gaps = await x.verifyInstallation(client, expected, point);
  assert.equal(gaps.ready, false);
  assert.deepEqual(gaps.findings.map(f => [f.check, f.status]), [
    ['activePackage', 'mismatch'], ['module:7:' + zeroHash, 'missing'],
    ['subject:' + subjectId + ':active', 'missing'],
    ['permission:' + subjectId + ':' + authority.authorityId, 'missing'],
    ['correctionOrigin:' + addresses.requests + ':enabled', 'missing'],
  ]);
  entries[correctionAddress].values.requestOriginCodeHash = zeroHash;
  const unbound = await x.verifyInstallation(client, expected, point);
  assert.ok(unbound.findings.some(f => f.check.endsWith(':codePin') && f.status === 'missing'));
  await assert.rejects(x.verifyInstallation(client, { ...expected, activePackageId: 0n }, point));
});

test('installation reuses the correction registry only within one block-hash check', async () => {
  const entries = verificationEntries(), appId = authority.authorityId, workflowKey = authority.roleKey;
  const origins = [addresses.requests, optional.ruleGovernance];
  const requirements = { appId, workflowKey, activePackageId: 7n, correctionOrigins: origins };
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: point.blockHash, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = { packageId: 7n, appId, workflowKey,
    version: 1n, compatibilityKey: zeroHash, authorityId: point.blockHash };
  entries[correctionAddress].values.requestOriginCodeHash = keccak256('0x6000');
  entries[correctionAddress].values.requestOriginDisabled = ([, origin]: readonly unknown[]) => origin === origins[1];
  const extensions = new AvaExtensions(sdk, {});
  let discoveries = 0, failSecondDiscovery = false;
  entries[addresses.kernel].values.CORRECTIONS = () => {
    discoveries++;
    if (failSecondDiscovery && discoveries === 2) throw { code: -32603, message: 'RPC unavailable' };
    return correctionAddress;
  };
  const gaps = [{ check: `correctionOrigin:${origins[1]}:enabled`, status: 'missing',
    detail: 'Required correction origin is prospectively disabled' }];
  const client = rpcBoundary(entries, {}, undefined, 0);
  for (let run = 0; run < 2; run++) {
    discoveries = 0;
    assert.deepEqual((await extensions.verifyInstallation(client, requirements, point)).findings, gaps);
    assert.equal(discoveries, 2);
  }
  const byNumber = rpcBoundary(entries, {}, undefined, 0, {}, { at: '0x2a', record() {} });
  discoveries = 0;
  assert.deepEqual((await extensions.verifyInstallation(byNumber, requirements, 42n)).findings, gaps);
  assert.equal(discoveries, 3);
  discoveries = 0;
  failSecondDiscovery = true;
  assert.deepEqual((await extensions.verifyInstallation(client, requirements, point)).findings, [
    { check: `correctionOrigin:${origins[0]}`, status: 'unavailable', detail: 'read_unavailable' }, ...gaps,
  ]);
  assert.equal(discoveries, 3);
});

test('installation readiness verifies current admins and actionable nominations at one canonical point', async () => {
  const entries = verificationEntries(), appId = authority.authorityId, workflowKey = authority.roleKey;
  const root = address(50), delegate = address(51), successor = address(52);
  const application = entries[addresses.applications].values;
  application.getApplication = { appId, applicationIdentityHash: point.blockHash, authorityId: point.blockHash,
    uri: 'ava:app', registeredBy: root };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = { packageId: 7n, appId, workflowKey,
    version: 1n, compatibilityKey: zeroHash, authorityId: point.blockHash };
  Object.assign(application, { ADMIN: root, applicationAdmin: delegate, pendingAdmin: zeroAddress,
    pendingApplicationAdmin: successor, adminVersion: 2n, pendingApplicationAdminVersion: 1n });
  const administration = { root, application: delegate, pendingRoot: zeroAddress, pendingApplication: zeroAddress };
  const expected: InstallationExpectations = { appId, workflowKey, activePackageId: 7n, administration };
  const extensions = new AvaExtensions(sdk, {}), client = rpcBoundary(entries, {}, undefined, 0);
  assert.equal((await extensions.verifyInstallation(client, expected, point)).ready, true);

  Object.assign(application, { ADMIN: successor, applicationAdmin: successor, pendingAdmin: delegate,
    pendingApplicationAdminVersion: 2n });
  const wrong = await extensions.verifyInstallation(client, expected, point);
  assert.equal(wrong.ready, false);
  assert.deepEqual(wrong.findings.map(f => [f.check, f.status]), [
    ['administration:root', 'mismatch'], ['administration:application', 'mismatch'],
    ['administration:pendingRoot', 'mismatch'], ['administration:pendingApplication', 'mismatch'],
  ]);
  assert.equal((await extensions.verifyInstallation(client, { ...expected, administration: {
    root: successor, application: successor, pendingRoot: delegate, pendingApplication: successor,
  } }, point)).ready, true);

  Object.assign(application, { ADMIN: root, applicationAdmin: delegate, pendingAdmin: zeroAddress,
    pendingApplicationAdminVersion: () => { throw { code: -32603, message: 'SYNTHETIC_PRIVATE_RPC' }; } });
  const unavailable = await extensions.verifyInstallation(client, expected, point);
  assert.equal(unavailable.ready, false);
  assert.deepEqual(unavailable.findings, [{ check: 'administration:pendingApplication', status: 'unavailable',
    detail: 'read_unavailable' }]);
  application.pendingApplicationAdmin = zeroAddress;
  assert.equal((await extensions.verifyInstallation(client, expected, point)).ready, true);
});

test('readiness distinguishes unavailable reads from missing records and recovers with safe details', async () => {
  const entries = verificationEntries(), appId = authority.authorityId, workflowKey = authority.roleKey;
  const application = { appId, applicationIdentityHash: zeroHash, authorityId: point.blockHash,
    uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = { packageId: 7n, appId, workflowKey,
    version: 2n, compatibilityKey: zeroHash, authorityId: point.blockHash };
  entries[addresses.applications].values.getApplication = () => {
    throw { code: -32603, message: 'SYNTHETIC_PRIVATE_PROVIDER_ERROR' };
  };
  const x = new AvaExtensions(sdk, {}), client = rpcBoundary(entries), expected = { appId, workflowKey, activePackageId: 7n };
  const unavailable = await x.verifyInstallation(client, expected, point);
  assert.equal(unavailable.findings.find(item => item.check === 'application')?.status, 'unavailable');
  assert(!JSON.stringify(unavailable.findings).includes('SYNTHETIC_PRIVATE'));
  entries[addresses.applications].values.getApplication = () => {
    throw { code: 3, message: 'execution reverted', data: encodeErrorResult({ abi: avaAbis.applications,
      errorName: 'UnknownReference', args: [7n] }) };
  };
  const missing = await x.verifyInstallation(client, expected, point);
  assert.equal(missing.findings.find(item => item.check === 'application')?.status, 'missing');
  entries[addresses.applications].values.getApplication = application;
  assert.equal((await x.verifyInstallation(client, expected, point)).ready, true);
  let failedSnapshot = true;
  const defaultClient = rpcBoundary(entries, {}, () => {
    if (failedSnapshot) throw { code: -32603, message: 'SYNTHETIC_PRIVATE_SNAPSHOT_PROVIDER' };
  });
  await assert.rejects(x.verifyInstallation(defaultClient, expected), error =>
    error instanceof AvaReadError && error.code === 'read_unavailable' && error.cause === undefined
      && !String(error).includes('SYNTHETIC_PRIVATE'));
  failedSnapshot = false;
  const recovered = await x.verifyInstallation(defaultClient, expected);
  assert.equal(recovered.ready, true);
  assert.deepEqual(recovered.point, point);
});

test('readiness checks declared source correction bindings and their current identities without installing them', async () => {
  const entries = verificationEntries();
  const appId = authority.authorityId, workflowKey = authority.roleKey;
  const context = { packageId: 7n, appId, workflowKey, version: 2n,
    compatibilityKey: zeroHash, authorityId: point.blockHash };
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: point.blockHash, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = context;
  const kernel = entries[addresses.kernel].values;
  kernel.sourceBoundTransitionRequesterByPackage = zeroAddress;
  kernel.transitionGuardByPackage = zeroAddress;
  kernel.postTransitionHookByPackage = zeroAddress;
  kernel.requireStablePackageBindings = undefined;
  const expected = { appId, workflowKey, activePackageId: 7n,
    sourceCorrectionBindings: [{ requester: addresses.challenges, guard: addresses.challenges, hook: zeroAddress }] };
  const x = new AvaExtensions(sdk, {}), client = rpcBoundary(entries);
  const missing = await x.verifyInstallation(client, expected, point);
  assert.equal(missing.ready, false);
  assert.deepEqual(missing.findings.map(f => [f.check, f.status]), [
    ['sourceCorrection:7:requester', 'missing'], ['sourceCorrection:7:guard', 'missing']]);
  kernel.sourceBoundTransitionRequesterByPackage = addresses.challenges;
  kernel.transitionGuardByPackage = optional.privacy;
  const mismatch = await x.verifyInstallation(client, expected, point);
  assert(mismatch.findings.some(f => f.check === 'sourceCorrection:7:guard' && f.status === 'mismatch'));
  kernel.transitionGuardByPackage = addresses.challenges;
  assert.equal((await x.verifyInstallation(client, expected, point)).ready, true);
  kernel.requireStablePackageBindings = () => { throw new Error('bound module identity drift'); };
  assert((await x.verifyInstallation(client, expected, point)).findings.some(f => f.check === 'sourceCorrection:7:stable'));
  kernel.requireStablePackageBindings = undefined;
  kernel.postTransitionHookByPackage = optional.privacy;
  assert((await x.verifyInstallation(client, expected, point)).findings.some(f => f.check === 'sourceCorrection:7:hook'));
  assert.equal((await x.verifyInstallation(client, { ...expected,
    sourceCorrectionBindings: [{ requester: zeroAddress, guard: zeroAddress }] }, point)).ready, false);
});

test('readiness pins a default snapshot and rejects historical scope, controller identity and module mismatches', async () => {
  const entries = verificationEntries();
  const appId = authority.authorityId, workflowKey = authority.roleKey;
  const context = { packageId: 7n, appId, workflowKey, version: 2n,
    compatibilityKey: zeroHash, authorityId: point.blockHash };
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: point.blockHash, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = (args: readonly unknown[]) => ({ ...context, packageId: args[0] });
  entries[addresses.packages].values.getVerifiedModulesCompact = [context, [optional.decisions]];
  entries[addresses.packages].values.getGovernanceBinding = { controller: optional.ruleGovernance,
    identityHash: point.blockHash, bootstrapPackageId: 6n };
  entries[optional.ruleGovernance].values.moduleIdentityHash = point.blockHash;
  const expected: InstallationExpectations = { appId, workflowKey, activePackageId: 7n,
    historicalPackageIds: [6n], modules: [{ capabilityKey: zeroHash, module: optional.decisions }],
    governanceController: optional.ruleGovernance };
  const x = new AvaExtensions(sdk, optional), client = rpcBoundary(entries);
  const ready = await x.verifyInstallation(client, expected);
  assert.equal(ready.ready, true);
  assert.deepEqual(ready.point, point);
  entries[addresses.packages].values.getVerifiedPackageContext = (args: readonly unknown[]) => ({
    ...context, packageId: args[0], appId: args[0] === 6n ? zeroHash : appId });
  entries[addresses.packages].values.getVerifiedModulesCompact = [context, [address(60)]];
  entries[optional.ruleGovernance].values.moduleIdentityHash = zeroHash;
  entries[optional.governedDisclosure].values.WORKFLOW_KEY = zeroHash;
  const mismatched = await x.verifyInstallation(client, expected, point);
  assert.equal(mismatched.ready, false);
  assert.deepEqual(mismatched.findings.map(f => [f.check, f.status]), [
    ['package:6:app', 'missing'], ['module:7:' + zeroHash, 'mismatch'],
    ['governanceController:identity', 'missing'], ['governedDisclosure:workflow', 'missing'],
  ]);
  entries[addresses.packages].values.getVerifiedPackageContext = () => { throw new Error('RPC temporarily unavailable'); };
  assert.ok((await x.verifyInstallation(client, expected, point)).findings.some(f => f.status === 'unavailable'));
});

test('readiness binds the requirements supplied before an asynchronous RPC and permits a later changed request', async () => {
  const entries = verificationEntries();
  const appId = authority.authorityId, workflowKey = authority.roleKey, subjectId = point.blockHash;
  const context = { packageId: 7n, appId, workflowKey, version: 2n,
    compatibilityKey: zeroHash, authorityId: subjectId };
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: subjectId, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = context;
  entries[addresses.packages].values.getVerifiedModulesCompact = [context, [optional.decisions]];
  entries[addresses.identities].values.getSubjectContext = { subjectId, appId,
    roleKey: authority.roleKey, account: address(50), active: true };
  entries[addresses.identities].values.subjectOf = subjectId;
  entries[addresses.authority].values.isAuthorised = false;
  const module = { capabilityKey: zeroHash, module: address(60) };
  const actionKeys = [authority.authorityId];
  const expected: InstallationExpectations = { appId, workflowKey, activePackageId: 7n,
    modules: [module], requiredSubjects: [{ account: address(50), roleKey: authority.roleKey, subjectId, actionKeys }] };
  const upstream = rpcBoundary(entries, {}, undefined, 0);
  let release!: () => void, started!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const firstRpc = new Promise<void>(resolve => { started = resolve; });
  let blocked = false;
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async args => {
    if (!blocked) { blocked = true; started(); await gate; }
    return upstream.request(args as never);
  } }, { retryCount: 0 }) });
  const x = new AvaExtensions(sdk, {});
  const pending = x.verifyInstallation(client, expected);
  await firstRpc;
  module.module = optional.decisions;
  actionKeys.length = 0;
  release();
  const original = await pending;
  assert.equal(original.ready, false);
  assert.deepEqual(original.findings.map(f => [f.check, f.status]), [
    ['module:7:' + zeroHash, 'mismatch'], ['permission:' + subjectId + ':' + authority.authorityId, 'missing'],
  ]);
  assert.equal((await x.verifyInstallation(client, expected)).ready, true);
});

test('decision history keeps exact support revisions and procedure dispositions at one canonical point', async () => {
  const client = rpcBoundary({ [optional.decisions]: { abi: decisionsAbi, values: {
    getRequest: decisionRequest, getDecision: decisionRecord,
    getSupportRevision: (args: readonly unknown[]) => {
      assert.equal(args[0], 3n);
      return { ...support, revision: args[1] };
    }, procedureDisposition: 12n, procedureReviewIdByDecision: 0n, constitutionalReviewIdByDecision: 12n,
    getEligibleWitnesses: [], getAdmissibleDecisions: [decisionRecord.option],
  } } });
  const x = new AvaExtensions(sdk, { decisions: optional.decisions });
  const request = await x.decisionRequest(client, 3n, point);
  assert.equal(request.record.lastDecisionId, 8n);
  assert.equal(request.support?.revision, 2n);
  assert.equal(request.latestDecision?.record.option.kind, 2);
  assert.equal(request.latestDecision?.execution, null);
  assert.equal(request.latestDecision?.procedureDispositionId, 12n);
  assert.equal(request.latestDecision?.constitutionalReviewId, 12n);
  assert.equal((await x.decisionSupport(client, 3n, 1n, point)).revision, 1n);
  assert.deepEqual(await x.admissibleDecisions(client, 3n, address(50), authority, point), [decisionRecord.option]);
  assert.deepEqual(await x.eligibleDecisionWitnesses(client, 3n, point), []);
});

test('privacy history retains immutable bindings while current access and usability remain separate', async () => {
  const binding = { evidenceId: 9n, resourceId: zeroHash, appId: zeroHash, caseId: zeroHash,
    privacyPolicyId: 5n, materialClass: zeroHash, ciphertextHash: zeroHash,
    workflowKey: zeroHash, packageId: 7n, subjectId: authority.authorityId, disclosurePolicyId: 6n };
  const client = rpcBoundary({
    [optional.privacy]: { abi: privacyAbi, values: {
      policyContext: [zeroHash, false], getPolicyRules: [], caseContext: [zeroHash, 5n, 2],
      resourceContext: [zeroHash, zeroHash, 5n, zeroHash, zeroHash, false],
      isMember: false, membershipGeneration: 3n, membershipDeadline: 100n,
      canAccess: false, accessDeadline: 100n, grantRevision: 4n,
      accessBasis: [optional.governedDisclosure, 7n, point.blockHash],
    } },
    [optional.evidenceBindings]: { abi: evidenceBindingsAbi, values: {
      getBinding: binding, resourceBinding: [9n, zeroHash, 7n, 6n, false],
    } },
  });
  const x = new AvaExtensions(sdk, optional);
  assert.deepEqual(await x.privacyPolicy(client, 5n, point), { appId: zeroHash, active: false, rules: [] });
  assert.equal((await x.privacyCase(client, zeroHash, point)).phase, 2);
  assert.equal((await x.privacyResource(client, zeroHash, point)).active, false);
  assert.deepEqual(await x.privacyMembership(client, zeroHash, zeroHash, zeroHash, point),
    { member: false, generation: 3n, expiresAt: 100n });
  assert.deepEqual(await x.privacyAccess(client, zeroHash, zeroHash, zeroHash, zeroHash, point),
    { allowed: false, expiresAt: 100n, revision: 4n, executor: optional.governedDisclosure,
      requestId: 7n, effectHash: point.blockHash });
  assert.deepEqual(await x.privateEvidence(client, 9n, point), { binding, usable: false });
});

test('procedure, governance and privacy builders encode exact explicit terms for the caller signer', () => {
  const x = new AvaExtensions(sdk, optional);
  const finding = { existingFindingId: 17n, supersedesFindingId: 0n, claimHash: zeroHash,
    useScopeHash: zeroHash, burdenHash: zeroHash };
  const resolution = { challengeId: 3n, expectedCurrentDecisionId: 8n, outcome: 2,
    replacementKey: zeroHash, decisionEvidenceId: 9n, ...authority, reasonHash: zeroHash, finding };
  const proposal = { sourceStateId: 3n, expectedSourceTransitionId: 4n,
    expectedTargetPackageId: 2n, correctionOfAppliedProposal: 1n };
  const proposed = { appId: zeroHash, workflowKey: zeroHash, ...authority,
    version: 2n, compatibilityKey: zeroHash, uri: 'ava:revision' };
  const bindings = [{ capabilityKey: zeroHash, module: address(51) }];
  const rules = [{ materialClass: zeroHash, readerRole: zeroHash, purpose: zeroHash,
    phaseMask: 1, maxLeaseSeconds: 60n, allocationExecutor: optional.governedDisclosure }];
  const parameters = { resourceId: zeroHash, persona: zeroHash, readerRole: zeroHash, purpose: zeroHash,
    expiresAt: 200n, membershipGeneration: 3n, grantRevision: 4n };
  const cases: [ReturnType<typeof x.openDecisionRequest>, Abi, string, readonly unknown[], Address][] = [
    [x.updateDecisionSupport(3n, [], 2n, authority), decisionsAbi, 'updateSupport',
      [3n, [], 2n, authority.roleKey, authority.authorityId], optional.decisions],
    [x.chooseDecision(3n, zeroHash, 7n, 8n, authority, zeroHash), decisionsAbi, 'choose',
      [3n, zeroHash, 7n, 8n, authority.roleKey, authority.authorityId, zeroHash], optional.decisions],
    [x.fileProcedureChallenge(8n, 9n, authority, zeroHash), procedureAbi, 'file',
      [8n, 9n, authority.roleKey, authority.authorityId, zeroHash], optional.procedure],
    [x.resolveProcedureChallenge(resolution), procedureAbi, 'resolve', [resolution], optional.procedure],
    [x.registerRuleProposal(proposal, proposed, bindings, authority), ruleGovernanceAbi, 'registerProposal',
      [proposal, proposed, bindings, authority.roleKey, authority.authorityId], optional.ruleGovernance],
    [x.executeRuleProposal(6n, proposed, bindings, authority), ruleGovernanceAbi, 'executeProposal',
      [6n, proposed, bindings, authority.roleKey, authority.authorityId], optional.ruleGovernance],
    [x.publishPrivacyPolicy(zeroHash, authority, rules), privacyAbi, 'publishPolicy',
      [zeroHash, authority.roleKey, authority.authorityId, rules], optional.privacy],
    [x.openPrivacyCase(zeroHash, zeroHash, 5n, authority), privacyAbi, 'openCase',
      [zeroHash, zeroHash, 5n, authority.roleKey, authority.authorityId], optional.privacy],
    [x.advancePrivacyPhase(zeroHash, 2, authority), privacyAbi, 'advancePhase',
      [zeroHash, 2, authority.roleKey, authority.authorityId], optional.privacy],
    [x.setPrivacyMember(zeroHash, zeroHash, zeroHash, 200n, true, authority), privacyAbi, 'setMember',
      [zeroHash, zeroHash, zeroHash, 200n, true, authority.roleKey, authority.authorityId], optional.privacy],
    [x.registerPrivateResource(zeroHash, zeroHash, zeroHash, zeroHash, authority), privacyAbi, 'registerResource',
      [zeroHash, zeroHash, zeroHash, zeroHash, authority.roleKey, authority.authorityId], optional.privacy],
    [x.grantPrivacyAccess(zeroHash, zeroHash, zeroHash, zeroHash, 200n, authority), privacyAbi, 'grantAccess',
      [zeroHash, zeroHash, zeroHash, zeroHash, 200n, authority.roleKey, authority.authorityId], optional.privacy],
    [x.revokePrivacyAccess(zeroHash, zeroHash, zeroHash, zeroHash, authority), privacyAbi, 'revokeAccess',
      [zeroHash, zeroHash, zeroHash, zeroHash, authority.roleKey, authority.authorityId], optional.privacy],
    [x.deactivatePrivacyPolicy(5n, authority), privacyAbi, 'deactivatePolicy',
      [5n, authority.roleKey, authority.authorityId], optional.privacy],
    [x.deactivatePrivateResource(zeroHash, authority), privacyAbi, 'deactivateResource',
      [zeroHash, authority.roleKey, authority.authorityId], optional.privacy],
    [x.bindPrivateEvidence(9n, zeroHash, authority), evidenceBindingsAbi, 'bindEvidence',
      [9n, zeroHash, authority.roleKey, authority.authorityId], optional.evidenceBindings],
    [x.executeDisclosure(7n, parameters), governedDisclosureAbi, 'executeDisclosure',
      [7n, parameters], optional.governedDisclosure],
  ];
  for (const [call, abi, functionName, args, to] of cases) {
    assert.equal(call.to, to);
    assert.deepEqual(decodeFunctionData({ abi, data: call.data }), { functionName, args });
  }
});

test('supported and decision execution builders bridge witnessed exact requests to the existing signer', () => {
  const x = new AvaExtensions(sdk, {});
  const input = { recognisedStateId: 2n, executor: address(50), responseClass: zeroHash,
    parametersHash: point.blockHash, burdenHash: authority.roleKey, validUntil: 1000n };
  const witness = [{ recognisedStateId: 2n, transitionId: 5n,
    scope: { claimHash: zeroHash, useHash: point.blockHash, burdenHash: authority.roleKey } }];
  const allocator = { roleKey: point.blockHash, authorityId: zeroHash };
  for (const [call, functionName, args] of [
    [x.createSupportedRequest(input, witness, authority), 'createSupportedRequest',
      [input, witness, authority.roleKey, authority.authorityId]],
    [x.createSupportedAndApproveRequest(input, witness, authority, allocator), 'createSupportedAndApproveRequest',
      [input, witness, { creatorRole: authority.roleKey, creatorAuthority: authority.authorityId,
        allocatorRole: allocator.roleKey, allocatorAuthority: allocator.authorityId }]],
    [x.createDecisionRequest(3n, input, witness, authority), 'createDecisionRequest',
      [3n, input, witness, authority.roleKey, authority.authorityId]],
    [x.createDecisionRequestForPackage(3n, 7n, input, witness, authority), 'createDecisionRequestForPackage',
      [3n, 7n, input, witness, authority.roleKey, authority.authorityId]],
  ] as const) {
    assert.equal(call.to, addresses.requests);
    assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: call.data }), { functionName, args });
  }
});

test('procedural origin projection keeps finding, disposition and decision separate using its fixed registry', async () => {
  const challenge = { id: 4n, decisionId: 8n, requestId: 3n, challenger: address(51),
    challengerAuthorityId: authority.authorityId, evidenceId: 9n, reasonHash: zeroHash,
    filedAt: 10n, resolutionId: 12n };
  const resolution = { id: 12n, challengeId: 4n, currentDecisionId: 8n, replacementDecisionId: 0n,
    outcome: 2, resolver: address(50), resolverAuthorityId: authority.authorityId,
    decisionEvidenceId: 10n, replacementKey: zeroHash, reasonHash: zeroHash, resolvedAt: 11n };
  const finding = { id: 11n, caseId: 7n, targetVersion: 8n, claimHash: point.blockHash,
    useScopeHash: zeroHash, burdenHash: zeroHash, evidenceId: 10n,
    verifierAuthorityId: authority.authorityId, verifier: address(50), formationAction: zeroHash,
    supersedesFindingId: 0n, independentReview: false, formedAt: 11n };
  const record = { id: 7n, origin: optional.procedure, acceptedAt: 10n, reviewId: 0n,
    input: { kind: 3, appId: zeroHash, workflowKey: zeroHash, packageId: 7n, targetPackageId: 7n,
      sourceStateId: 0n, originCaseId: 4n, targetId: 8n, originalTargetVersion: 8n,
      filingEvidenceId: 9n, challengerSubjectId: authority.authorityId, originalActor: address(50),
      challenger: address(51), affectedActor: address(50) } };
  let snapshots = 0;
  const client = rpcBoundary({
    [addresses.kernel]: { abi: avaAbis.kernel, values: { CORRECTIONS: correctionAddress } },
    [correctionAddress]: { abi: correctionsAbi, values: { getCase: record,
      findingIdByCase: 11n, getFinding: finding, supersededByFindingId: 0n } },
    [optional.procedure]: { abi: procedureAbi, values: { DECISION_REGISTRY: optional.decisions,
      getChallenge: challenge, getResolution: resolution, correctionReviewCaseIdByChallenge: 7n } },
    [optional.decisions]: { abi: decisionsAbi, values: { getDecision: decisionRecord,
      procedureDisposition: 12n, procedureReviewIdByDecision: 0n, constitutionalReviewIdByDecision: 0n } },
  }, {}, () => { snapshots++; });
  const x = new AvaExtensions(sdk, { procedure: optional.procedure });
  const history = await x.procedureChallenge(client, 4n, point);
  assert.equal(history.correction?.finding?.id, 11n);
  assert.equal(history.resolution?.id, 12n);
  assert.equal(history.decision.execution, null);
  const projected = await x.correctionCase(client, 7n, point);
  assert.equal(projected.finding?.claimHash, point.blockHash);
  assert.equal(projected.originRecord?.family, 'procedure');
  if (projected.originRecord?.family === 'procedure') {
    assert.equal(projected.originRecord.resolution?.outcome, 2);
    assert.equal(projected.originRecord.decision.record.id, 8n);
  }
  assert.equal((await x.procedureResolution(client, 12n, point)).decisionEvidenceId, 10n);
  assert.equal(snapshots, 0);
  assert.equal((await x.correctionCase(client, 7n)).originRecord?.family, 'procedure');
  assert.equal(snapshots, 1, 'Core and procedural origin must reuse the same outer point');
  assert.equal((await x.procedureChallenge(client, 4n)).correction?.finding?.id, 11n);
  assert.equal(snapshots, 2, 'a fresh outer read gets one fresh point, without nested latest reads');
});

test('rule proposal history exposes ratification and activation as separate retained occurrences', async () => {
  const proposal = { id: 2n, appId: zeroHash, targetWorkflowKey: authority.roleKey,
    sourceStateId: 3n, sourceObjectId: 4n, sourceTransitionId: 5n, governancePackageId: 6n,
    expectedTargetPackageId: 7n, sourceSubjectId: authority.authorityId, revisionCommitment: point.blockHash,
    proposalCommitment: point.blockHash, proposedVersion: 2n, proposedAuthorityId: authority.authorityId,
    proposedRoleKey: authority.roleKey, correctionOfAppliedProposal: 1n, proposer: address(50),
    proposerRoleKey: authority.roleKey, proposerAuthorityId: authority.authorityId,
    recognisedBy: address(51), sourceDecisionActor: address(52), recognisedAt: 10n,
    submittedAt: 11n, ratificationId: 0n, activationId: 0n };
  const ratification = { id: 8n, proposalId: 2n, sourceStateId: 3n, sourceTransitionId: 5n,
    governancePackageId: 6n, previousPackageId: 7n, revisionCommitment: point.blockHash,
    actor: address(53), actorRoleKey: authority.roleKey, actorAuthorityId: authority.authorityId, ratifiedAt: 12n };
  const activation = { id: 9n, proposalId: 2n, ratificationId: 8n, appId: zeroHash,
    targetWorkflowKey: authority.roleKey, sourceStateId: 3n, sourceTransitionId: 5n,
    governancePackageId: 6n, previousPackageId: 7n, replacementPackageId: 10n,
    revisionCommitment: point.blockHash, correctionOfAppliedProposal: 1n, actor: address(53),
    actorAuthorityId: authority.authorityId, activatedAt: 13n };
  const client = rpcBoundary({ [optional.ruleGovernance]: { abi: ruleGovernanceAbi, values: {
    getProposal: proposal, getRatification: ratification, getActivation: activation,
  } } });
  const x = new AvaExtensions(sdk, { ruleGovernance: optional.ruleGovernance });
  const pending = await x.ruleProposal(client, 2n, point);
  assert.equal(pending.record.sourceTransitionId, 5n);
  assert.equal(pending.ratification, null);
  assert.equal(pending.activation, null);
  proposal.ratificationId = 8n;
  proposal.activationId = 9n;
  const applied = await x.ruleProposal(client, 2n, point);
  assert.equal(applied.ratification?.actor, address(53));
  assert.equal(applied.activation?.replacementPackageId, 10n);
  assert.deepEqual(await x.ruleRatification(client, 8n, point), ratification);
  assert.deepEqual(await x.ruleActivation(client, 9n, point), activation);
});

test('rule proposal terms verify ordered module bindings against the sealed recorded revision', async () => {
  const appId = authority.authorityId, workflowKey = authority.roleKey, controller = optional.ruleGovernance;
  const proposed = { appId, workflowKey, roleKey: authority.roleKey, authorityId: authority.authorityId,
    version: 2n, compatibilityKey: point.blockHash, uri: 'local:revision-2' };
  const bindings = [{ capabilityKey: authority.roleKey, module: address(60) },
    { capabilityKey: authority.authorityId, module: address(61) }];
  const proposal = { id: 2n, appId, targetWorkflowKey: workflowKey,
    sourceStateId: 3n, sourceObjectId: 4n, sourceTransitionId: 5n, governancePackageId: 6n,
    expectedTargetPackageId: 7n, sourceSubjectId: authority.authorityId, revisionCommitment: point.blockHash,
    proposalCommitment: authority.roleKey, proposedVersion: 2n, proposedAuthorityId: authority.authorityId,
    proposedRoleKey: authority.roleKey, correctionOfAppliedProposal: 1n, proposer: address(50),
    proposerRoleKey: authority.roleKey, proposerAuthorityId: authority.authorityId,
    recognisedBy: address(51), sourceDecisionActor: address(52), recognisedAt: 10n,
    submittedAt: 11n, ratificationId: 0n, activationId: 0n };
  const entries = verificationEntries();
  entries[controller].values.getProposal = proposal;
  entries[controller].values.moduleIdentityHash = authority.authorityId;
  entries[addresses.packages].values.getGovernanceBinding = { controller, identityHash: authority.authorityId, bootstrapPackageId: 7n };
  entries[addresses.packages].values.revisionCommitment = ([input, previous, modules]: readonly unknown[]) => {
    assert.equal(previous, 7n);
    return (input as typeof proposed).uri === 'local:revision-2'
      && (modules as typeof bindings)[0].module === address(60) ? point.blockHash : zeroHash;
  };
  const extensions = new AvaExtensions(sdk, { ruleGovernance: controller });
  const client = rpcBoundary(entries, {}, undefined, 0);
  const matching = await extensions.verifyRuleProposalTerms(client, 2n, proposed, bindings, point);
  assert.deepEqual(matching, { matches: true, previousPackageId: 7n, revisionCommitment: point.blockHash, point });
  let blockReads = 0;
  const byHeight = createPublicClient({ transport: custom({ request: async request => {
    if (request.method === 'eth_getBlockByNumber') {
      assert.deepEqual(request.params, ['0x2a', false]);
      blockReads++;
      return { hash: point.blockHash, number: '0x2a', transactions: [] };
    }
    return client.request(request as never);
  } }, { retryCount: 0 }) });
  assert.deepEqual(await extensions.verifyRuleProposalTerms(byHeight, 2n, proposed, bindings, 42n), matching);
  assert.equal(blockReads, 1);
  assert.equal((await extensions.verifyRuleProposalTerms(client, 2n, { ...proposed, uri: 'local:changed' }, bindings, point)).matches, false);
  assert.equal((await extensions.verifyRuleProposalTerms(client, 2n, proposed, [...bindings].reverse(), point)).matches, false);
  entries[controller].values.moduleIdentityHash = zeroHash;
  await assert.rejects(extensions.verifyRuleProposalTerms(client, 2n, proposed, bindings, point), AvaReadError);
  entries[controller].values.moduleIdentityHash = authority.authorityId;
  entries[addresses.packages].values.revisionCommitment = () => { throw { code: -32603, message: 'SYNTHETIC_PRIVATE_RPC' }; };
  await assert.rejects(extensions.verifyRuleProposalTerms(client, 2n, proposed, bindings, point), error =>
    error instanceof AvaReadError && error.cause === undefined);
});

test('origin lifecycle builder discovers the fixed Core registry and preserves the explicit enable decision', async () => {
  const client = rpcBoundary({ [addresses.kernel]: { abi: avaAbis.kernel,
    values: { CORRECTIONS: correctionAddress } } });
  const x = new AvaExtensions(sdk, {});
  for (const enabled of [false, true]) {
    const call = await x.setRequestOriginEnabled(client, authority.authorityId, addresses.requests, enabled, point);
    assert.equal(call.to, correctionAddress);
    assert.deepEqual(decodeFunctionData({ abi: correctionsAbi, data: call.data }),
      { functionName: 'setRequestOriginEnabled', args: [authority.authorityId, addresses.requests, enabled] });
  }
});

test('a retained disclosure authorization preserves the actual completed Core effect after current support ends', async () => {
  const parameters = { resourceId: zeroHash, persona: zeroHash, readerRole: zeroHash, purpose: zeroHash,
    expiresAt: 200n, membershipGeneration: 3n, grantRevision: 4n };
  const receipt = { requestId: 7n, recognisedStateId: 2n, recognisedStateTransitionId: 5n,
    packageId: 6n, evidenceReceiptId: 9n, targetEvidenceId: 10n, parameters,
    parametersHash: point.blockHash, allocator: address(50), allocatorRoleKey: authority.roleKey,
    allocatorAuthorityId: authority.authorityId, decisionHash: authority.roleKey,
    effectHash: point.blockHash, resolutionHead: 0n, grantedAt: 100n };
  const request = { id: 7n, input: { recognisedStateId: 2n, executor: optional.governedDisclosure,
    responseClass: zeroHash, parametersHash: point.blockHash, burdenHash: zeroHash, validUntil: 200n },
    recognisedStateTransitionId: 5n, supersedesRequestId: 0n, appId: zeroHash,
    workflowKey: zeroHash, packageId: 6n, subjectId: authority.authorityId, evidenceReceiptId: 9n,
    creator: address(51), creatorRoleKey: authority.roleKey, creatorAuthorityId: authority.authorityId,
    allocator: address(50), allocatorRoleKey: authority.roleKey, allocatorAuthorityId: authority.authorityId,
    triggeredBy: address(52), cancelled: false, consumed: true, completed: true,
    effectHash: point.blockHash, createdAt: 1n, approvedAt: 2n, consumedAt: 3n, completedAt: 4n };
  const client = rpcBoundary({
    [optional.governedDisclosure]: { abi: governedDisclosureAbi, values: { getReceipt: receipt, isGrantCurrent: false } },
    [addresses.requests]: { abi: requestsAbi, values: { getRequest: request,
      lastResolutionIdByRequest: 0n, EXECUTION: executionAddress } },
    [executionAddress]: { abi: executionAbi, values: { isSplit: false } },
  });
  const result = await new AvaExtensions(sdk, optional).disclosureReceipt(client, 7n, point);
  assert.equal(result.record.effectHash, point.blockHash);
  assert.equal(result.current, false);
  assert.equal(result.execution.record.completed, true);
  assert.equal(result.execution.record.effectHash, result.record.effectHash);
  assert.equal(result.execution.execution, null);
});

test('readiness groups module reads by package at one pinned point and preserves binding order', async () => {
  const entries = verificationEntries(), appId = authority.authorityId, workflowKey = authority.roleKey;
  const context = { packageId: 7n, appId, workflowKey, version: 2n, compatibilityKey: zeroHash, authorityId: point.blockHash };
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: point.blockHash, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = (args: readonly unknown[]) => ({ ...context, packageId: args[0] });
  const keys = [zeroHash, authority.roleKey, authority.authorityId, point.blockHash];
  const calls: unknown[] = [];
  entries[addresses.packages].values.getVerifiedModulesCompact = (args: readonly unknown[]) => {
    calls.push(args);
    return [{ ...context, packageId: args[0] }, (args[1] as Hex[]).map(() => address(60))];
  };
  const bindings = [
    { capabilityKey: keys[0], module: optional.decisions },
    { packageId: 6n, capabilityKey: keys[1], module: optional.decisions },
    { capabilityKey: keys[2], module: optional.decisions },
    { packageId: 6n, capabilityKey: keys[3], module: optional.decisions },
  ];
  const result = await new AvaExtensions(sdk, {}).verifyInstallation(rpcBoundary(entries),
    { appId, workflowKey, activePackageId: 7n, historicalPackageIds: [6n], modules: bindings });
  assert.deepEqual(result.point, point);
  assert.deepEqual(calls, [[7n, [keys[0], keys[2]]], [6n, [keys[1], keys[3]]]]);
  assert.deepEqual(result.findings.map(f => [f.check, f.status]), bindings.map(binding =>
    [`module:${binding.packageId ?? 7n}:${binding.capabilityKey}`, 'mismatch']));
});

test('failed module batch falls back to individual safe findings and a later call recovers', async () => {
  const entries = verificationEntries(), appId = authority.authorityId, workflowKey = authority.roleKey;
  const context = { packageId: 7n, appId, workflowKey, version: 2n, compatibilityKey: zeroHash, authorityId: point.blockHash };
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: point.blockHash, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = context;
  const keys = [zeroHash, authority.roleKey, authority.authorityId];
  let recover = false;
  const calls: number[] = [];
  entries[addresses.packages].values.getVerifiedModulesCompact = (args: readonly unknown[]) => {
    const selected = args[1] as Hex[];
    calls.push(selected.length);
    if (!recover && selected.length > 1) throw { code: -32603, message: 'PRIVATE_BATCH_FAILURE' };
    if (!recover && selected[0] === keys[0]) throw { code: 3, message: 'execution reverted',
      data: encodeErrorResult({ abi: avaAbis.packages, errorName: 'NotAuthorised', args: [address(50), keys[0]] }) };
    if (!recover && selected[0] === keys[2]) throw { code: -32603, message: 'PRIVATE_RPC_FAILURE' };
    return [context, selected.map(() => recover ? optional.decisions : address(60))];
  };
  const expected = { appId, workflowKey, activePackageId: 7n,
    modules: keys.map(capabilityKey => ({ capabilityKey, module: optional.decisions })) };
  const x = new AvaExtensions(sdk, {}), client = rpcBoundary(entries, {}, undefined, 0);
  const failed = await x.verifyInstallation(client, expected, point);
  assert.deepEqual(failed.findings.map(f => [f.check, f.status]), [
    [`module:7:${keys[0]}`, 'missing'], [`module:7:${keys[1]}`, 'mismatch'], [`module:7:${keys[2]}`, 'unavailable']]);
  assert(!JSON.stringify(failed.findings).includes('PRIVATE'));
  assert.deepEqual(calls, [3, 1, 1, 1]);
  recover = true; calls.length = 0;
  assert.equal((await x.verifyInstallation(client, expected, point)).ready, true);
  assert.deepEqual(calls, [3]);
});


test('decision capability mismatch is refused during installation, including a discovered decision, then repairs cleanly', async () => {
  const entries = verificationEntries(), appId = authority.authorityId, workflowKey = authority.roleKey;
  entries[addresses.applications].values.getApplication = { appId, applicationIdentityHash: zeroHash,
    authorityId: point.blockHash, uri: 'ava:app', registeredBy: address(50) };
  entries[addresses.packages].values.getActivePackageId = 7n;
  entries[addresses.packages].values.getVerifiedPackageContext = { packageId: 7n, appId, workflowKey,
    version: 2n, compatibilityKey: zeroHash, authorityId: point.blockHash };
  const rawResults: Record<string, Hex> = {};
  const expected = { appId, workflowKey, activePackageId: 7n }, client = rpcBoundary(entries, {}, undefined, 0, rawResults);
  for (const configured of [{ decisions: optional.decisions }, { procedure: optional.procedure }]) {
    const extension = new AvaExtensions(sdk, configured);
    entries[addresses.authority].values.isAuthorisedSubject = () => {
      throw { code: 3, message: 'execution reverted', data: '0x' };
    };
    await assert.rejects(extension.verify(client, point), /decisions.*authority.*mismatch/);
    const refused = await extension.verifyInstallation(client, expected, point);
    assert.equal(refused.ready, false);
    assert.equal(refused.findings.find(item => item.check === 'deployment')?.status, 'mismatch');
    // Core-only use does not depend on the optional Decision capability.
    assert.equal((await new AvaExtensions(sdk, {}).verifyInstallation(client, expected, point)).ready, true);
    entries[addresses.authority].values.isAuthorisedSubject = true;
    await assert.rejects(extension.verify(client, point), /decisions.*authority.*mismatch/);
    for (const raw of ['0x', '0x01', `0x${'00'.repeat(31)}02`] as Hex[]) {
      rawResults.isAuthorisedSubject = raw;
      await assert.rejects(extension.verify(client, point), /decisions.*authority.*mismatch/);
      const inconsistent = await extension.verifyInstallation(client, expected, point);
      assert.equal(inconsistent.findings.find(item => item.check === 'deployment')?.status, 'mismatch');
    }
    delete rawResults.isAuthorisedSubject;
    entries[addresses.authority].values.isAuthorisedSubject = () => {
      throw { code: -32603, message: 'SYNTHETIC_PRIVATE_CAPABILITY_RPC_FAULT' };
    };
    const unavailable = await extension.verifyInstallation(client, expected, point);
    assert.equal(unavailable.ready, false);
    assert.equal(unavailable.findings.find(item => item.check === 'deployment')?.status, 'unavailable');
    assert(!JSON.stringify(unavailable.findings).includes('SYNTHETIC_PRIVATE'));
    entries[addresses.authority].values.isAuthorisedSubject = false;
    assert.equal((await extension.verifyInstallation(client, expected, point)).ready, true);
  }
});
