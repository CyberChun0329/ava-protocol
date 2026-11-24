import assert from 'node:assert/strict';
import test from 'node:test';
import { encodeAbiParameters, encodeEventTopics, encodeFunctionData, keccak256, toHex, type Abi, type Address, type Hex } from 'viem';
import { avaAbis, correctionsAbi } from '@ava-protocol/sdk';
import { exportPublicDeployment } from '../../ava-sdk/src/deployment.js';

const word = (n: number) => `0x${n.toString(16).padStart(64, '0')}` as Hex;
const address = (n: number) => `0x${n.toString(16).padStart(40, '0')}` as Address;
const appId = word(1), workflowKey = word(2), role = word(3), subject = word(4);
const coreNames = ['AVAApplicationRegistry', 'AVAIdentityRegistry', 'AVAAuthorityMatrix',
  'AVACoreRulePackageRegistry', 'AVADisclosurePolicyRegistry', 'AVAEvidenceRegistry',
  'AVAGovernanceKernel', 'AVARequestAllocation', 'AVAChallengeExtension'];
const artifactValue = { abi: [] as Abi, bytecode: { object: '0x00' }, privateBuildNote: 'SECRET_ARTIFACT' };
const artifact = async (_name: string) => artifactValue;

function fixture(offset = 0, id = appId, existingCore = false,
  profile?: { capabilityKey: Hex; module: Address }[], workflow = workflowKey) {
  const transactions: any[] = [], receipts: any[] = [];
  let nextTransaction = 0;
  const addresses = coreNames.map((_, i) => address((existingCore ? 0 : offset) + 10 + i));
  function add(tx: object, logs: object[] = []) {
    const hash = word(offset + 1000 + nextTransaction++);
    transactions.push({ hash, ...tx });
    receipts.push({ transactionHash: hash, status: '0x1', logs });
  }
  for (let i = 0; !existingCore && i < coreNames.length; i++) add({ transactionType: 'CREATE', contractName: coreNames[i],
    contractAddress: addresses[i], transaction: { input: '0x', chainId: '0x7a69' },
    additionalContracts: i === 6 ? [{ transactionType: 'CREATE', contractName: 'AVACorrectionRegistry', address: address(offset + 20) }] : [] });
  add({ transactionType: 'CREATE', contractName: 'DefaultAVACorePolicyBundle', contractAddress: address(offset + 30), transaction: { input: '0x' } });
  add({ transactionType: 'CREATE', contractName: 'AVATeachingRegistry', contractAddress: address(offset + 31),
    transaction: { input: '0x' }, additionalContracts: [{ transactionType: 'CREATE',
      contractName: 'TeachingRewardDistributor', address: address(offset + 32) }] });
  function call(abi: Abi, to: Address, functionName: string, args: readonly unknown[], logs: object[] = []) {
    add({ transactionType: 'CALL', contractAddress: to,
      transaction: { to, input: encodeFunctionData({ abi, functionName, args }) }, arguments: ['SECRET_ARGUMENT'] }, logs);
  }
  function event(abi: Abi, eventName: string, emitter: Address, args: any, data: Hex) {
    return { address: emitter, topics: encodeEventTopics({ abi, eventName, args }), data };
  }
  call(avaAbis.applications, addresses[0], 'registerApplication', [id, word(10), word(11), address(50), 'SECRET_URI']);
  const bindings = profile ?? [{ capabilityKey: word(100), module: address(offset + 30) },
    { capabilityKey: word(101), module: address(offset + 31) }];
  call(avaAbis.packages, addresses[3], 'registerRulePackage', [{ appId: id, workflowKey: workflow,
    roleKey: role, authorityId: subject, version: 1n, compatibilityKey: word(5), uri: 'SECRET_PACKAGE_URI' }, bindings],
    [event(avaAbis.packages, 'RulePackageRegistered', addresses[3], { packageId: existingCore ? 8n : 7n, appId: id, workflowKey: workflow },
    encodeAbiParameters([{ type: 'bytes32' }, { type: 'address' }], [word(6), address(50)]))]);
  call(avaAbis.disclosure, addresses[4], 'registerPolicy', [id, role, subject, word(8), 'SECRET_LABEL', 'SECRET_DISCLOSURE_URI'],
    [event(avaAbis.disclosure, 'DisclosurePolicyRegistered', addresses[4], { policyId: existingCore ? 10n : 9n, appId: id, policyKey: word(8) },
      encodeAbiParameters([{ type: 'bytes32' }, { type: 'address' }], [subject, address(50)]))]);
  return { broadcast: { chain: 31337, pending: [], transactions, receipts, env: { API_TOKEN: 'SECRET_ENV' } },
    addresses, call, bindings };
}

test('exports a public deployment declaration from submitted modules and matched receipt IDs', async () => {
  const f = fixture();
  const result = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  assert.deepEqual(result.deployment, { chainId: 31337, addresses: {
    applications: address(10), identities: address(11), authority: address(12), packages: address(13),
    disclosure: address(14), evidence: address(15), kernel: address(16), requests: address(17), challenges: address(18) } });
  assert.deepEqual(result.apps[appId], { appId, workflowKey, packageId: '7', disclosurePolicyId: '9',
    modules: [{ capabilityKey: word(100), module: address(30) }, { capabilityKey: word(101), module: address(31) }],
    requiredSubjects: [], correctionOrigins: [], sourceCorrectionBindings: [],
    contracts: Object.fromEntries([...coreNames.map((name, i) => [name, address(10 + i)]),
      ['AVACorrectionRegistry', address(20)], ['DefaultAVACorePolicyBundle', address(30)],
      ['AVATeachingRegistry', address(31)], ['TeachingRewardDistributor', address(32)]]
      .map(([name, contractAddress]) => [name, { address: contractAddress, abi: [],
        artifactSha256: 'c0cf2e25b990d0b9d064ed5522b4838a4261e7befa29bcc6b1f1e288c4450739' }])) });
  assert.equal(result.schemaVersion, 1);
  assert.doesNotMatch(JSON.stringify(result), /SECRET|arguments|bytecode|privateBuildNote/);
});

test('preserves all nineteen submitted capability bindings including custom replacements and order', async () => {
  const f = fixture(0, appId, false, [
    { capabilityKey: word(101), module: address(501) }, { capabilityKey: word(102), module: address(502) },
    { capabilityKey: word(103), module: address(502) }, { capabilityKey: word(104), module: address(503) },
    { capabilityKey: word(105), module: address(503) }, { capabilityKey: word(106), module: address(502) },
    { capabilityKey: word(107), module: address(502) }, { capabilityKey: word(108), module: address(502) },
    { capabilityKey: word(109), module: address(502) }, { capabilityKey: word(110), module: address(504) },
    { capabilityKey: word(111), module: address(502) }, { capabilityKey: word(112), module: address(502) },
    { capabilityKey: word(113), module: address(505) }, { capabilityKey: word(114), module: address(505) },
    { capabilityKey: word(115), module: address(505) }, { capabilityKey: word(116), module: address(505) },
    { capabilityKey: word(117), module: address(505) }, { capabilityKey: word(118), module: address(505) },
    { capabilityKey: word(119), module: address(505) },
  ]);
  const result = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  assert.deepEqual(result.apps[appId].modules.map(binding => [binding.capabilityKey, binding.module]), [
    [word(101), address(501)], [word(102), address(502)], [word(103), address(502)],
    [word(104), address(503)], [word(105), address(503)], [word(106), address(502)],
    [word(107), address(502)], [word(108), address(502)], [word(109), address(502)],
    [word(110), address(504)], [word(111), address(502)], [word(112), address(502)],
    [word(113), address(505)], [word(114), address(505)], [word(115), address(505)],
    [word(116), address(505)], [word(117), address(505)], [word(118), address(505)],
    [word(119), address(505)],
  ]);
});

test('combines applications on one Core while retaining each submitted policy address', async () => {
  const peer = fixture(), spark = fixture(200, word(200), true);
  // The receipt array order is deliberately unrelated to the transaction order.
  spark.broadcast.receipts.reverse();
  const result = await exportPublicDeployment({ broadcasts: [peer.broadcast, spark.broadcast], artifact });
  assert.deepEqual(Object.keys(result.apps), [appId, word(200)]);
  assert.equal(result.apps[appId].contracts.DefaultAVACorePolicyBundle.address, address(30));
  assert.equal(result.apps[word(200)].contracts.DefaultAVACorePolicyBundle.address, address(230));
  assert.equal(result.apps[word(200)].contracts.TeachingRewardDistributor.address, address(232));
  assert.deepEqual(result.apps[word(200)].modules, [
    { capabilityKey: word(100), module: address(230) }, { capabilityKey: word(101), module: address(231) }]);
  assert.equal(result.apps[word(200)].packageId, '8');
  assert.equal(result.apps[word(200)].disclosurePolicyId, '10');
});

function multiWorkflowFixture() {
  const editorialWorkflow = word(202);
  const acceptance = fixture(), editorial = fixture(200, appId, true, undefined, editorialWorkflow);
  // The second installation reuses the existing application namespace.
  const registration = editorial.broadcast.transactions.findIndex(tx => tx.contractAddress === address(10));
  editorial.broadcast.transactions.splice(registration, 1);
  editorial.broadcast.receipts.splice(registration, 1);
  acceptance.call(avaAbis.identities, address(11), 'assignSubject', [address(60), appId, role, subject, 'SECRET_OLD']);
  acceptance.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(80), true]);
  editorial.call(avaAbis.identities, address(11), 'deactivateSubject', [subject]);
  editorial.call(avaAbis.identities, address(11), 'assignSubject', [address(61), appId, role, word(204), 'SECRET_CURRENT']);
  editorial.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(80), false]);
  editorial.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(81), true]);
  editorial.call(correctionsAbi, address(20), 'bindRequestOrigin', [appId, address(17)]);
  acceptance.call(avaAbis.kernel, address(16), 'bindSourceBoundTransitionRequester', [7n, address(84)]);
  acceptance.call(avaAbis.kernel, address(16), 'bindTransitionGuard', [7n, address(85)]);
  editorial.call(avaAbis.kernel, address(16), 'bindSourceBoundTransitionRequester', [8n, address(284)]);
  editorial.call(avaAbis.kernel, address(16), 'bindTransitionGuard', [8n, address(285)]);
  editorial.call(avaAbis.kernel, address(16), 'bindPostTransitionHook', [8n, address(286)]);
  return { acceptance, editorial, editorialWorkflow,
    broadcasts: [acceptance.broadcast, editorial.broadcast] };
}

test('exports two workflows in one namespace with explicit legacy selection and current shared history', async () => {
  const f = multiWorkflowFixture();
  const result = await exportPublicDeployment({ broadcasts: f.broadcasts, artifact,
    primaryWorkflows: { [appId]: workflowKey } });
  assert.deepEqual(Object.keys(result.apps), [appId]);
  const profiles = result.workflows![appId];
  assert.deepEqual(Object.keys(profiles), [workflowKey, f.editorialWorkflow]);
  assert.deepEqual(result.apps[appId], profiles[workflowKey]);
  assert.equal(profiles[workflowKey].packageId, '7');
  assert.equal(profiles[workflowKey].disclosurePolicyId, '9');
  assert.equal(profiles[workflowKey].contracts.AVATeachingRegistry.address, address(31));
  assert.equal(profiles[f.editorialWorkflow].packageId, '8');
  assert.equal(profiles[f.editorialWorkflow].disclosurePolicyId, '10');
  assert.deepEqual(profiles[f.editorialWorkflow].modules, [
    { capabilityKey: word(100), module: address(230) }, { capabilityKey: word(101), module: address(231) }]);
  assert.equal(profiles[f.editorialWorkflow].contracts.AVATeachingRegistry.address, address(231));
  for (const profile of Object.values(profiles)) {
    assert.deepEqual(profile.requiredSubjects, [{ account: address(61), roleKey: role,
      subjectId: word(204), actionKeys: [word(81)] }]);
    assert.deepEqual(profile.correctionOrigins, [address(17)]);
  }
  assert.deepEqual(profiles[workflowKey].sourceCorrectionBindings,
    [{ requester: address(84), guard: address(85), hook: address(0) }]);
  assert.deepEqual(profiles[f.editorialWorkflow].sourceCorrectionBindings,
    [{ requester: address(284), guard: address(285), hook: address(286) }]);
  assert.doesNotMatch(JSON.stringify(result), /SECRET|arguments|bytecode|privateBuildNote/);
});

test('requires an exact explicit primary for multiple workflows and can select either profile', async () => {
  const f = multiWorkflowFixture();
  await assert.rejects(exportPublicDeployment({ broadcasts: f.broadcasts, artifact }), /primary workflow required/);
  for (const selection of [{ [appId]: word(999) }, { [word(999)]: workflowKey },
    { [appId]: workflowKey, [word(999)]: workflowKey }]) {
    await assert.rejects(exportPublicDeployment({ broadcasts: f.broadcasts, artifact,
      primaryWorkflows: selection }), /primary workflow/);
  }
  const selected = await exportPublicDeployment({ broadcasts: f.broadcasts, artifact,
    primaryWorkflows: { [appId]: f.editorialWorkflow } });
  assert.deepEqual(selected.apps[appId], selected.workflows![appId][f.editorialWorkflow]);
  const single = await exportPublicDeployment({ broadcasts: fixture().broadcast, artifact,
    primaryWorkflows: { [appId]: workflowKey } });
  assert.equal(single.workflows, undefined);
});

test('rejects duplicate workflow, package IDs, policy IDs and capability keys even outside the primary profile', async () => {
  const duplicateWorkflow = fixture(200, appId, true);
  await assert.rejects(exportPublicDeployment({ broadcasts: [fixture().broadcast, duplicateWorkflow.broadcast], artifact,
    primaryWorkflows: { [appId]: workflowKey } }), /Ambiguous application package/);

  const duplicatePackage = multiWorkflowFixture();
  const packageReceipt = duplicatePackage.editorial.broadcast.receipts.find(receipt => receipt.logs[0]?.topics[1] === word(8))!;
  packageReceipt.logs[0].topics[1] = word(7);
  await assert.rejects(exportPublicDeployment({ broadcasts: duplicatePackage.broadcasts, artifact,
    primaryWorkflows: { [appId]: workflowKey } }), /Duplicate package/);

  const duplicatePolicy = multiWorkflowFixture();
  const policyReceipt = duplicatePolicy.editorial.broadcast.receipts.find(receipt => receipt.logs[0]?.topics[1] === word(10))!;
  policyReceipt.logs[0].topics[1] = word(9);
  await assert.rejects(exportPublicDeployment({ broadcasts: duplicatePolicy.broadcasts, artifact,
    primaryWorkflows: { [appId]: workflowKey } }), /Duplicate disclosure policy/);

  const duplicateCapability = multiWorkflowFixture();
  const packageTx = duplicateCapability.editorial.broadcast.transactions.find(tx => tx.contractAddress === address(13))!;
  packageTx.transaction.input = encodeFunctionData({ abi: avaAbis.packages, functionName: 'registerRulePackage', args: [{
    appId, workflowKey: duplicateCapability.editorialWorkflow, roleKey: role, authorityId: subject,
    version: 1n, compatibilityKey: word(5), uri: 'SECRET_PACKAGE_URI',
  }, [{ capabilityKey: word(100), module: address(230) }, { capabilityKey: word(100), module: address(231) }]] });
  await assert.rejects(exportPublicDeployment({ broadcasts: duplicateCapability.broadcasts, artifact,
    primaryWorkflows: { [appId]: workflowKey } }), /Duplicate capability/);
});

test('rejects ambiguous disclosure pairing and incomplete correction bindings in an unselected workflow', async () => {
  const ambiguous = multiWorkflowFixture();
  // Add a second pending package before the first disclosure registration.
  const packageIndex = ambiguous.editorial.broadcast.transactions.findIndex(tx => tx.contractAddress === address(13));
  const policyIndex = ambiguous.acceptance.broadcast.transactions.findIndex(tx => tx.contractAddress === address(14));
  ambiguous.acceptance.broadcast.transactions.splice(policyIndex, 0, ambiguous.editorial.broadcast.transactions[packageIndex]);
  ambiguous.acceptance.broadcast.receipts.push(ambiguous.editorial.broadcast.receipts[packageIndex]);
  await assert.rejects(exportPublicDeployment({ broadcasts: ambiguous.broadcasts, artifact,
    primaryWorkflows: { [appId]: workflowKey } }), /Ambiguous application disclosure/);
  const incomplete = multiWorkflowFixture();
  const guard = incomplete.editorial.broadcast.transactions.findIndex(tx => tx.transaction.input ===
    encodeFunctionData({ abi: avaAbis.kernel, functionName: 'bindTransitionGuard', args: [8n, address(285)] }));
  incomplete.editorial.broadcast.transactions.splice(guard, 1);
  incomplete.editorial.broadcast.receipts.splice(guard, 1);
  await assert.rejects(exportPublicDeployment({ broadcasts: incomplete.broadcasts, artifact,
    primaryWorkflows: { [appId]: workflowKey } }), /Incomplete source correction binding/);
});

test('uses a different deployment address set without hardcoded fixture addresses', async () => {
  const f = fixture(400);
  const result = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  assert.equal(result.deployment.addresses.kernel, address(416));
  assert.equal(result.apps[appId].modules[0].module, address(430));
});

test('an explicitly declared authority implementation changes only its Core name mapping', async () => {
  const f = fixture();
  f.broadcast.transactions.find(tx => tx.contractName === 'AVAAuthorityMatrix')!.contractName = 'OsxAuthority';
  await assert.rejects(exportPublicDeployment({ broadcasts: f.broadcast, artifact }), /Missing Core deployment/);
  const result = await exportPublicDeployment({ broadcasts: f.broadcast, artifact, authorityContract: 'OsxAuthority' });
  assert.equal(result.deployment.addresses.authority, address(12));
  assert.equal(result.apps[appId].contracts.OsxAuthority.address, address(12));
  const original = await exportPublicDeployment({ broadcasts: fixture().broadcast, artifact });
  assert.equal(original.apps[appId].contracts.AVAAuthorityMatrix.address, address(12));
  assert.equal(original.apps[appId].contracts.OsxAuthority, undefined);
});

test('rejects missing, failed and pending transaction receipts without exposing private inputs', async () => {
  const missing = fixture(); missing.broadcast.receipts.pop();
  const failed = fixture(); failed.broadcast.receipts[0].status = '0x0';
  const pending = fixture(); (pending.broadcast.pending as unknown[]).push('SECRET_PENDING_TRANSACTION');
  for (const f of [missing, failed, pending]) {
    await assert.rejects(exportPublicDeployment({ broadcasts: f.broadcast, artifact }), error => {
      assert.doesNotMatch(String(error), /SECRET/);
      return /receipt|Pending/.test(String(error));
    });
  }
});

test('rejects conflicting Core declarations and registration logs from an unrelated emitter', async () => {
  await assert.rejects(exportPublicDeployment({ broadcasts: [fixture().broadcast, fixture(400, word(200)).broadcast], artifact }),
    /Conflicting deployment contracts/);
  const f = fixture();
  f.broadcast.receipts.find(receipt => receipt.logs.length)!.logs[0].address = address(999);
  await assert.rejects(exportPublicDeployment({ broadcasts: f.broadcast, artifact }), /registration event/);
});

test('reconstructs current subjects, revoked permissions, origin enablement and custom correction bindings', async () => {
  const f = fixture();
  f.call(avaAbis.identities, address(11), 'assignSubject', [address(60), appId, role, word(99), 'SECRET_BOOTSTRAP']);
  f.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(80), true]);
  f.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(80), false]);
  f.call(avaAbis.identities, address(11), 'deactivateSubject', [word(99)]);
  f.call(avaAbis.identities, address(11), 'assignSubject', [address(61), appId, word(70), subject, 'SECRET_SUBJECT']);
  f.call(avaAbis.authority, address(12), 'setPermission', [appId, word(70), word(81), true]);
  f.call(avaAbis.authority, address(12), 'setPermission', [appId, word(70), word(82), true]);
  f.call(avaAbis.authority, address(12), 'setPermission', [appId, word(70), word(82), false]);
  f.call(correctionsAbi, address(20), 'bindRequestOrigin', [appId, address(17)]);
  f.call(correctionsAbi, address(20), 'bindRequestOrigin', [appId, address(83)]);
  f.call(correctionsAbi, address(20), 'setRequestOriginEnabled', [appId, address(83), false]);
  f.call(correctionsAbi, address(20), 'bindRequestOrigin', [appId, address(83)]);
  f.call(avaAbis.kernel, address(16), 'bindSourceBoundTransitionRequester', [7n, address(84)]);
  f.call(avaAbis.kernel, address(16), 'bindTransitionGuard', [7n, address(85)]);
  f.call(avaAbis.kernel, address(16), 'bindPostTransitionHook', [7n, address(86)]);
  // Same selector on an unrelated app contract must not become Core configuration.
  f.call(avaAbis.identities, address(31), 'assignSubject', [address(62), appId, role, word(98), 'SECRET_UNRELATED']);
  const result = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  assert.deepEqual(result.apps[appId].requiredSubjects, [{ account: address(61), roleKey: word(70),
    subjectId: subject, actionKeys: [word(81)] }]);
  assert.deepEqual(result.apps[appId].correctionOrigins, [address(17)]);
  assert.deepEqual(result.apps[appId].sourceCorrectionBindings,
    [{ requester: address(84), guard: address(85), hook: address(86) }]);
});

test('reconstructs permissions in transaction and batch order while isolating other applications and emitters', async () => {
  const f = fixture();
  f.call(avaAbis.identities, address(11), 'assignSubject', [address(60), appId, role, subject, 'SECRET_SUBJECT']);
  f.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(80), true]);
  f.call(avaAbis.authority, address(12), 'setPermissions', [appId, [
    { roleKey: role, actionKey: word(80), allowed: false },
    { roleKey: role, actionKey: word(81), allowed: true },
    { roleKey: role, actionKey: word(82), allowed: true },
    { roleKey: role, actionKey: word(82), allowed: false },
  ]]);
  f.call(avaAbis.authority, address(12), 'setPermissions', [word(200), [
    { roleKey: role, actionKey: word(83), allowed: true },
  ]]);
  f.call(avaAbis.authority, address(31), 'setPermissions', [appId, [
    { roleKey: role, actionKey: word(84), allowed: true },
  ]]);
  f.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(85), true]);
  f.broadcast.receipts.reverse();
  const result = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  assert.deepEqual(result.apps[appId].requiredSubjects, [{ account: address(60), roleKey: role,
    subjectId: subject, actionKeys: [word(81), word(85)] }]);
});

function defaultPolicyFixture(overrides: readonly string[] = []) {
  // Canonical slots from script/AVADefaultBindings.sol; application and allocation stay app-specific.
  const profile = [
    ['application', 31], ['attribution', 30], ['verification', 30], ['transition-rule', 30],
    ['evidence-policy', 30], ['disclosure-policy', 30], ['challenge-policy', 30], ['authority-policy', 30],
    ['standing', 30], ['allocation', 33], ['consequence', 30], ['evidence-lifecycle', 30],
    ['standing-computation', 40], ['standing-credential', 40], ['reward', 40], ['administrative-priority', 40],
    ['penalty', 40], ['restoration', 40], ['value-execution', 40],
  ] as const;
  const f = fixture(0, appId, false, profile.map(([name, n]) => ({
    capabilityKey: keccak256(toHex(`ava.capability.${name}.v1`)), module: address(overrides.includes(name) ? 90 : n),
  })));
  const policyTx = f.broadcast.transactions.find(tx => tx.contractName === 'DefaultAVACorePolicyBundle')!;
  policyTx.additionalContracts = [{ transactionType: 'CREATE', contractName: 'DefaultAVAExtensionPolicyModule', address: address(40) }];
  return f;
}

test('validates reused default-policy bindings for every workflow including the unselected one', async () => {
  const acceptance = defaultPolicyFixture(), editorialWorkflow = word(202);
  const editorial = fixture(200, appId, true, [
    { capabilityKey: keccak256(toHex('ava.capability.attribution.v1')), module: address(30) },
    { capabilityKey: keccak256(toHex('ava.capability.reward.v1')), module: address(40) },
  ], editorialWorkflow);
  const creation = editorial.broadcast.transactions.findIndex(tx => tx.contractName === 'DefaultAVACorePolicyBundle');
  editorial.broadcast.transactions.splice(creation, 1);
  editorial.broadcast.receipts.splice(creation, 1);
  const input = { broadcasts: [acceptance.broadcast, editorial.broadcast], artifact,
    primaryWorkflows: { [appId]: workflowKey },
    defaultPolicies: { corePolicy: address(30), extensionPolicy: address(40) } };
  const result = await exportPublicDeployment(input);
  assert.equal(result.workflows![appId][editorialWorkflow].contracts.DefaultAVAExtensionPolicyModule.address, address(40));
  const packageTx = editorial.broadcast.transactions.find(tx => tx.contractAddress === address(13))!;
  packageTx.transaction.input = encodeFunctionData({ abi: avaAbis.packages, functionName: 'registerRulePackage', args: [{
    appId, workflowKey: editorialWorkflow, roleKey: role, authorityId: subject,
    version: 1n, compatibilityKey: word(5), uri: 'SECRET_PACKAGE_URI',
  }, [{ capabilityKey: keccak256(toHex('ava.capability.attribution.v1')), module: address(90) },
    { capabilityKey: keccak256(toHex('ava.capability.reward.v1')), module: address(40) }]] });
  await assert.rejects(exportPublicDeployment(input), /Default policy binding mismatch/);
});

test('exports explicitly reused default policies without CREATE records and preserves installation semantics', async () => {
  const f = defaultPolicyFixture();
  f.call(avaAbis.identities, address(11), 'assignSubject', [address(60), appId, role, subject, 'SECRET_SUBJECT']);
  f.call(avaAbis.authority, address(12), 'setPermissions', [appId, [
    { roleKey: role, actionKey: word(80), allowed: true },
    { roleKey: role, actionKey: word(81), allowed: true },
    { roleKey: role, actionKey: word(81), allowed: false },
  ]]);
  f.call(correctionsAbi, address(20), 'bindRequestOrigin', [appId, address(17)]);
  f.call(avaAbis.kernel, address(16), 'bindSourceBoundTransitionRequester', [7n, address(84)]);
  f.call(avaAbis.kernel, address(16), 'bindTransitionGuard', [7n, address(85)]);
  const fresh = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  const policyIndex = f.broadcast.transactions.findIndex(tx => tx.contractName === 'DefaultAVACorePolicyBundle');
  f.broadcast.transactions.splice(policyIndex, 1);
  f.broadcast.receipts.splice(policyIndex, 1);
  const reused = await exportPublicDeployment({ broadcasts: f.broadcast, artifact,
    defaultPolicies: { corePolicy: address(30), extensionPolicy: address(40) } });
  assert.deepEqual(reused, fresh);
  assert.deepEqual(reused.apps[appId].requiredSubjects, [{ account: address(60), roleKey: role,
    subjectId: subject, actionKeys: [word(80)] }]);
  assert.equal(reused.apps[appId].contracts.DefaultAVACorePolicyBundle.address, address(30));
  assert.equal(reused.apps[appId].contracts.DefaultAVAExtensionPolicyModule.address, address(40));
  assert.doesNotMatch(JSON.stringify(reused), /SECRET|bytecode|privateBuildNote/);
});

test('preserves custom policy adapters alongside explicitly reused defaults and actor configuration', async () => {
  const overridden = ['attribution', 'verification', 'transition-rule', 'evidence-policy', 'reward'];
  const f = defaultPolicyFixture(overridden);
  f.call(avaAbis.identities, address(11), 'assignSubject', [address(60), appId, role, subject, 'SECRET_SUBJECT']);
  f.call(avaAbis.authority, address(12), 'setPermissions', [appId, [
    { roleKey: role, actionKey: word(80), allowed: true },
  ]]);
  f.call(correctionsAbi, address(20), 'bindRequestOrigin', [appId, address(17)]);
  const fresh = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  const policyIndex = f.broadcast.transactions.findIndex(tx => tx.contractName === 'DefaultAVACorePolicyBundle');
  f.broadcast.transactions.splice(policyIndex, 1);
  f.broadcast.receipts.splice(policyIndex, 1);
  const reused = await exportPublicDeployment({ broadcasts: f.broadcast, artifact,
    defaultPolicies: { corePolicy: address(30), extensionPolicy: address(40) } });
  assert.deepEqual(reused, fresh);
  for (const name of overridden) {
    assert.equal(reused.apps[appId].modules.find(binding =>
      binding.capabilityKey === keccak256(toHex(`ava.capability.${name}.v1`)))?.module, address(90));
  }
  assert.deepEqual(reused.apps[appId].requiredSubjects, [{ account: address(60), roleKey: role,
    subjectId: subject, actionKeys: [word(80)] }]);
  assert.deepEqual(reused.apps[appId].correctionOrigins, [address(17)]);
});

test('rejects invalid or conflicting reused policies and remains usable after rejected declarations', async () => {
  const f = defaultPolicyFixture();
  const valid = { corePolicy: address(30), extensionPolicy: address(40) };
  const expected = await exportPublicDeployment({ broadcasts: f.broadcast, artifact });
  const policyIndex = f.broadcast.transactions.findIndex(tx => tx.contractName === 'DefaultAVACorePolicyBundle');
  f.broadcast.transactions.splice(policyIndex, 1);
  f.broadcast.receipts.splice(policyIndex, 1);
  for (const invalid of [
    { ...valid, corePolicy: address(0) }, { ...valid, extensionPolicy: 'SECRET_INVALID_ADDRESS' },
    { ...valid, corePolicy: address(90) }, { ...valid, extensionPolicy: address(91) },
    { corePolicy: address(40), extensionPolicy: address(30) },
    { corePolicy: address(30), extensionPolicy: address(30) },
    { corePolicy: address(30) }, null,
  ]) {
    await assert.rejects(exportPublicDeployment({ broadcasts: f.broadcast, artifact, defaultPolicies: invalid as any }), error => {
      assert.doesNotMatch(String(error), /SECRET/);
      return /[Ii]nvalid|[Cc]onflicting|[Mm]ismatch/.test(String(error));
    });
  }
  // A declaration cannot replace a conflicting CREATE identity, even when its bindings agree.
  const conflicting = defaultPolicyFixture();
  conflicting.broadcast.transactions.find(tx => tx.contractName === 'DefaultAVACorePolicyBundle')!.contractAddress = address(90);
  await assert.rejects(exportPublicDeployment({ broadcasts: conflicting.broadcast, artifact, defaultPolicies: valid }),
    /Conflicting default policy/);
  await assert.rejects(exportPublicDeployment({ broadcasts: fixture().broadcast, artifact, defaultPolicies: valid }),
    /Default policy binding mismatch/);
  const unusedCore = defaultPolicyFixture(['attribution', 'verification', 'transition-rule', 'evidence-policy',
    'disclosure-policy', 'challenge-policy', 'authority-policy', 'standing', 'consequence', 'evidence-lifecycle']);
  await assert.rejects(exportPublicDeployment({ broadcasts: unusedCore.broadcast, artifact, defaultPolicies: valid }),
    /Default policy binding mismatch/);
  assert.deepEqual(await exportPublicDeployment({ broadcasts: f.broadcast, artifact, defaultPolicies: valid }), expected);
});

test('requires opt-in for a Core-only deployment and still rejects incomplete profiles', async () => {
  const core = fixture();
  core.broadcast.transactions.splice(coreNames.length);
  core.broadcast.receipts.splice(coreNames.length);
  await assert.rejects(exportPublicDeployment({ broadcasts: core.broadcast, artifact }), /Incomplete application deployment/);
  const result = await exportPublicDeployment({ broadcasts: core.broadcast, artifact, allowCoreOnly: true });
  assert.deepEqual(result.apps, {});
  assert.equal(result.deployment.addresses.kernel, address(16));
  const incomplete = fixture();
  const registration = incomplete.broadcast.transactions.findIndex(tx => tx.contractAddress === address(14) && tx.transactionType === 'CALL');
  if (registration < 0) throw new Error('Missing disclosure registration fixture');
  incomplete.broadcast.transactions.splice(registration, 1);
  incomplete.broadcast.receipts.splice(registration, 1);
  await assert.rejects(exportPublicDeployment({ broadcasts: incomplete.broadcast, artifact, allowCoreOnly: true }), /Incomplete application deployment/);
});

test('does not hide a partially configured application behind Core-only export', async () => {
  const registrationOnly = fixture();
  // Keep the Core and the real submitted application registration, before its rule package.
  registrationOnly.broadcast.transactions.splice(coreNames.length + 3);
  registrationOnly.broadcast.receipts.splice(coreNames.length + 3);
  await assert.rejects(exportPublicDeployment({ broadcasts: registrationOnly.broadcast, artifact, allowCoreOnly: true }),
    /Incomplete application deployment/);

  const permissionsOnly = fixture();
  permissionsOnly.broadcast.transactions.splice(coreNames.length);
  permissionsOnly.broadcast.receipts.splice(coreNames.length);
  permissionsOnly.call(avaAbis.authority, address(12), 'setPermission', [appId, role, word(99), true]);
  await assert.rejects(exportPublicDeployment({ broadcasts: permissionsOnly.broadcast, artifact, allowCoreOnly: true }),
    /Incomplete application deployment/);

  const repaired = await exportPublicDeployment({ broadcasts: fixture().broadcast, artifact });
  assert.equal(repaired.apps[appId].packageId, '7');
});
