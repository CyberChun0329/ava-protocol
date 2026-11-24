import assert from 'node:assert/strict';
import { spawn, type ChildProcess } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:net';
import { resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { createPublicClient, createWalletClient, custom, decodeFunctionData, encodeAbiParameters, encodeFunctionData,
  http, keccak256, toHex, zeroAddress,
  type Abi, type Address, type Hex } from 'viem';
import { mnemonicToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { AvaSdk, AvaExtensions, AvaServiceClient, AvaServiceError, AvaSigningError, AvaReceiptError, localClient, avaAbis, avaExtensionAbis,
  RecognitionStatus, Stage, RequestChallengeTarget, RequestResolutionOutcome,
  type AvaCall, type InstallationExpectations } from '@ava-protocol/sdk';
import { exportPublicDeployment, foundryArtifactLoader, type FoundryBroadcast } from '@ava-protocol/sdk/deployment';
import { buildAvaService } from '@ava-protocol/local-service/server';

const json = (value: unknown) => JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item, 2) + '\n';
const key = (text: string) => keccak256(toHex(text));
const profileMode = process.env.AVA_WORK_ORDER_PROFILES === '1';
const ruleLifecycleMode = process.env.AVA_WORK_ORDER_RULE_LIFECYCLE === '1';
assert(!(profileMode && ruleLifecycleMode), 'Rule lifecycle and cost profiles use separate fixtures');
const identities = Array.from({ length: 7 }, (_, addressIndex) =>
  mnemonicToAccount('test test test test test test test test test test test junk', { addressIndex }));
const accounts = identities.map(account => account.address);
const server = createServer();
await new Promise<void>((accept, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', accept); });
const port = (server.address() as { port: number }).port;
await new Promise<void>((accept, reject) => server.close(error => error ? reject(error) : accept()));
const rpcUrl = `http://127.0.0.1:${port}`;
const client = localClient(rpcUrl);
// Use the same disposable node for caller-owned SDK signing and Foundry installation.
const signers = identities.map(account => createWalletClient({ account, chain: foundry,
  transport: http(rpcUrl, { retryCount: 0 }) }));
const processes: ChildProcess[] = [];
const logs: Promise<unknown>[] = [];
const terminate = () => { for (const child of processes) child.kill('SIGTERM'); };
process.once('SIGINT', terminate);
process.once('SIGTERM', terminate);
const start = (command: string, args: string[], logName: string, env: NodeJS.ProcessEnv = {}) => {
  const child = spawn(command, args, { env: { ...process.env, RAYON_NUM_THREADS: '2', ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  const chunks: Buffer[] = [];
  child.stdout!.on('data', chunk => chunks.push(Buffer.from(chunk)));
  child.stderr!.on('data', chunk => chunks.push(Buffer.from(chunk)));
  logs.push(new Promise<void>(accept => child.once('close', async () => {
    await writeFile(logName, Buffer.concat(chunks)); accept();
  })));
  processes.push(child);
  return child;
};
const runForge = async (target: string, signature: string, args: string[], logName: string) => {
  const child = start('forge', ['script', target, '--offline', '--sig', signature, ...args,
    '--rpc-url', rpcUrl, '--chain-id', '31337', '--sender', accounts[0], '--unlocked', '--broadcast', '--slow', '-vv'], logName);
  const [exit] = await once(child, 'exit');
  assert.equal(exit, 0, `Forge failed; inspect ${resolve(logName)}`);
  const script = target.split('/').at(-1)!.split(':')[0];
  const entry = signature.slice(0, signature.indexOf('('));
  return JSON.parse(await readFile(`broadcast/${script}/31337/${entry}-latest.json`, 'utf8')) as FoundryBroadcast;
};

async function rehearseInstallRecovery(installed: FoundryBroadcast, checkpoint: Hex,
    extensions: AvaExtensions, expected: InstallationExpectations) {
  const { transactions } = installed;
  const last = transactions.at(-1)!;
  assert.equal(last.transaction.to?.toLowerCase(), extensions.sdk.deployment.addresses.authority.toLowerCase());
  assert.equal(decodeFunctionData({ abi: avaAbis.authority, data: last.transaction.input }).functionName, 'setPermissions');
  // Capture the exact local sequence, then stage its prefix on the pre-install snapshot.
  const envelopes = await Promise.all(transactions.map(async tx => {
    const hash = tx.hash as Hex;
    const bytes = await client.request({ method: 'eth_getRawTransactionByHash', params: [hash] });
    assert(bytes && keccak256(bytes) === hash);
    return { hash, bytes, created: tx.transactionType === 'CREATE' ? tx.contractAddress?.toLowerCase() : undefined };
  }));
  assert.equal(await client.request({ method: 'evm_revert', params: [checkpoint] } as never), true);
  const receipts: FoundryBroadcast['receipts'][number][] = [];
  async function submitOriginal({ hash, bytes, created }: typeof envelopes[number]) {
    assert.equal(await client.request({ method: 'eth_sendRawTransaction', params: [bytes] }), hash);
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert.equal(receipt.status, 'success');
    if (created) assert.equal(receipt.contractAddress?.toLowerCase(), created);
    receipts.push({ transactionHash: receipt.transactionHash, status: '0x1', logs: receipt.logs });
  }
  for (const envelope of envelopes.slice(0, -1)) await submitOriginal(envelope);
  const partial = await extensions.verifyInstallation(client, expected);
  assert.equal(partial.ready, false);
  const missingActions = expected.requiredSubjects!.flatMap(subject => subject.actionKeys.map(action =>
    `permission:${subject.subjectId}:${action}`));
  assert.equal(missingActions.length, 10, 'The independent app expects ten business grants');
  assert.deepEqual(partial.findings.map(f => [f.check, f.status]), missingActions.map(check => [check, 'missing']));
  const withheld = envelopes.at(-1)!;
  await submitOriginal(withheld);
  return { broadcast: { ...installed, receipts }, partial, resumedHash: withheld.hash };
}
const transactions: { phase: string; operation: string; hash: Hex; gasUsed: bigint; gasPrice: bigint;
  feeWei: bigint; calldataBytes: number; transaction?: unknown; receipt?: unknown }[] = [];
const recordCost = async (phase: string, operation: string, hash: Hex) => {
  const [receipt, tx] = await Promise.all([client.getTransactionReceipt({ hash }), client.getTransaction({ hash })]);
  assert.equal(receipt.status, 'success');
  transactions.push({ phase, operation, hash, gasUsed: receipt.gasUsed, gasPrice: receipt.effectiveGasPrice,
    feeWei: receipt.gasUsed * receipt.effectiveGasPrice, calldataBytes: (tx.input.length - 2) / 2,
    ...(profileMode ? { transaction: tx, receipt } : {}) });
};
let service: Awaited<ReturnType<typeof buildAvaService>> | undefined;
try {
  const node = start('anvil', ['--host', '127.0.0.1', '--port', String(port), '--chain-id', '31337', '--silent'], 'anvil.log');
  let ready = false;
  for (let i = 0; i < 150; i++) {
    try { ready = await client.getChainId() === 31337; if (ready) break; } catch {}
    if (node.exitCode !== null) break;
    await new Promise(accept => setTimeout(accept, 20));
  }
  assert(ready, 'Local Anvil starts');
  // Exclude compilation from the paired installation timings below.
  const build = start('forge', ['build', '--offline', ...(ruleLifecycleMode ? [] : ['--skip', 'InstallRuleLifecycle.s.sol'])], 'compile.log');
  assert.equal((await once(build, 'exit'))[0], 0, 'Consumer sources compile');
  const artifact = foundryArtifactLoader(resolve('out'));
  const core = await runForge('node_modules/@ava-protocol/contracts/script/DeployAVACore.s.sol:DeployAVACore',
    'run(address)', [accounts[0]], 'core-deploy.log');
  const verification = { client };
  const coreOnly = await exportPublicDeployment({ broadcasts: core, artifact, allowCoreOnly: true, verification });
  assert.equal(Object.keys(coreOnly.apps).length, 0);
  const deterministic = core.transactions.find(tx => tx.transactionType === 'CREATE2');
  assert(deterministic, 'Core fixture includes deterministic deployments');
  if (!profileMode) await assert.rejects(exportPublicDeployment({ artifact, allowCoreOnly: true, verification,
    broadcasts: { ...core, transactions: core.transactions.map(tx => tx === deterministic
      ? { ...tx, contractAddress: accounts[1] } : tx) },
  }), error => error instanceof AvaReceiptError && error.code === 'receipt_mismatch');
  const coreAddresses = coreOnly.deployment.addresses;
  for (const tx of core.transactions) await recordCost('core', tx.contractName ?? tx.transactionType, tx.hash as Hex);
  // These exact stateless defaults can already belong to another app on the same Core.
  const sharedPolicies: Address[] = [];
  for (const name of ['DefaultAVACorePolicyBundle', 'DefaultAVAExtensionPolicyModule']) {
    const compiled = await artifact(name) as { abi: Abi; bytecode: { object: Hex } };
    const hash = await signers[0].deployContract({ abi: compiled.abi, bytecode: compiled.bytecode.object });
    const receipt = await client.waitForTransactionReceipt({ hash });
    assert(receipt.contractAddress);
    sharedPolicies.push(receipt.contractAddress);
    await recordCost('shared-policy-setup', name, hash);
  }
  const defaultPolicies = { corePolicy: sharedPolicies[0], extensionPolicy: sharedPolicies[1] };
  const installArgs = [accounts[0], coreAddresses.kernel, coreAddresses.requests, coreAddresses.challenges,
    ...accounts.slice(1, 4)];
  let snapshot = await client.request({ method: 'evm_snapshot' } as never);
  const profileExpiry = (await client.getBlock()).timestamp + 3600n;
  let freshElapsedMs = 0;
  let reusedElapsedMs = 0;
  const rejectedPolicies: string[] = [];
  if (!profileMode) {
  const freshStart = performance.now();
  const fresh = await runForge('script/InstallWorkOrder.s.sol:InstallWorkOrder',
    'run(address,address,address,address,address,address,address)', installArgs, 'work-order-fresh.log');
  freshElapsedMs = performance.now() - freshStart;
  for (const tx of fresh.transactions) await recordCost('fresh-install', tx.contractName ?? tx.transactionType, tx.hash as Hex);
  assert.equal(await client.request({ method: 'evm_revert', params: [snapshot] } as never), true);
  const reuseSignature = 'runWithPolicies(address,address,address,address,address,address,address,address,address)';
  for (const [label, pair] of [
    ['wrong-core', [accounts[4], defaultPolicies.extensionPolicy]],
    ['wrong-type', [defaultPolicies.extensionPolicy, defaultPolicies.corePolicy]],
    ['wrong-extension', [defaultPolicies.corePolicy, accounts[4]]],
  ] as const) {
    const child = start('forge', ['script', 'script/InstallWorkOrder.s.sol:InstallWorkOrder', '--offline',
      '--sig', reuseSignature, ...installArgs, ...pair, '--rpc-url', rpcUrl, '--sender', accounts[0], '-vv'],
      `rejected-${label}.log`);
    assert.notEqual((await once(child, 'exit'))[0], 0, `${label} cannot install`);
    // The failure must be the exact-policy guard, not an unrelated CLI or compiler failure.
    await logs.at(-1);
    assert.match(await readFile(`rejected-${label}.log`, 'utf8'), /InvalidDefaultPolicies/);
    rejectedPolicies.push(label);
  }
  }
  const profiles = profileMode ? [
    { name: 'fresh-split', reuse: false, split: true },
    { name: 'fresh-combined', reuse: false, split: false },
    { name: 'reused-combined', reuse: true, split: false },
  ] : [{ name: 'default', reuse: true, split: false }];
  const commonTransactions = transactions.filter(tx => tx.phase === 'core' || tx.phase === 'shared-policy-setup');
  const summarize = (items: typeof transactions, names: string[]) => Object.fromEntries(names.map(phase => {
    const selected = items.filter(tx => tx.phase === phase);
    return [phase, { transactions: selected.length, gasUsed: selected.reduce((sum, tx) => sum + tx.gasUsed, 0n),
      feeWei: selected.reduce((sum, tx) => sum + tx.feeWei, 0n), calldataBytes: selected.reduce((sum, tx) => sum + tx.calldataBytes, 0) }];
  }));
  const profileResults: { name: string; phases: ReturnType<typeof summarize>; [key: string]: unknown }[] = [];
  const packageHashes = JSON.parse(await readFile('package-hashes.json', 'utf8'));
  const fixtureHashes = JSON.parse(await readFile('fixture-hashes.json', 'utf8'));
  for (const [profileIndex, profile] of profiles.entries()) {
  const firstTransaction = transactions.length;
  const beforeInstall = profileMode ? undefined : await client.request({ method: 'evm_snapshot' } as never) as Hex;
  const reusedStart = performance.now();
  let installed = await runForge('script/InstallWorkOrder.s.sol:InstallWorkOrder', profile.reuse
    ? 'runWithPolicies(address,address,address,address,address,address,address,address,address)'
    : 'run(address,address,address,address,address,address,address)',
    profile.reuse ? [...installArgs, ...sharedPolicies] : installArgs,
    profileMode ? `work-order-${profile.name}.log` : 'work-order-install.log');
  const installElapsedMs = performance.now() - reusedStart;
  reusedElapsedMs = installElapsedMs;
  if (profile.reuse) assert(!installed.transactions.some(tx => tx.transactionType === 'CREATE'
    && ['DefaultAVACorePolicyBundle', 'DefaultAVAExtensionPolicyModule'].includes(tx.contractName ?? '')), 'Reuse creates no duplicate stateless policies');
  const exportInstallation = (broadcast: FoundryBroadcast) => exportPublicDeployment({ broadcasts: [core, broadcast], artifact, verification,
    ...(profile.reuse ? { defaultPolicies } : {}) });
  const declaration = await exportInstallation(installed);
  if (!profileMode) {
    const calls = installed.transactions.filter(tx => tx.transactionType === 'CALL');
    assert(calls.length >= 2, 'WorkOrder fixture includes distinct installation calls');
    const [first, second] = calls;
    const swapped = { ...installed, transactions: installed.transactions.map(tx => tx === first ? { ...tx, hash: second.hash }
      : tx === second ? { ...tx, hash: first.hash } : tx) };
    await assert.rejects(exportInstallation(swapped), error => error instanceof AvaReceiptError && error.code === 'receipt_mismatch');
    const emptyLocalLogs = { ...installed, receipts: installed.receipts.map(receipt => ({ ...receipt, logs: [] })) };
    assert.deepEqual(await exportInstallation(emptyLocalLogs), declaration, 'Verified IDs come from canonical receipt logs');
  }
  const appId = key('independent.work-order.app.v1');
  const app = declaration.apps[appId];
  assert(app, 'Exporter discovers the new app using its receipts');
  assert.equal(Object.keys(declaration.apps).length, 1);
  assert(app.contracts.WorkOrderLedger && app.contracts.WorkOrderModule);
  const sdk = new AvaSdk(declaration.deployment), extensions = new AvaExtensions(sdk, {});
  await sdk.verify(client);
  const roles = ['requester', 'inspector', 'manager'].map(role => key(`independent.work-order.role.${role}.v1`));
  const subjects = roles.map((role, i) => keccak256(encodeAbiParameters(
    [{ type: 'bytes32' }, { type: 'bytes32' }, { type: 'address' }], [appId, role, accounts[i + 1]])));
  const allocationAction = key('ava.extension.allocation.record.v1');
  const requiredActions = [
    ['ava.core.register-evidence.v1', 'ava.core.register-correction-evidence.v1', 'ava.core.register-governed-object.v1',
      'ava.extension.request.create.v1', 'ava.extension.request.challenge.file.v1'].map(key),
    ['ava.core.form-recognised-state.v1', 'ava.core.transition-recognised-state.v1', 'ava.core.vest-recognised-state.v1',
      'ava.extension.request.challenge.resolve.v1'].map(key),
    [allocationAction],
  ];
  const requiredSubjects = roles.map((roleKey, i) => ({ account: accounts[i + 1], roleKey, subjectId: subjects[i], actionKeys: requiredActions[i] }));
  const applicationCapability = key('ava.capability.application.v1');
  const applicationModule = { capabilityKey: applicationCapability, module: app.contracts.WorkOrderModule.address };
  const expectations: InstallationExpectations = { appId, workflowKey: app.workflowKey,
    activePackageId: BigInt(app.packageId),
    modules: [applicationModule, ...app.modules.filter(binding => binding.capabilityKey !== applicationCapability)],
    requiredSubjects,
    administration: { root: accounts[0], application: accounts[0], pendingRoot: zeroAddress, pendingApplication: zeroAddress },
    correctionOrigins: app.correctionOrigins, sourceCorrectionBindings: app.sourceCorrectionBindings,
    forbiddenPermissions: [
      { account: accounts[2], roleKey: roles[1], actionKey: allocationAction },
      { account: accounts[0], roleKey: key('independent.work-order.bootstrap.v1'),
        actionKey: key('ava.core.register-rule-package.v1') },
    ] };
  let installationRecovery: { partial: Awaited<ReturnType<AvaExtensions['verifyInstallation']>>; resumedHash: Hex } | undefined;
  if (beforeInstall) {
    const recovered = await rehearseInstallRecovery(installed, beforeInstall, extensions, expectations);
    installed = recovered.broadcast;
    installationRecovery = { partial: recovered.partial, resumedHash: recovered.resumedHash };
    assert.deepEqual(await exportInstallation(installed), declaration, 'Recovery preserves the public installation identity');
  }
  for (const tx of installed.transactions) await recordCost('install', tx.contractName ?? tx.transactionType, tx.hash as Hex);
  const deploymentFile = profileMode ? `public-deployment-${profile.name}.json` : 'public-deployment.json';
  await writeFile(deploymentFile, json(declaration));
  const installation = await extensions.verifyInstallation(client, expectations);
  assert.equal(installation.ready, true, json(installation.findings));
  let installationDiagnostics;
  if (!profileMode) {
    const wrong = await extensions.verifyInstallation(client, { ...expectations,
      modules: [{ ...applicationModule, module: app.contracts.WorkOrderLedger.address }],
      requiredSubjects: [{ ...requiredSubjects[0], subjectId: subjects[1] }],
    }, installation.point);
    const wrongModule = wrong.findings.find(finding =>
      finding.check === `module:${expectations.activePackageId}:${applicationCapability}`)?.status;
    const wrongSubject = wrong.findings.find(finding => finding.check === `subject:${subjects[1]}:canonical`)?.status;
    assert.equal(wrong.ready, false);
    assert.equal(wrongModule, 'mismatch');
    assert.equal(wrongSubject, 'mismatch');
    const repaired = await extensions.verifyInstallation(client, expectations, installation.point);
    assert.equal(repaired.ready, true, json(repaired.findings));
    installationDiagnostics = { wrongModule, wrongSubject, correctedDeclarationReady: repaired.ready, point: repaired.point };
  }
  assert.equal(app.requiredSubjects.length, 3, 'Bootstrap publisher is deactivated');
  assert.equal(app.correctionOrigins.length, 1);
  assert.equal(app.sourceCorrectionBindings.length, 1);
  const ledger = app.contracts.WorkOrderLedger;
  let ruleGovernance: AvaExtensions | undefined;
  let replacementModule: Address | undefined;
  if (ruleLifecycleMode) {
    const bootstrap = await runForge('script/InstallRuleLifecycle.s.sol:InstallRuleLifecycle',
      'run(address,address,address,address,address,address)',
      [accounts[0], coreAddresses.kernel, coreAddresses.challenges, ...accounts.slice(1, 4)], 'rule-bootstrap.log');
    const createdContract = (name: string) => {
      const matching = bootstrap.transactions.filter(tx => tx.transactionType === 'CREATE' && tx.contractName === name);
      assert.equal(matching.length, 1, name);
      assert(matching[0].contractAddress, name);
      return matching[0].contractAddress as Address;
    };
    const controller = createdContract('AVARecognisedRuleGovernance');
    ruleGovernance = new AvaExtensions(sdk, { ruleGovernance: controller });
    replacementModule = createdContract('RetiredWorkOrderModule');
    for (const tx of bootstrap.transactions) await recordCost('rule-bootstrap', tx.contractName ?? tx.transactionType, tx.hash as Hex);
  }
  const token = randomBytes(32).toString('base64url');
  let interruptedSend: { attempts: Hex[]; accepted: number } | undefined;
  const relayClient = ruleLifecycleMode ? { ...client, sendRawTransaction: async (request: Parameters<typeof client.sendRawTransaction>[0]) => {
    if (!interruptedSend) return client.sendRawTransaction(request);
    const send = interruptedSend;
    send.attempts.push(keccak256(request.serializedTransaction));
    if (send.attempts.length === 1) throw new Error('Synthetic interruption before node submission');
    await client.sendRawTransaction(request);
    send.accepted++;
    throw new Error('Synthetic interruption after node acceptance');
  } } : client;
  service = await buildAvaService({ client: relayClient, sdk, token,
    databasePath: resolve(profileMode ? `service-${profile.name}.sqlite` : 'service.sqlite'),
    extensions: ruleGovernance,
    additionalSources: { workOrders: { address: ledger.address, abi: ledger.abi } } });
  await service.app.listen({ host: '127.0.0.1', port: 0 });
  const remote = new AvaServiceClient(service.app.listeningOrigin, token);
  assert.equal((await remote.health()).status, 'synced');
  const authority = (i: number) => ({ roleKey: roles[i], authorityId: subjects[i] });
  let sequence = 0;
  async function execute(actor: number, operation: string, call: AvaCall, abi: Abi = []) {
    const signed = await sdk.sign(client, signers[actor], call, abi);
    const txKey = `work-order:${++sequence}`;
    const submitted = await remote.submit(txKey, signed.serializedTransaction);
    assert.equal(submitted.hash, signed.hash);
    const observed = await remote.observeTransaction({ key: txKey, hash: signed.hash }, { pollIntervalMs: 20 });
    assert.equal(observed.status, 'confirmed');
    const phase = operation.startsWith('rule-') ? 'rule-lifecycle' : operation.startsWith('handover-') ? 'installation-handover'
      : profileMode && (operation === 'revoke-manager' || operation === 'restore-manager')
      ? 'verification-permissions' : profileMode && ['correction-evidence', 'challenge-completed-effect', 'resolve-finite-correction'].includes(operation)
        ? 'correction' : 'business';
    await recordCost(phase, operation, signed.hash);
    return signed.hash;
  }
  async function refused(actor: number, call: AvaCall, abi: Abi = [], expectedError?: string) {
    await assert.rejects(() => sdk.sign(client, signers[actor], call, abi), (error: unknown) => {
      assert(error instanceof AvaSigningError);
      assert.equal(error.stage, 'simulation');
      assert.equal(error.code, 'contract_reverted');
      if (expectedError) assert.equal(error.errorName, expectedError);
      return true;
    });
  }
  async function created(actor: number, operation: string, call: AvaCall, event: Parameters<AvaSdk['createdId']>[2]) {
    return (await sdk.createdId(client, await execute(actor, operation, call), event)).id;
  }
  const contracts = sdk.contracts(client);
  let handover: { overgrant: typeof installation; unavailable: typeof installation; repaired: typeof installation } | undefined;
  if (!profileMode) {
    const proposeAdmin = (account: Address): AvaCall => ({ to: coreAddresses.applications, data: encodeFunctionData({
      abi: avaAbis.applications, functionName: 'proposeApplicationAdmin', args: [appId, account] }) });
    const acceptAdmin: AvaCall = { to: coreAddresses.applications, data: encodeFunctionData({
      abi: avaAbis.applications, functionName: 'acceptApplicationAdmin', args: [appId] }) };
    const inspectorAllocation = (allowed: boolean): AvaCall => ({ to: coreAddresses.authority, data: encodeFunctionData({
      abi: avaAbis.authority, functionName: 'setPermission', args: [appId, roles[1], allocationAction, allowed] }) });
    await execute(0, 'handover-nominate-initial', proposeAdmin(accounts[5]));
    await execute(5, 'handover-accept-initial', acceptAdmin);
    await execute(5, 'handover-overgrant-inspector', inspectorAllocation(true));
    const inspectorAllocationCheck = `permission:forbidden:${accounts[2]}:${roles[1]}:${allocationAction}`;
    const delegated = { ...expectations, administration: { ...expectations.administration, application: accounts[5] } };
    const overgrant = await extensions.verifyInstallation(client, delegated);
    assert.equal(overgrant.ready, false);
    assert.deepEqual(overgrant.findings.map(f => [f.check, f.status]), [[inspectorAllocationCheck, 'mismatch']]);
    await execute(5, 'handover-nominate-successor', proposeAdmin(accounts[6]));
    const pending = await extensions.verifyInstallation(client, delegated);
    assert.deepEqual(pending.findings.map(f => [f.check, f.status]), [
      ['administration:pendingApplication', 'mismatch'], [inspectorAllocationCheck, 'mismatch'],
    ]);
    await refused(6, inspectorAllocation(false));
    await execute(6, 'handover-accept-successor', acceptAdmin);
    await refused(5, inspectorAllocation(false));
    await execute(6, 'handover-repair-inspector', inspectorAllocation(false));
    const successor = { ...expectations, administration: { ...expectations.administration, application: accounts[6] } };
    const inspectorPermissionRead = encodeFunctionData({ abi: avaAbis.authority, functionName: 'isAuthorised',
      args: [accounts[2], appId, roles[1], allocationAction] });
    const unavailableClient = createPublicClient({ transport: custom({ request: async request => {
      const [call] = Array.isArray(request.params) ? request.params : [];
      if (request.method === 'eth_call' && call?.data === inspectorPermissionRead) {
        throw { code: -32603, message: 'Synthetic permission read failure' };
      }
      return client.request(request as never);
    } }, { retryCount: 0 }) });
    const repaired = await extensions.verifyInstallation(client, successor);
    assert.equal(repaired.ready, true, json(repaired.findings));
    const unavailable = await extensions.verifyInstallation(unavailableClient, successor, repaired.point);
    assert.equal(unavailable.ready, false);
    assert.deepEqual(unavailable.findings.map(f => [f.check, f.status]), [[inspectorAllocationCheck, 'unavailable']]);
    assert.equal((await extensions.verifyInstallation(client, successor, repaired.point)).ready, true);
    handover = { overgrant, unavailable, repaired };
  }
  const workflowKey = app.workflowKey, packageId = BigInt(app.packageId), disclosurePolicyId = BigInt(app.disclosurePolicyId);
  const responseClass = key('independent.work-order.response.close.v1'), burdenHash = key('independent.work-order.burden.inspection.v1');
  const expiry = profileMode ? profileExpiry : (await client.getBlock()).timestamp + 3600n;
  async function prepareOrder(orderId: Hex, completionHash: Hex, prefix = '') {
    const parametersHash = keccak256(encodeAbiParameters([{ type: 'bytes32' }, { type: 'bytes32' }], [orderId, completionHash]));
    const commitment = await contracts.requests.read.commitmentFor([appId, ledger.address, responseClass, parametersHash, burdenHash, expiry]);
    const evidence = { appId, workflowKey, packageId, ...authority(0), subjectId: subjects[0], commitment: completionHash,
      evidenceTypeHash: key('independent.work-order.evidence.inspection.v1'), disclosurePolicyId, uri: 'local:synthetic-inspection' };
    const evidenceId = await created(1, `${prefix}register-inspection`, sdk.registerEvidence(evidence),
      { source: 'evidence', eventName: 'EvidenceRegistered', idField: 'evidenceId' });
    const objectId = await created(1, `${prefix}register-work-order`, sdk.registerObject({ ...evidence,
      objectTypeKey: key('independent.work-order.object.v1'), objectCommitment: commitment,
      parentObjectId: 0n, evidenceReceiptId: evidenceId, metadataHash: parametersHash }),
      { source: 'kernel', eventName: 'GovernedObjectRegistered', idField: 'id' });
    const formationInput = { governedObjectId: objectId, ...authority(1), stage: Stage.Verification,
      status: RecognitionStatus.Provisional, reasonHash: key('Inspector observed synthetic completion'), reasonURI: 'local:inspection' };
    const formation = profile.split ? sdk.formRecognition(formationInput)
      : sdk.formChallengeable(formationInput, key('Synthetic inspection accepted'), 'local:inspection');
    if (!prefix) await refused(1, formation);
    const stateId = await created(2, `${prefix}inspector-recognition`, formation,
      { source: 'kernel', eventName: 'RecognisedStateFormed', idField: 'id' });
    const transition = { recognisedStateId: stateId, ...authority(1), reasonHash: key('Synthetic inspection accepted'), reasonURI: 'local:inspection' };
    if (profile.split) await execute(2, `${prefix}mark-challengeable`, sdk.transition({ ...transition, toStatus: RecognitionStatus.Challengeable }));
    await execute(2, `${prefix}vest`, sdk.vest({ ...transition, toStatus: RecognitionStatus.Vested }));
    const requestId = await created(1, `${prefix}request-close`, sdk.createRequest({ recognisedStateId: stateId,
      executor: ledger.address, responseClass, parametersHash, burdenHash, validUntil: expiry }, authority(0)),
      { source: 'requests', eventName: 'RequestCreated', idField: 'requestId' });
    const close = (completion = completionHash): AvaCall => ({ to: ledger.address,
      data: encodeFunctionData({ abi: ledger.abi, functionName: 'closeOrder', args: [requestId, orderId, completion] }) });
    return { orderId, evidence, evidenceId, objectId, stateId, requestId, parametersHash, close };
  }
  const { orderId, evidence, evidenceId, objectId, stateId, requestId, parametersHash, close } = await prepareOrder(
    key('work-order:repair-pump-17'), key('Synthetic inspection report: pump 17 completed'));
  await refused(4, close(), ledger.abi);
  const allocation = sdk.allocate(requestId, authority(2));
  await refused(1, allocation);
  await execute(3, 'allocate-close', allocation);
  const permission = (enabled: boolean): AvaCall => ({ to: coreAddresses.authority,
    data: encodeFunctionData({ abi: avaAbis.authority, functionName: 'setPermission',
      args: [appId, roles[2], allocationAction, enabled] }) });
  await execute(0, 'revoke-manager', permission(false));
  await refused(4, close(), ledger.abi);
  assert.equal((await sdk.request(client, requestId)).record.consumed, false);
  await execute(0, 'restore-manager', permission(true));
  await refused(4, close(key('different inspection')), ledger.abi);
  await execute(4, 'close-work-order', close(), ledger.abi);
  await refused(4, close(), ledger.abi);
  const originalRecognition = await sdk.recognition(client, stateId);
  const originalRequest = (await sdk.request(client, requestId)).record;
  const originalReceipt = await client.readContract({ address: ledger.address, abi: ledger.abi,
    functionName: 'getReceipt', args: [requestId] }) as { effectHash: Hex; orderId: Hex };
  assert.equal(originalRequest.completed, true);
  assert.equal(originalReceipt.orderId, orderId);
  assert.equal(originalReceipt.effectHash, originalRequest.effectHash);

  let ruleLifecycle: { replacementPackageId: string; backlogRequestId: bigint; checks: Record<string, boolean> } | undefined;
  if (ruleGovernance && replacementModule) {
    const backlog = await prepareOrder(key('work-order:repair-pump-18'), key('Synthetic inspection report: pump 18 completed'), 'rule-backlog-');
    await execute(3, 'rule-backlog-allocate', sdk.allocate(backlog.requestId, authority(2)));
    const originalBacklogRecognition = await sdk.recognition(client, backlog.stateId);
    const approved = (await sdk.request(client, backlog.requestId)).record;
    assert.equal(approved.packageId, packageId);
    assert.equal(approved.allocator.toLowerCase(), accounts[3].toLowerCase());
    assert(approved.approvedAt > 0n && !approved.consumed && !approved.completed);
    const governor = ruleGovernance, controller = governor.ruleGovernance(client).address;
    const successorModule = replacementModule;
    const governingWorkflowKey = key('independent.work-order.governance.v1');
    const governingPackageId = await contracts.packages.read.getActivePackageId([appId, governingWorkflowKey]);
    const previous = await contracts.packages.read.getRulePackageById([packageId]);
    const applicationCapability = key('ava.capability.application.v1');
    const bindings = app.modules.map(binding => binding.capabilityKey === applicationCapability
      ? { ...binding, module: successorModule } : binding);
    assert.equal(bindings.filter(binding => binding.module === successorModule).length, 1);
    const proposed = { appId, workflowKey, ...authority(2), version: previous.version + 1n,
      compatibilityKey: previous.compatibilityKey, uri: 'local:work-order/close-intake' };
    const competingUri = 'local:work-order/competing-revision-2';
    async function propose(terms: typeof proposed) {
      const commitment = await contracts.packages.read.revisionCommitment([terms, packageId, bindings]);
      const revisionEvidence = { ...evidence, workflowKey: governingWorkflowKey, packageId: governingPackageId,
        commitment: key(`Synthetic proposal evidence ${terms.uri}`), uri: terms.uri };
      const revisionEvidenceId = await created(1, 'rule-evidence', sdk.registerEvidence(revisionEvidence),
        { source: 'evidence', eventName: 'EvidenceRegistered', idField: 'evidenceId' });
      const revisionObject = await created(1, 'rule-object', sdk.registerObject({ ...revisionEvidence,
        objectTypeKey: key('ava.rule-revision.proposal.v1'), objectCommitment: commitment,
        metadataHash: commitment, parentObjectId: 0n, evidenceReceiptId: revisionEvidenceId }),
      { source: 'kernel', eventName: 'GovernedObjectRegistered', idField: 'id' });
      const reasonHash = key('Synthetic revision terms verified'), reasonURI = 'local:rule-verification';
      const sourceStateId = await created(2, 'rule-recognise', sdk.formChallengeable({ governedObjectId: revisionObject,
        ...authority(1), stage: Stage.Verification, status: RecognitionStatus.Provisional, reasonHash, reasonURI }, reasonHash, reasonURI),
      { source: 'kernel', eventName: 'RecognisedStateFormed', idField: 'id' });
      await execute(2, 'rule-vest', sdk.vest({ recognisedStateId: sourceStateId, ...authority(1),
        toStatus: RecognitionStatus.Vested, reasonHash, reasonURI }));
      const { state } = await sdk.recognition(client, sourceStateId);
      const call = governor.registerRuleProposal({ sourceStateId, expectedSourceTransitionId: state.lastTransitionId,
        expectedTargetPackageId: packageId, correctionOfAppliedProposal: 0n }, terms, bindings, authority(0));
      const hash = await execute(1, 'rule-register-proposal', call, avaExtensionAbis.ruleGovernance);
      return (await governor.createdId(client, hash, { source: 'ruleGovernance', eventName: 'RuleRevisionProposed', idField: 'proposalId' })).id;
    }
    const proposalId = await propose(proposed), competingId = await propose({ ...proposed, uri: competingUri });
    await writeFile('rule-handoff.json', json({ deployment: sdk.deployment, governor: controller,
      authority: authority(2), proposalId, competingId, competingUri, proposed, bindings, originalPackageId: packageId }));
    const reviser = start(process.execPath, ['build/rule-reviser.js', 'rule-handoff.json', 'rule-revision.json'], 'rule-reviser.log', {
      AVA_RULE_RPC_URL: rpcUrl, AVA_RULE_SERVICE_URL: service.app.listeningOrigin, AVA_RULE_SERVICE_TOKEN: token,
    });
    assert.equal((await once(reviser, 'exit'))[0], 0, 'Independent rule reviser failed; inspect rule-reviser.log');
    const revision = JSON.parse(await readFile('rule-revision.json', 'utf8')) as {
      replacementPackageId: string; hash: Hex; checks: Record<string, boolean>;
    };
    const replacementPackageId = BigInt(revision.replacementPackageId);
    await recordCost('rule-lifecycle', 'rule-activate', revision.hash);
    const before = { ...expectations, governanceController: controller,
      requiredSubjects: [
        { ...requiredSubjects[0], actionKeys: [...requiredActions[0], key('ava.extension.rule-governance.propose.v1')] },
        requiredSubjects[1],
        { ...requiredSubjects[2], actionKeys: [...requiredActions[2], key('ava.extension.rule-governance.revise.v1')] },
      ],
      administration: { ...expectations.administration, application: accounts[6] } };
    const stale = await governor.verifyInstallation(client, before);
    assert.deepEqual(stale.findings.map(finding => finding.check), ['activePackage']);
    const current = await governor.verifyInstallation(client, { ...before, activePackageId: replacementPackageId,
      historicalPackageIds: [packageId], modules: [...bindings, ...app.modules.map(binding => ({ ...binding, packageId }))],
      sourceCorrectionBindings: [...app.sourceCorrectionBindings, ...app.sourceCorrectionBindings.map(binding => ({ ...binding, packageId }))],
    });
    assert.equal(current.ready, true, json(current.findings));
    const successorEvidence = { ...evidence, packageId: replacementPackageId,
      commitment: key('Synthetic evidence under replacement package'), uri: 'local:work-order/revision-2/evidence' };
    const successorEvidenceId = await created(1, 'rule-successor-evidence', sdk.registerEvidence(successorEvidence),
    { source: 'evidence', eventName: 'EvidenceRegistered', idField: 'evidenceId' });
    const newOrderTerms = { objectTypeKey: key('independent.work-order.object.v1'), parentObjectId: 0n,
      objectCommitment: key('A new WorkOrder after retirement'), metadataHash: parametersHash };
    await refused(1, sdk.registerObject({ ...evidence, ...newOrderTerms, evidenceReceiptId: evidenceId }),
      avaAbis.kernel, 'InvalidState');
    await refused(1, sdk.registerObject({ ...successorEvidence, ...newOrderTerms, evidenceReceiptId: successorEvidenceId }),
      [{ type: 'error', name: 'WorkOrderIntakeClosed', inputs: [] }], 'WorkOrderIntakeClosed');
    assert.deepEqual((await sdk.request(client, backlog.requestId)).record, approved);
    const signedBacklog = await sdk.sign(client, signers[4], backlog.close(), ledger.abi);
    const backlogKey = `work-order:${++sequence}`;
    const { hash, serializedTransaction } = signedBacklog;
    const identity = { key: backlogKey, hash };
    const send = { attempts: [] as Hex[], accepted: 0 };
    interruptedSend = send;
    const firstSend = await remote.submit(backlogKey, serializedTransaction);
    assert.equal(firstSend.status, 'unknown', 'The relay must preserve an interrupted submission as uncertain');
    const status = await remote.transaction(backlogKey);
    assert.deepEqual({ key: status.key, hash: status.hash }, identity);
    assert.equal(status.status, 'unknown');
    assert.equal((await remote.submit(backlogKey, serializedTransaction)).status, 'unknown');
    const aliasKey = `${backlogKey}:retry`;
    const alias = await remote.submit(aliasKey, serializedTransaction);
    assert.deepEqual({ key: alias.key, hash: alias.hash, status: alias.status }, { key: aliasKey, hash, status: 'unknown' });
    await assert.rejects(remote.observeTransaction(identity, { pollIntervalMs: 20, timeoutMs: 250 }),
      error => error instanceof AvaServiceError && error.code === 'observation_timeout');
    const differentBytes = `${serializedTransaction.slice(0, -2)}${serializedTransaction.endsWith('00') ? '01' : '00'}` as Hex;
    await assert.rejects(remote.recoverSubmit(backlogKey, differentBytes),
      error => error instanceof AvaServiceError && error.code === 'transaction_conflict');
    assert.deepEqual(send, { attempts: [hash], accepted: 0 });
    assert.deepEqual((await sdk.request(client, backlog.requestId)).record, approved);

    const recovered = await remote.recoverSubmit(backlogKey, serializedTransaction);
    assert.equal(recovered.status, 'unknown', 'A lost response after node acceptance still needs observation');
    const observed = await remote.observeTransaction(identity, { pollIntervalMs: 20 });
    assert.equal(observed.status, 'confirmed');
    assert.equal(observed.nonce, firstSend.nonce);
    const receipt = await client.getTransactionReceipt({ hash });
    assert.equal(receipt.status, 'success');
    assert.equal(observed.blockHash, receipt.blockHash);
    assert.equal((await client.getBlock({ blockNumber: receipt.blockNumber })).hash, observed.blockHash);
    assert.equal((await remote.recoverSubmit(backlogKey, serializedTransaction)).status, 'confirmed');
    assert.deepEqual(send, { attempts: [hash, hash], accepted: 1 });
    interruptedSend = undefined;
    const transactionRecovery = { ...identity, nonce: observed.nonce, blockHash: receipt.blockHash,
      attempts: send.attempts.length, accepted: send.accepted };
    await recordCost('rule-lifecycle', 'rule-backlog-close', hash);
    await refused(4, backlog.close(), ledger.abi);
    const closed = (await sdk.request(client, backlog.requestId)).record;
    assert(closed.completed && closed.consumed && closed.effectHash !== approved.effectHash);
    assert.equal(closed.triggeredBy.toLowerCase(), accounts[4].toLowerCase());
    assert.deepEqual({ ...closed, completed: approved.completed, consumed: approved.consumed, effectHash: approved.effectHash,
      triggeredBy: approved.triggeredBy, consumedAt: approved.consumedAt, completedAt: approved.completedAt }, approved);
    assert.deepEqual(await sdk.recognition(client, backlog.stateId), originalBacklogRecognition);
    const backlogReceipt = await client.readContract({ address: ledger.address, abi: ledger.abi,
      functionName: 'getReceipt', args: [backlog.requestId] }) as { orderId: Hex; effectHash: Hex; sourceTransitionId: bigint };
    assert.equal(backlogReceipt.orderId, backlog.orderId);
    assert.equal(backlogReceipt.effectHash, closed.effectHash);
    assert.equal(backlogReceipt.sourceTransitionId, approved.recognisedStateTransitionId);
    const backlogEffects = await remote.events({ source: 'workOrders', expectedSourceAddress: ledger.address,
      event: 'WorkOrderClosed', arg: { name: 'requestId', value: backlog.requestId.toString() } });
    assert.equal(backlogEffects.items.length, 1);
    const lifecycleResult = { proposalId, competingId, ...revision, backlogRequestId: backlog.requestId, transactionRecovery,
      checks: { ...revision.checks, predecessorIntakeRefused: true, successorIntakeRefused: true,
        approvedBacklogExecutedOnce: true, explicitRecovery: true },
      oldInstallationRefused: !stale.ready, successorInstallation: current };
    ruleLifecycle = lifecycleResult;
  }
  const correctionEvidence = { ...evidence,
    commitment: key('Synthetic follow-up inspection: closure occurred, earlier report omitted a limitation'),
    uri: 'local:follow-up-inspection' };
  const ordinaryEvidence = sdk.registerEvidence(correctionEvidence);
  const admissionPackageId = ruleLifecycle ? BigInt(ruleLifecycle.replacementPackageId) : undefined;
  if (admissionPackageId !== undefined) await refused(1, ordinaryEvidence);
  const correctionEvidenceId = await created(1, 'correction-evidence', admissionPackageId === undefined
    ? ordinaryEvidence : sdk.registerCorrectionEvidence(correctionEvidence, admissionPackageId, key('Historical inspection follow-up')),
  { source: 'evidence', eventName: 'EvidenceRegistered', idField: 'evidenceId' });
  if (admissionPackageId !== undefined) {
    const [admittedBy] = await contracts.evidence.read.correctionEvidenceAdmissions([correctionEvidenceId]);
    assert.equal(admittedBy, admissionPackageId);
  }
  const challengeId = await created(1, 'challenge-completed-effect', sdk.fileRequestChallenge(requestId,
    RequestChallengeTarget.Effect, correctionEvidenceId, authority(0), key('Examine limited inspection claim after closure')),
    { source: 'requests', eventName: 'RequestChallengeFiled', idField: 'challengeId' });
  const caseId = await contracts.requests.read.correctionReviewCaseIdByChallenge([challengeId]);
  const finding = { existingFindingId: 0n, supersedesFindingId: 0n,
    claimHash: key('Closure occurred; follow-up inspection limits the earlier completion claim'),
    useScopeHash: key('This work-order closure only; no second execution or operational safety certification'),
    burdenHash: key('Original immutable closure receipt and synthetic follow-up inspection') };
  const resolveCorrection = sdk.resolveRequestChallenge({ challengeId, expectedPreviousResolutionId: 0n, ...authority(1),
    decisionEvidenceId: correctionEvidenceId, outcome: RequestResolutionOutcome.Residual,
    reasonHash: key('Retain completed closure and record finite later finding'),
    remedy: { asset: zeroAddress, recipient: zeroAddress, amount: 0n }, finding });
  await refused(1, resolveCorrection);
  await execute(2, 'resolve-finite-correction', resolveCorrection);
  const correction = await sdk.correctionCase(client, caseId);
  assert.equal(correction.record.input.packageId, packageId);
  assert.equal(correction.record.input.targetPackageId, packageId);
  assert.equal(correction.record.input.targetId, requestId);
  assert(correction.originRecord?.family === 'request');
  assert.equal(correction.originRecord.record.outcome, RequestResolutionOutcome.Residual);
  assert(correction.finding);
  assert.equal(correction.finding.claimHash, finding.claimHash);
  assert.equal(correction.finding.useScopeHash, finding.useScopeHash);
  assert.equal(correction.finding.burdenHash, finding.burdenHash);
  assert.equal(correction.finding.verifier.toLowerCase(), accounts[2].toLowerCase());
  assert.deepEqual(await sdk.recognition(client, stateId), originalRecognition);
  assert.deepEqual((await sdk.request(client, requestId)).record, originalRequest);
  assert.deepEqual(await client.readContract({ address: ledger.address, abi: ledger.abi,
    functionName: 'getReceipt', args: [requestId] }), originalReceipt);
  await refused(4, close(), ledger.abi);
  const listedStates = await remote.recognitions(appId), listedRequests = await remote.requests(appId);
  assert.equal(listedStates.items.length, ruleLifecycle ? 4 : 1);
  assert.equal(listedStates.items.find(item => item.state.id === stateId.toString())?.state.status, RecognitionStatus.Vested);
  assert.equal(listedRequests.items.length, ruleLifecycle ? 2 : 1);
  assert.equal(listedRequests.items.find(item => item.record.id === requestId.toString())?.record.completed, true);
  if (ruleLifecycle) assert.equal(listedRequests.items.find(item => item.record.id === ruleLifecycle.backlogRequestId.toString())?.record.completed, true);
  const effects = await remote.events({ source: 'workOrders', expectedSourceAddress: ledger.address,
    event: 'WorkOrderClosed', arg: { name: 'requestId', value: requestId.toString() } });
  assert.equal(effects.items.length, 1, 'HTTP projection retains exactly one closure');
  const corrections = await remote.corrections(appId);
  assert.equal(corrections.items.length, 1);
  assert.equal(corrections.items[0].finding?.claimHash, finding.claimHash);
  if (ruleLifecycle) ruleLifecycle.checks.historicalCorrectionAfterReplacement = true;
  const ids = { objectId, evidenceId, stateId, requestId, challengeId, caseId };
  const httpHistory = { recognitionCount: listedStates.items.length, requestCount: listedRequests.items.length,
    effectCount: effects.items.length, correctionCount: corrections.items.length };
  const checks = { wrongActor: true, allocationRequired: true, currentRevocation: true, exactParameters: true,
    onceOnly: true, finiteFinding: true, immutableOriginalHistory: true };
  const deploymentSha256 = createHash('sha256').update(await readFile(deploymentFile)).digest('hex');
  if (profileMode) {
    const branchTransactions = transactions.slice(firstTransaction);
    const phases = summarize(branchTransactions, ['install', 'business', 'correction', 'verification-permissions']);
    assert.equal(branchTransactions.filter(tx => tx.phase === 'verification-permissions').length, 2);
    assert.equal(branchTransactions.filter(tx => tx.phase === 'business').length, profile.split ? 8 : 7);
    assert.equal(branchTransactions.filter(tx => tx.phase === 'correction').length, 3);
    profileResults.push({ name: profile.name, policies: profile.reuse ? 'shared' : 'fresh',
      recognition: profile.split ? 'split' : 'combined', installElapsedMs, installation, ids,
      originalRecognition, originalRequest, originalReceipt, correction, http: httpHistory, checks,
      phases, transactions: branchTransactions, deploymentFile, deploymentSha256 });
    await service.app.close();
    service = undefined;
    if (profileIndex + 1 < profiles.length) {
      assert.equal(await client.request({ method: 'evm_revert', params: [snapshot] } as never), true);
      snapshot = await client.request({ method: 'evm_snapshot' } as never);
    }
  } else {
    const phases = summarize(transactions, ['core', 'shared-policy-setup', 'fresh-install', 'install', 'installation-handover', 'business',
      ...(ruleLifecycle ? ['rule-bootstrap', 'rule-lifecycle'] : [])]);
    await writeFile(ruleLifecycle ? 'lifecycle-evidence.json' : 'evidence.json', json({ status: 'scoped-checks-passed', chainId: 31337, observedAt: new Date().toISOString(),
      policyReuse: { defaultPolicies, rejectedPolicies, freshElapsedMs, reusedElapsedMs,
        note: 'Two local installation branches from one snapshot after shared-policy setup; setup is separately counted.' },
      packageHashes, fixtureHashes, installation, installationDiagnostics, installationRecovery, handover, ids, ruleLifecycle,
      deploymentVerification: { coreTransactions: core.transactions.length, appTransactions: installed.transactions.length,
        deterministicCreations: core.transactions.filter(tx => tx.transactionType === 'CREATE2').length,
        changedCreationAddressRefused: true, swappedHashesRefused: true, usesRpcRegistrationLogs: true },
      originalRecognition, originalRequest, originalReceipt, correction,
      http: httpHistory, checks, phases, transactions, deploymentSha256 }));
  }
  }
  if (profileMode) {
    assert.equal(profileResults.length, 3);
    const delta = (before: number, after: number, phase: string) => {
      const a = profileResults[before].phases[phase], b = profileResults[after].phases[phase];
      return { transactions: b.transactions - a.transactions, gasUsed: b.gasUsed - a.gasUsed,
        calldataBytes: b.calldataBytes - a.calldataBytes };
    };
    await writeFile('evidence.json', json({ status: 'scoped-checks-passed', chainId: 31337,
      observedAt: new Date().toISOString(), packageHashes, fixtureHashes, defaultPolicies,
      baseline: 'Each branch begins from the same post-Core, post-shared-policy snapshot; shared setup is counted once.',
      phases: summarize(commonTransactions, ['core', 'shared-policy-setup']),
      comparisons: { combinedVsSplitBusiness: delta(0, 1, 'business'),
        reusedVsFreshInstall: delta(1, 2, 'install'), reusedVsFreshBusiness: delta(1, 2, 'business') },
      commonTransactions, profiles: profileResults }));
  }
  console.log(`Independent WorkOrder app scoped checks passed: ${resolve(ruleLifecycleMode ? 'lifecycle-evidence.json' : 'evidence.json')}`);
} finally {
  if (service) await service.app.close();
  for (const child of processes.reverse()) {
    if (child.exitCode !== null || child.signalCode !== null) continue;
    const stopped = once(child, 'exit'); child.kill('SIGTERM'); await stopped;
  }
  await Promise.all(logs);
  process.off('SIGINT', terminate);
  process.off('SIGTERM', terminate);
}
