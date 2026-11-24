import assert from 'node:assert/strict';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { createPublicClient, custom, decodeFunctionData, encodeFunctionResult, zeroHash, type Abi, type Address, type Hex } from 'viem';
import { AvaSdk, AvaServiceClient, Stage, RecognitionStatus, RequestChallengeTarget,
  AvaExtensions,
  RequestResolutionOutcome, CorrectionReviewOutcome, type ChallengeResolutionInput, type FormationInput,
  type RequestResolutionInput, type CorrectionReviewInput } from '../src/index.ts';
import { avaAbis, challengesAbi, correctionsAbi, evidenceAbi, executionAbi, kernelAbi, requestsAbi } from '../src/abi.ts';

const addresses = Object.fromEntries(['applications', 'identities', 'authority', 'packages',
  'disclosure', 'evidence', 'kernel', 'requests', 'challenges']
  .map((name, i) => [name, `0x${(i + 1).toString(16).padStart(40, '0')}`])) as Record<
  'applications'|'identities'|'authority'|'packages'|'disclosure'|'evidence'|'kernel'|'requests'|'challenges', Address>;

test('request commitment uses named fields at the requested read point', async () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const input = { appId: `0x${'11'.repeat(32)}` as Hex, executor: addresses.evidence,
    responseClass: `0x${'22'.repeat(32)}` as Hex, parametersHash: `0x${'33'.repeat(32)}` as Hex,
    burdenHash: `0x${'44'.repeat(32)}` as Hex, validUntil: 12345n };
  const result = `0x${'55'.repeat(32)}` as Hex;
  let expectedPoint: unknown;
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    assert.equal(method, 'eth_call');
    const [call, point] = params as [{ to: Address; data: Hex }, unknown];
    assert.equal(call.to.toLowerCase(), addresses.requests);
    assert.deepEqual(point, expectedPoint);
    assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: call.data }), {
      functionName: 'commitmentFor', args: [input.appId, input.executor, input.responseClass,
        input.parametersHash, input.burdenHash, input.validUntil],
    });
    return encodeFunctionResult({ abi: requestsAbi, functionName: 'commitmentFor', result });
  } }, { retryCount: 0 }) });
  const hashPoint = { blockHash: `0x${'aa'.repeat(32)}` as Hex, requireCanonical: true as const };
  expectedPoint = hashPoint;
  assert.equal(await sdk.requestCommitment(client, input, hashPoint), result);
  expectedPoint = '0x2a';
  assert.equal(await sdk.requestCommitment(client, input, 42n), result);
});

test('optional adapters are exported and service history pages preserve opaque cursors', async () => {
  assert.equal(typeof AvaExtensions, 'function');
  const service = new AvaServiceClient('http://127.0.0.1:8080');
  const seen: URL[] = [];
  service.call = async path => { seen.push(new URL(path, service.url)); return { items: [], nextCursor: 'next' }; };
  for (const kind of ['objects', 'recognitions', 'requests'] as const) {
    assert.equal((await service[kind](zeroHash, { limit: 1, after: 'opaque&cursor?+' })).nextCursor, 'next');
    assert.equal(seen.at(-1)?.pathname, `/v1/${kind}`);
    assert.equal(seen.at(-1)?.searchParams.get('appId'), zeroHash);
    assert.equal(seen.at(-1)?.searchParams.get('limit'), '1');
    assert.equal(seen.at(-1)?.searchParams.get('after'), 'opaque&cursor?+');
    await service[kind](zeroHash);
    assert.equal(seen.at(-1)?.searchParams.has('after'), false);
    assert.equal(seen.at(-1)?.searchParams.has('limit'), false);
  }
});

test('recognition and Allocation are distinct explicit commands', () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const formed = sdk.formRecognition({ governedObjectId: 7n, roleKey: zeroHash,
    authorityId: zeroHash, stage: Stage.Verification, status: RecognitionStatus.Provisional,
    reasonHash: zeroHash, reasonURI: 'ava:test' });
  assert.equal(formed.to, addresses.kernel);
  const decoded = decodeFunctionData({ abi: kernelAbi, data: formed.data });
  assert.equal(decoded.functionName, 'formRecognisedState');
  assert.equal(decoded.args?.[0].stage, 2);
  const allocated = sdk.allocate(3n, { roleKey: zeroHash, authorityId: zeroHash });
  assert.equal(allocated.to, addresses.requests);
  assert.equal(decodeFunctionData({ abi: requestsAbi, data: allocated.data }).functionName, 'approve');
});

test('historical correction evidence uses explicit current admission without reopening ordinary registration', () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const input = { appId: zeroHash, workflowKey: zeroHash, packageId: 7n, roleKey: zeroHash,
    subjectId: zeroHash, commitment: zeroHash, evidenceTypeHash: zeroHash, disclosurePolicyId: 3n,
    authorityId: zeroHash, uri: 'ava:synthetic-historical-correction' };
  const reason = `0x${'a1'.repeat(32)}` as Hex;
  const correction = sdk.registerCorrectionEvidence(input, 9n, reason);
  assert.equal(correction.to, addresses.evidence);
  assert.deepEqual(decodeFunctionData({ abi: evidenceAbi, data: correction.data }),
    { functionName: 'registerCorrectionEvidence', args: [input, 9n, reason] });
  assert.equal(decodeFunctionData({ abi: evidenceAbi, data: sdk.registerEvidence(input).data }).functionName, 'registerEvidence');
});

test('compound Challengeable formation preserves both reasons in the exact typed Kernel call', () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const formationReason = `0x${'11'.repeat(32)}` as Hex;
  const challengeableReason = `0x${'22'.repeat(32)}` as Hex;
  const input: FormationInput = { governedObjectId: 7n, roleKey: zeroHash, authorityId: zeroHash,
    stage: Stage.Verification, status: RecognitionStatus.Provisional,
    reasonHash: formationReason, reasonURI: 'ava:formed' };
  const call = sdk.formChallengeable(input, challengeableReason, 'ava:challengeable');
  assert.equal(call.to, addresses.kernel);
  assert.deepEqual(decodeFunctionData({ abi: kernelAbi, data: call.data }), {
    functionName: 'formChallengeableState', args: [{ governedObjectId: 7n, roleKey: zeroHash,
      authorityId: zeroHash, stage: 2, status: 3, reasonHash: formationReason, reasonURI: 'ava:formed' },
    challengeableReason, 'ava:challengeable'],
  });
});

test('SDK rejects malformed deployment addresses rather than signing an ambiguous call', () => {
  assert.throws(() => new AvaSdk({ chainId: 31337, addresses: { ...addresses, kernel: '0x123' as Address } }));
});

test('split declaration and recovery preserve the caller supplied configuration, report and authority', () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const configurationHash = `0x${'71'.repeat(32)}` as Hex;
  const declaration = sdk.declareSplitMode(23n, configurationHash);
  assert.equal(declaration.to, addresses.requests);
  assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: declaration.data }),
    { functionName: 'declareSplitMode', args: [23n, configurationHash] });
  const input = { requestId: 23n, expectedReportId: 41n, decisionEvidenceId: 63n,
    roleKey: `0x${'72'.repeat(32)}` as Hex, authorityId: `0x${'73'.repeat(32)}` as Hex,
    reasonHash: `0x${'74'.repeat(32)}` as Hex };
  const recovery = sdk.authoriseRecovery(input);
  assert.equal(recovery.to, addresses.requests);
  assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: recovery.data }),
    { functionName: 'authoriseRecovery', args: [input] });
});

test('correction decisions retain caller supplied findings, evidence and disposition independently', () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const finding = { existingFindingId: 47n, supersedesFindingId: 0n,
    claimHash: zeroHash, useScopeHash: zeroHash, burdenHash: zeroHash };
  const challenge: ChallengeResolutionInput = { challengeId: 13n, roleKey: zeroHash,
    authorityId: `0x${'34'.repeat(32)}`, outcome: 2, correctionStatus: RecognitionStatus.Frozen,
    reasonHash: `0x${'56'.repeat(32)}`, reasonURI: 'ava:decision', finding };
  const resolved = sdk.resolveChallenge(challenge, 83n);
  assert.equal(resolved.to, addresses.challenges);
  const decoded = decodeFunctionData({ abi: challengesAbi, data: resolved.data });
  assert.equal(decoded.functionName, 'resolveChallengeWithEvidence');
  assert.deepEqual(decoded.args, [challenge, 83n]);

  const resolution: RequestResolutionInput = { challengeId: 29n, expectedPreviousResolutionId: 17n,
    roleKey: zeroHash, authorityId: challenge.authorityId, decisionEvidenceId: 91n,
    outcome: RequestResolutionOutcome.Withdrawn, reasonHash: challenge.reasonHash,
    remedy: { asset: addresses.evidence, recipient: addresses.identities, amount: 6n }, finding };
  const requestCall = sdk.resolveRequestChallenge(resolution);
  assert.equal(requestCall.to, addresses.requests);
  assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: requestCall.data }).args, [resolution]);
  const filed = sdk.fileRequestChallenge(7n, RequestChallengeTarget.Effect, 8n,
    { roleKey: zeroHash, authorityId: challenge.authorityId }, challenge.reasonHash);
  assert.deepEqual(decodeFunctionData({ abi: requestsAbi, data: filed.data }).args,
    [7n, 1, 8n, zeroHash, challenge.authorityId, challenge.reasonHash]);
});

test('independent review and its evidence use the registry selected by Core', async () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const registry = '0x0000000000000000000000000000000000000091' as Address;
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    assert.equal(method, 'eth_call');
    const [call] = params as [{ to: Address; data: Hex }];
    assert.equal(call.to.toLowerCase(), addresses.kernel);
    assert.equal(decodeFunctionData({ abi: kernelAbi, data: call.data }).functionName, 'CORRECTIONS');
    return encodeFunctionResult({ abi: kernelAbi, functionName: 'CORRECTIONS', result: registry });
  } }) });
  const input: CorrectionReviewInput = { caseId: 7n, expectedTargetVersion: 19n,
    outcome: CorrectionReviewOutcome.Residual, evidenceId: 8n, roleKey: zeroHash,
    authorityId: `0x${'11'.repeat(32)}`, reasonHash: `0x${'22'.repeat(32)}`,
    asset: addresses.authority, recipient: addresses.identities, amount: 9n,
    finding: { existingFindingId: 31n, supersedesFindingId: 0n,
      claimHash: zeroHash, useScopeHash: zeroHash, burdenHash: zeroHash } };
  const review = await sdk.reviewCorrection(client, input);
  assert.equal(review.to, registry);
  assert.deepEqual(decodeFunctionData({ abi: correctionsAbi, data: review.data }),
    { functionName: 'review', args: [input] });
  const evidence = { appId: zeroHash, workflowKey: zeroHash, packageId: 2n,
    roleKey: zeroHash, subjectId: input.authorityId, commitment: input.reasonHash,
    evidenceTypeHash: zeroHash, disclosurePolicyId: 3n, authorityId: input.authorityId,
    uri: 'ava:review-evidence' };
  const registered = await sdk.registerReviewEvidence(client, 7n, evidence);
  assert.equal(registered.to, addresses.evidence);
  assert.deepEqual(decodeFunctionData({ abi: evidenceAbi, data: registered.data }),
    { functionName: 'registerReviewEvidence', args: [evidence, registry, 7n] });
});

test('service correction pages preserve the app filter and opaque cursor', async (t) => {
  const seen: URL[] = [];
  t.mock.method(globalThis, 'fetch', async (input: URL | RequestInfo, init?: RequestInit) => {
    const url = new URL(String(input));
    seen.push(url);
    assert.equal(url.pathname, '/v1/corrections');
    assert.equal(url.searchParams.get('appId'), zeroHash);
    assert.equal(init?.method, 'GET');
    return Response.json({ asOf: { number: '42', hash: zeroHash }, items: [], nextCursor: 'next' });
  });
  const service = new AvaServiceClient('http://127.0.0.1:8080');
  const page = await service.corrections(zeroHash, { limit: 1, after: 'cursor&with?+bytes' });
  assert.deepEqual(page.items, []);
  assert.equal(page.nextCursor, 'next');
  assert.equal(seen[0].searchParams.get('limit'), '1');
  assert.equal(seen[0].searchParams.get('after'), 'cursor&with?+bytes');
  await service.corrections(zeroHash);
  assert.equal(seen[1].searchParams.has('limit'), false);
  assert.equal(seen[1].searchParams.has('after'), false);
});

test('deployment verification requires fixed helper code and reverse Core and request bindings', async () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const registry = '0x0000000000000000000000000000000000000091' as Address;
  const execution = '0x0000000000000000000000000000000000000092' as Address;
  let registryCode = '0x6000';
  let executionCode = '0x6000';
  let reverseKernel = addresses.kernel;
  let reverseRequests = addresses.requests;
  let pendingCodeReads = 0, peakCodeReads = 0;
  const codeFailures = new Map<Address, string | Error>();
  const defaultPoint = { blockHash: `0x${'ab'.repeat(32)}` as Hex, requireCanonical: true as const };
  let expectedPoint: unknown = defaultPoint;
  const bindings: Record<string, Address> = { APPLICATION_REGISTRY: addresses.applications,
    IDENTITY_REGISTRY: addresses.identities, AUTHORITY_MATRIX: addresses.authority,
    RULE_PACKAGE_REGISTRY: addresses.packages, EVIDENCE_REGISTRY: addresses.evidence,
    DISCLOSURE_REGISTRY: addresses.disclosure, CORRECTIONS: registry,
    GOVERNANCE_KERNEL: addresses.kernel, EXECUTION: execution };
  const client = createPublicClient({ cacheTime: 0, transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_chainId') return '0x7a69';
    if (method === 'eth_getBlockByNumber') return { number: '0x2a', hash: defaultPoint.blockHash, transactions: [] };
    if (method === 'eth_getCode') {
      assert.deepEqual((params as unknown[])[1], expectedPoint, 'code lookup must use verification snapshot');
      const [address] = params as [Address];
      pendingCodeReads++;
      peakCodeReads = Math.max(peakCodeReads, pendingCodeReads);
      await setImmediate();
      pendingCodeReads--;
      const failure = codeFailures.get(address.toLowerCase() as Address);
      if (failure instanceof Error) throw failure;
      if (failure !== undefined) return failure;
      return address.toLowerCase() === registry ? registryCode
        : address.toLowerCase() === execution ? executionCode : '0x6000';
    }
    assert.equal(method, 'eth_call');
    assert.deepEqual((params as unknown[])[1], expectedPoint, 'link lookup must use verification snapshot');
    const [call] = params as [{ to: Address; data: Hex }];
    const entry = Object.entries(addresses).find(([, address]) => address === call.to.toLowerCase());
    const abi: Abi = entry ? avaAbis[entry[0] as keyof typeof avaAbis]
      : call.to.toLowerCase() === execution ? executionAbi : correctionsAbi;
    const name = decodeFunctionData({ abi, data: call.data }).functionName;
    const result = call.to.toLowerCase() === registry ? reverseKernel
      : call.to.toLowerCase() === execution ? reverseRequests : bindings[name];
    assert.ok(result, `Unexpected binding: ${name}`);
    return encodeFunctionResult({ abi, functionName: name, result });
  } }, { retryCount: 0 }) });
  await sdk.verify(client);
  assert.equal(peakCodeReads, 9, 'independent configured code reads must progress together');
  codeFailures.set(addresses.applications, '0x');
  codeFailures.set(addresses.identities, new Error('Later address RPC unavailable'));
  await assert.rejects(sdk.verify(client), /No code at applications/);
  codeFailures.set(addresses.applications, new Error('First address RPC unavailable'));
  codeFailures.set(addresses.identities, '0x');
  await assert.rejects(sdk.verify(client), /First address RPC unavailable/);
  codeFailures.clear();
  await sdk.verify(client);
  registryCode = '0x';
  await assert.rejects(sdk.verify(client), /No code at corrections/);
  registryCode = '0x6000';
  reverseKernel = addresses.applications;
  await assert.rejects(sdk.verify(client), /configured Core/);
  reverseKernel = addresses.kernel;
  executionCode = '0x';
  await assert.rejects(sdk.verify(client), /No code at execution/);
  executionCode = '0x6000';
  reverseRequests = addresses.challenges;
  await assert.rejects(sdk.verify(client), /configured Core/);
  reverseRequests = addresses.requests;
  const point = { blockHash: `0x${'ac'.repeat(32)}` as Hex, requireCanonical: true as const };
  expectedPoint = point;
  await sdk.verify(client, point);
});

test('request execution heads and retained history use one canonical point while atomic requests stay explicit', async () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const helper = '0x0000000000000000000000000000000000000092' as Address;
  const blockHash = `0x${'81'.repeat(32)}` as Hex;
  const point = { blockHash, requireCanonical: true as const };
  const request = { id: 23n, input: { recognisedStateId: 8n, executor: addresses.authority,
    responseClass: zeroHash, parametersHash: blockHash, burdenHash: zeroHash, validUntil: 999n },
    recognisedStateTransitionId: 12n, supersedesRequestId: 0n, appId: zeroHash,
    workflowKey: zeroHash, packageId: 2n, subjectId: zeroHash, evidenceReceiptId: 6n,
    creator: addresses.identities, creatorRoleKey: zeroHash, creatorAuthorityId: zeroHash,
    allocator: addresses.packages, allocatorRoleKey: zeroHash, allocatorAuthorityId: zeroHash,
    triggeredBy: addresses.evidence, cancelled: false, consumed: true, completed: false,
    effectHash: zeroHash, createdAt: 1n, approvedAt: 2n, consumedAt: 3n, completedAt: 0n };
  const declaration = { executor: addresses.authority, codeHash: blockHash,
    configurationHash: blockHash, parametersHash: blockHash, latestAttemptId: 5n,
    liveAttemptId: 5n, latestReportId: 7n, latestRecoveryId: 9n, frozen: false, completed: false };
  const attempt = { id: 5n, requestId: 23n, previousAttemptId: 2n, recoveryId: 9n,
    triggeredBy: addresses.evidence, startedAt: 5n, endedAt: 0n, retired: false,
    completed: false, effectHash: zeroHash };
  const report = { id: 7n, requestId: 23n, attemptId: 2n, previousReportId: 3n,
    kind: 1, receiptHash: blockHash, reporter: addresses.authority, reportedAt: 4n };
  const recovery = { id: 9n, input: { requestId: 23n, expectedReportId: 7n,
    decisionEvidenceId: 63n, roleKey: blockHash, authorityId: blockHash, reasonHash: blockHash },
    attemptId: 2n, previousRecoveryId: 4n, actor: addresses.kernel, decisionHash: blockHash,
    authorisedAt: 5n, used: true };
  let split = false, started = false, snapshots = 0, failSnapshot = false;
  let head = blockHash, expectedPoint: unknown = point;
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    if (method === 'eth_getBlockByNumber') {
      snapshots++;
      if (failSnapshot) throw { code: -32603, message: 'SYNTHETIC_PRIVATE_SNAPSHOT' };
      return { hash: head, number: '0x2a', transactions: [] };
    }
    assert.equal(method, 'eth_call');
    const [call, reference] = params as [{ to: Address; data: Hex }, unknown];
    assert.deepEqual(reference, expectedPoint);
    const abi = call.to.toLowerCase() === addresses.requests ? requestsAbi : executionAbi;
    const { functionName: name, args } = decodeFunctionData({ abi, data: call.data });
    let result: unknown;
    if (call.to.toLowerCase() === addresses.requests) {
      if (name === 'getRequest') result = request;
      else if (name === 'lastResolutionIdByRequest') result = 0n;
      else if (name === 'EXECUTION') result = helper;
      else throw new Error(`Unexpected request query: ${name}`);
    } else {
      assert.equal(call.to.toLowerCase(), helper);
      if (name === 'isSplit') result = split;
      else if (name === 'getDeclaration') result = started ? declaration : { ...declaration,
        latestAttemptId: 0n, liveAttemptId: 0n, latestReportId: 0n, latestRecoveryId: 0n };
      else if (name === 'getAttempt') result = args?.[0] === 2n
        ? { ...attempt, id: 2n, previousAttemptId: 0n, recoveryId: 0n, endedAt: 4n, retired: true } : attempt;
      else if (name === 'getReport') result = report;
      else if (name === 'getRecovery') result = recovery;
      else throw new Error(`Unexpected execution query: ${name}`);
    }
    return encodeFunctionResult({ abi, functionName: name, result } as never);
  } }) });
  assert.equal((await sdk.request(client, 23n, point)).execution, null);
  split = true;
  const declared = (await sdk.request(client, 23n, point)).execution;
  assert.equal(declared?.helper, helper);
  assert.equal(declared?.latestAttempt, null);
  assert.equal(declared?.liveAttempt, null);
  assert.equal(declared?.latestReport, null);
  assert.equal(declared?.latestRecovery, null);
  started = true;
  const active = (await sdk.request(client, 23n, point)).execution;
  assert.deepEqual(active, { helper, declaration, latestAttempt: attempt, liveAttempt: attempt,
    latestReport: report, latestRecovery: recovery });
  const execution = await sdk.execution(client, point);
  assert.equal((await execution.read.getAttempt([2n], point)).retired, true);
  assert.equal((await execution.read.getReport([7n], point)).previousReportId, 3n);
  assert.equal((await execution.read.getRecovery([9n], point)).previousRecoveryId, 4n);
  assert.equal(snapshots, 0);
  await sdk.request(client, 23n);
  assert.equal(snapshots, 1);
  head = `0x${'82'.repeat(32)}` as Hex;
  expectedPoint = { blockHash: head, requireCanonical: true };
  await sdk.request(client, 23n);
  assert.equal(snapshots, 2);
  expectedPoint = '0x0';
  await sdk.request(client, 23n, 0n);
  assert.equal(snapshots, 2);
  failSnapshot = true;
  await assert.rejects(sdk.request(client, 23n), error => error instanceof Error
    && error.name === 'AvaReadError' && !String(error).includes('SYNTHETIC_PRIVATE'));
  failSnapshot = false;
  expectedPoint = { blockHash: head, requireCanonical: true };
  assert.equal((await sdk.request(client, 23n)).record.id, 23n);
});

test('correction queries preserve the finding namespace and one canonical read point', async () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const registry = '0x0000000000000000000000000000000000000091' as Address;
  const blockHash = `0x${'12'.repeat(32)}` as Hex;
  const record = { id: 7n, origin: addresses.challenges, acceptedAt: 1n, reviewId: 3n,
    input: { kind: 0, appId: zeroHash, workflowKey: zeroHash, packageId: 2n, targetPackageId: 2n,
      sourceStateId: 9n, originCaseId: 4n, targetId: 9n, originalTargetVersion: 5n,
      filingEvidenceId: 6n, challengerSubjectId: zeroHash, originalActor: addresses.identities,
      challenger: addresses.authority, affectedActor: addresses.packages } };
  const finding = { id: 11n, caseId: 7n, targetVersion: 5n, claimHash: blockHash,
    useScopeHash: blockHash, burdenHash: blockHash, evidenceId: 8n, verifierAuthorityId: zeroHash,
    verifier: addresses.evidence, formationAction: zeroHash, supersedesFindingId: 0n,
    independentReview: true, formedAt: 2n };
  const review = { id: 3n, input: { caseId: 7n, expectedTargetVersion: 5n,
    outcome: 3, evidenceId: 8n, roleKey: zeroHash, authorityId: zeroHash,
    reasonHash: blockHash, asset: addresses.applications, recipient: addresses.identities,
    amount: 0n, finding: { existingFindingId: 11n, supersedesFindingId: 0n,
      claimHash: zeroHash, useScopeHash: zeroHash, burdenHash: zeroHash } },
    actor: addresses.evidence, reviewedAt: 3n, reviewHash: blockHash };
  const challenge = { id: 4n, appId: zeroHash, workflowKey: zeroHash, packageId: 2n, targetPackageId: 2n,
    challengeGovernedObjectId: 10n, challengeRecognisedStateId: 12n, challengedRecognisedStateId: 9n,
    challengerSubjectId: zeroHash, evidenceReceiptId: 6n, disclosurePolicyId: 1n,
    targetStatusAtFiling: 5, targetTransitionIdAtFiling: 5n, targetTransitionIdAfterResolution: 13n,
    challengeStateTransitionIdAtFiling: 12n, challengeStateTransitionIdAfterResolution: 14n,
    status: 3, outcome: 1, lastTransitionId: 2n, filedBy: addresses.authority, filedAt: 1n,
    decisionEvidenceReceiptId: 8n };
  let neutral = false;
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    assert.equal(method, 'eth_call');
    const [call, point] = params as [{ to: Address; data: Hex }, unknown];
    assert.deepEqual(point, { blockHash, requireCanonical: true });
    if (call.to.toLowerCase() === addresses.kernel) {
      assert.equal(decodeFunctionData({ abi: kernelAbi, data: call.data }).functionName, 'CORRECTIONS');
      return encodeFunctionResult({ abi: kernelAbi, functionName: 'CORRECTIONS', result: registry });
    }
    if (call.to.toLowerCase() === addresses.challenges) {
      assert.deepEqual(decodeFunctionData({ abi: challengesAbi, data: call.data }),
        { functionName: 'getChallenge', args: [4n] });
      return encodeFunctionResult({ abi: challengesAbi, functionName: 'getChallenge', result: challenge });
    }
    assert.equal(call.to.toLowerCase(), registry);
    const name = decodeFunctionData({ abi: correctionsAbi, data: call.data }).functionName;
    if (name === 'getCase') return encodeFunctionResult({ abi: correctionsAbi, functionName: name,
      result: { ...record, reviewId: neutral ? 0n : 3n } });
    if (name === 'findingIdByCase') return encodeFunctionResult({ abi: correctionsAbi, functionName: name, result: neutral ? 0n : 11n });
    if (name === 'getFinding') return encodeFunctionResult({ abi: correctionsAbi, functionName: name, result: finding });
    if (name === 'supersededByFindingId') return encodeFunctionResult({ abi: correctionsAbi, functionName: name, result: 0n });
    if (name === 'getReview') return encodeFunctionResult({ abi: correctionsAbi, functionName: name, result: review });
    throw new Error(`Unexpected correction query: ${name}`);
  } }) });
  const result = await sdk.correctionCase(client, 7n, { blockHash, requireCanonical: true });
  assert.equal(result.record.input.sourceStateId, 9n);
  assert.equal(result.finding?.id, 11n);
  assert.equal(result.finding?.claimHash, blockHash);
  assert.equal(result.review?.input.outcome, 3);
  assert.equal(result.review?.input.finding.existingFindingId, 11n);
  assert.equal(result.originRecord?.family, 'source');
  assert.equal(result.originRecord?.record.outcome, 1);
  assert.equal(result.compensation, null);
  neutral = true;
  const unresolved = await sdk.correctionCase(client, 7n, { blockHash, requireCanonical: true });
  assert.equal(unresolved.finding, null);
  assert.equal(unresolved.review, null);
  assert.equal(unresolved.compensation, null);
});

test('a correction retains its own compensation after a newer non-compensatory request resolution', async () => {
  const sdk = new AvaSdk({ chainId: 31337, addresses });
  const registry = '0x0000000000000000000000000000000000000091' as Address;
  const blockHash = `0x${'91'.repeat(32)}` as Hex;
  const point = { blockHash, requireCanonical: true as const };
  const record = { id: 7n, origin: addresses.requests, acceptedAt: 1n, reviewId: 0n,
    input: { kind: 2, appId: zeroHash, workflowKey: zeroHash, packageId: 2n, targetPackageId: 2n,
      sourceStateId: 9n, originCaseId: 4n, targetId: 23n, originalTargetVersion: 5n,
      filingEvidenceId: 6n, challengerSubjectId: zeroHash, originalActor: addresses.identities,
      challenger: addresses.authority, affectedActor: addresses.packages } };
  const challenge = { id: 4n, requestId: 23n, target: 1, challengerSubjectId: zeroHash,
    evidenceId: 6n, decisionEvidenceId: 8n, outcome: 4, reasonHash: blockHash,
    filingReasonHash: blockHash, resolutionHash: blockHash, previousResolutionId: 2n,
    filedBy: addresses.authority, resolvedBy: addresses.kernel, resolverAuthorityId: blockHash,
    filedAt: 1n, resolvedAt: 2n, consumedAtFiling: true, completedAtFiling: true,
    effectHashAtFiling: blockHash, sourceTransitionIdAtFiling: 5n, sourceStatusAtFiling: 5,
    consumedAtResolution: true, completedAtResolution: true, effectHashAtResolution: blockHash,
    sourceTransitionIdAtResolution: 5n, sourceStatusAtResolution: 5 };
  const compensation = { terms: { asset: addresses.evidence, recipient: addresses.identities, amount: 19n },
    funded: true, paid: true, funder: addresses.authority, fundedAt: 3n, paidAt: 4n,
    paymentHash: blockHash };
  let latestResolutionId = 4n;
  const client = createPublicClient({ transport: custom({ request: async ({ method, params }) => {
    assert.equal(method, 'eth_call');
    const [call, reference] = params as [{ to: Address; data: Hex }, unknown];
    assert.deepEqual(reference, point);
    const abi = call.to.toLowerCase() === addresses.kernel ? kernelAbi
      : call.to.toLowerCase() === addresses.requests ? requestsAbi : correctionsAbi;
    const { functionName: name, args } = decodeFunctionData({ abi, data: call.data });
    let result: unknown;
    if (call.to.toLowerCase() === addresses.kernel) {
      assert.equal(name, 'CORRECTIONS'); result = registry;
    } else if (call.to.toLowerCase() === addresses.requests) {
      if (name === 'getCompensation') { assert.deepEqual(args, [4n]); result = compensation; }
      else if (name === 'lastResolutionIdByRequest') result = latestResolutionId;
      else if (name === 'getRequestChallenge') result = args?.[0] === 4n ? challenge
        : { ...challenge, id: 29n, outcome: 5, previousResolutionId: 4n };
      else throw new Error(`Unexpected request query: ${name}`);
    } else {
      assert.equal(call.to.toLowerCase(), registry);
      if (name === 'getCase') result = record;
      else if (name === 'findingIdByCase') result = 0n;
      else throw new Error(`Unexpected correction query: ${name}`);
    }
    return encodeFunctionResult({ abi, functionName: name, result } as never);
  } }) });
  assert.deepEqual(await sdk.compensation(client, 4n, point), compensation);
  assert.deepEqual((await sdk.correctionCase(client, 7n, point)).compensation, compensation);
  latestResolutionId = 29n;
  const requests = sdk.contracts(client).requests;
  const latest = await requests.read.lastResolutionIdByRequest([23n], point);
  assert.equal((await requests.read.getRequestChallenge([latest], point)).outcome, 5);
  const retained = await sdk.correctionCase(client, 7n, point);
  assert.equal(retained.originRecord?.record.id, 4n);
  assert.deepEqual(retained.compensation, compensation);
  record.origin = addresses.evidence;
  assert.equal((await sdk.correctionCase(client, 7n, point)).compensation, null);
});
