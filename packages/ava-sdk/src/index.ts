import {
  createPublicClient, encodeFunctionData,
  getContract, http, isAddress, keccak256, parseAbi, parseTransaction, recoverAddress, serializeTransaction, toHex, zeroAddress,
  type Abi, type Account, type Address, type Chain, type ContractFunctionArgs, type Hex,
  type GetContractReturnType, type PublicClient, type TransactionSerializable, type Transport, type WalletClient,
} from 'viem';
import { avaAbis, avaExtensionAbis, challengesAbi, correctionsAbi, evidenceAbi, executionAbi, kernelAbi, requestsAbi } from './abi.js';
import { AvaReceiptError, readCreatedId, readCreatedIdPair, type CreatedIdEvent } from './receipts.js';
import { AvaSigningError, signingStep, type SigningStage } from './signing-errors.js';
import { isSupportedTransactionType } from './transaction-envelope.js';
import { AvaReadError, readRejection } from './read-errors.js';
import { resolveReadPoint, withCanonicalSnapshot } from './read-point.js';
import { readActorContext, type ActorContextQuery } from './actor-context.js';
export type { ActorContext, ActorContextQuery } from './actor-context.js';
export { AvaReadError, readRejection } from './read-errors.js';
export { AvaSigningError, type SigningStage, type SigningErrorCode } from './signing-errors.js';
export * from './abi.js';
export * from './extensions.js';
export * from './installation.js';
export * from './receipts.js';
export { resolveReadPoint, withCanonicalSnapshot, type CanonicalSnapshot } from './read-point.js';
export * from './service-types.js';
export * from './service-client.js';
export * from './transaction-recovery.js';
export * from './signed-intent.js';
export * from './runtime-context.js';

export const Stage = { None: 0, Attribution: 1, Verification: 2, Allocation: 3 } as const;
export const RecognitionStatus = {
  None: 0, Draft: 1, Registered: 2, Provisional: 3, Challengeable: 4,
  Vested: 5, Frozen: 6, Downgraded: 7, Voided: 8, Restored: 9,
} as const;
export const RequestChallengeTarget = { Allocation: 0, Effect: 1 } as const;
export type RequestChallengeTarget = typeof RequestChallengeTarget[keyof typeof RequestChallengeTarget];
export const RequestResolutionOutcome = {
  None: 0, Rejected: 1, Withdrawn: 2, Residual: 3, Compensate: 4,
  EvidenceUnavailable: 5, AlreadyWithdrawn: 6, ReviewedResidual: 7,
} as const;
export const CorrectionReviewOutcome = {
  None: 0, Affirmed: 1, Withdrawn: 2, Residual: 3, Compensate: 4,
  EvidenceUnavailable: 5, TargetChanged: 6,
} as const;
export type CoreAddresses = Record<keyof typeof avaAbis, Address>;
export type CreatedIdSource = keyof CoreAddresses | 'corrections' | 'execution';
export type CoreContracts = { [K in keyof CoreAddresses]: GetContractReturnType<typeof avaAbis[K], PublicClient, Address> };
export interface AvaDeployment { chainId: number; addresses: CoreAddresses }
export interface AvaCall { to: Address; data: Hex; value?: bigint }
export interface Authority { roleKey: Hex; authorityId: Hex }
export type EvidenceInput = ContractFunctionArgs<typeof evidenceAbi, 'nonpayable', 'registerEvidence'>[0];
export type ObjectInput = ContractFunctionArgs<typeof kernelAbi, 'nonpayable', 'registerGovernedObject'>[0];
export type SourceOccurrence = ContractFunctionArgs<typeof kernelAbi, 'nonpayable', 'registerGovernedObjectWithDependencies'>[1][number];
export type FormationInput = ContractFunctionArgs<typeof kernelAbi, 'nonpayable', 'formRecognisedState'>[0];
export type TransitionInput = ContractFunctionArgs<typeof kernelAbi, 'nonpayable', 'transitionRecognisedState'>[0];
export type RequestInput = ContractFunctionArgs<typeof requestsAbi, 'nonpayable', 'createRequest'>[0];
export interface RequestCommitmentInput {
  appId: Hex;
  executor: Address;
  responseClass: Hex;
  parametersHash: Hex;
  burdenHash: Hex;
  validUntil: bigint;
}
export type RecoveryInput = ContractFunctionArgs<typeof requestsAbi, 'nonpayable', 'authoriseRecovery'>[0];
export type ChallengeFilingInput = ContractFunctionArgs<typeof challengesAbi, 'nonpayable', 'fileChallenge'>[0];
export type ChallengeResolutionInput = ContractFunctionArgs<typeof challengesAbi, 'nonpayable', 'resolveChallengeWithEvidence'>[0];
export type RequestResolutionInput = ContractFunctionArgs<typeof requestsAbi, 'nonpayable', 'resolveRequestChallenge'>[0];
export type CorrectionReviewInput = ContractFunctionArgs<typeof correctionsAbi, 'nonpayable', 'review'>[0];
export type CorrectionFindingInput = ContractFunctionArgs<typeof correctionsAbi, 'nonpayable', 'review'>[0]['finding'];
export type AvaWallet = WalletClient<Transport, Chain, Account>;
export type ReadPoint = bigint | { blockHash: Hex; requireCanonical: true };
const readAt = (point?: ReadPoint) => typeof point === 'bigint' || point === undefined
  ? { blockNumber: point } : point;
const recognitionDependenciesAbi = parseAbi([
  'function GOVERNANCE_KERNEL() view returns (address)',
  'function getDependencies(uint256 objectId) view returns ((uint256 recognisedStateId,uint256 transitionId)[])',
]);
const errorsFor = (applicationAbi: Abi): Abi => [...Object.values(avaAbis).flat(), ...Object.values(avaExtensionAbis).flat(),
  ...correctionsAbi, ...executionAbi, ...applicationAbi].filter(item => item.type === 'error');

export function jsonValue<T>(value: T): unknown {
  return JSON.parse(JSON.stringify(value, (_, item) => typeof item === 'bigint' ? item.toString() : item));
}

/** A caller supplies its signer; no service or SDK operation implicitly chooses a decision. */
export class AvaSdk {
  constructor(readonly deployment: AvaDeployment) {
    if (!Number.isSafeInteger(deployment.chainId) || deployment.chainId < 1) throw new Error('Invalid chain ID');
    for (const name of Object.keys(avaAbis) as (keyof CoreAddresses)[]) {
      const address = deployment.addresses[name];
      if (!address || !isAddress(address) || address === zeroAddress) throw new Error(`Invalid ${name} address`);
    }
  }

  contracts(client: PublicClient): CoreContracts {
    const a = this.deployment.addresses;
    return {
      applications: getContract({ address: a.applications, abi: avaAbis.applications, client }),
      identities: getContract({ address: a.identities, abi: avaAbis.identities, client }),
      authority: getContract({ address: a.authority, abi: avaAbis.authority, client }),
      packages: getContract({ address: a.packages, abi: avaAbis.packages, client }),
      disclosure: getContract({ address: a.disclosure, abi: avaAbis.disclosure, client }),
      evidence: getContract({ address: a.evidence, abi: evidenceAbi, client }),
      kernel: getContract({ address: a.kernel, abi: kernelAbi, client }),
      requests: getContract({ address: a.requests, abi: requestsAbi, client }),
      challenges: getContract({ address: a.challenges, abi: avaAbis.challenges, client }),
    };
  }

  actorContext(client: PublicClient, query: ActorContextQuery, point?: ReadPoint) {
    return readActorContext(this, client, query, point);
  }

  /** The correction registry is fixed by Core, never supplied by an application. */
  async corrections(client: PublicClient, point?: ReadPoint): Promise<GetContractReturnType<typeof correctionsAbi, PublicClient, Address>> {
    const address = await this.contracts(client).kernel.read.CORRECTIONS(readAt(point));
    return getContract({ address, abi: correctionsAbi, client });
  }

  /** The execution helper is fixed by the configured request allocation. */
  async execution(client: PublicClient, point?: ReadPoint): Promise<GetContractReturnType<typeof executionAbi, PublicClient, Address>> {
    const address = await this.contracts(client).requests.read.EXECUTION(readAt(point));
    return getContract({ address, abi: executionAbi, client });
  }
  /** Immutable source occurrences belong to Core's fixed helper, not an application-supplied address. */
  async objectDependencies(client: PublicClient, objectId: bigint, point?: ReadPoint): Promise<readonly SourceOccurrence[]> {
    if (point === undefined) return withCanonicalSnapshot(client, snapshot => this.objectDependencies(client, objectId, snapshot.point));
    point = await resolveReadPoint(client, point);
    const at = readAt(point), address = await this.contracts(client).kernel.read.DEPENDENCIES(at);
    const dependencies = getContract({ address, abi: recognitionDependenciesAbi, client });
    if ((await dependencies.read.GOVERNANCE_KERNEL(at)).toLowerCase() !== this.deployment.addresses.kernel.toLowerCase()) {
      throw new AvaReadError();
    }
    return dependencies.read.getDependencies([objectId], at);
  }

  async verify(client: PublicClient, point?: ReadPoint) {
    if (await client.getChainId() !== this.deployment.chainId) throw new Error('AVA chain mismatch');
    point = await resolveReadPoint(client, point);
    const at = readAt(point);
    const entries = Object.entries(this.deployment.addresses);
    const code = await Promise.allSettled(entries.map(([, address]) => client.getCode({ address, ...at })));
    // Read independent code concurrently, retaining configured-address error precedence.
    for (const [i, [name]] of entries.entries()) {
      const result = code[i];
      if (result.status === 'rejected') throw result.reason;
      if (!result.value || result.value === '0x') throw new Error(`No code at ${name}`);
    }
    const c = this.contracts(client), a = this.deployment.addresses;
    const corrections = await this.corrections(client, point);
    const correctionCode = await client.getCode({ address: corrections.address, ...at });
    if (!correctionCode || correctionCode === '0x') throw new Error('No code at corrections');
    const execution = await this.execution(client, point);
    const executionCode = await client.getCode({ address: execution.address, ...at });
    if (!executionCode || executionCode === '0x') throw new Error('No code at execution');
    const [identitiesApplications, authorityApplications, authorityIdentities,
      kernelAuthority, kernelIdentities, kernelPackages, kernelEvidence, kernelDisclosure,
      requestsKernel, challengesKernel, correctionsKernel, executionAllocation] = await Promise.all([
      c.identities.read.APPLICATION_REGISTRY(at),
      c.authority.read.APPLICATION_REGISTRY(at),
      c.authority.read.IDENTITY_REGISTRY(at),
      c.kernel.read.AUTHORITY_MATRIX(at),
      c.kernel.read.IDENTITY_REGISTRY(at),
      c.kernel.read.RULE_PACKAGE_REGISTRY(at),
      c.kernel.read.EVIDENCE_REGISTRY(at),
      c.kernel.read.DISCLOSURE_REGISTRY(at),
      c.requests.read.GOVERNANCE_KERNEL(at),
      c.challenges.read.GOVERNANCE_KERNEL(at),
      corrections.read.GOVERNANCE_KERNEL(at),
      execution.read.REQUEST_ALLOCATION(at),
    ]);
    const links = [
      [identitiesApplications, a.applications],
      [authorityApplications, a.applications],
      [authorityIdentities, a.identities],
      [kernelAuthority, a.authority],
      [kernelIdentities, a.identities],
      [kernelPackages, a.packages],
      [kernelEvidence, a.evidence],
      [kernelDisclosure, a.disclosure],
      [requestsKernel, a.kernel],
      [challengesKernel, a.kernel],
      [correctionsKernel, a.kernel],
      [executionAllocation, a.requests],
    ];
    if (links.some(([actual, expected]) => actual.toLowerCase() !== expected.toLowerCase())) {
      throw new Error('AVA deployment components do not share the configured Core');
    }
  }

  async createdId(client: PublicClient, hash: Hex, event: CreatedIdEvent & { source: CreatedIdSource }, confirmations = 1) {
    const { source, eventName, idField } = event, chainId = this.deployment.chainId;
    if (source !== 'corrections' && source !== 'execution') {
      if (!Object.hasOwn(avaAbis, source)) throw new AvaReceiptError('invalid_request');
      return readCreatedId(client, hash, { chainId,
        emitter: this.deployment.addresses[source], abi: avaAbis[source], eventName, idField, confirmations });
    }
    const contracts = this.contracts(client);
    const expectedHost = source === 'corrections' ? contracts.kernel.address : contracts.requests.address;
    const abi = source === 'corrections' ? correctionsAbi : executionAbi;
    let emitter: Address;
    try {
      if (await client.getChainId() !== chainId) throw new AvaReceiptError('chain_mismatch');
      const point = await resolveReadPoint(client), at = readAt(point);
      emitter = source === 'corrections' ? await contracts.kernel.read.CORRECTIONS(at)
        : await contracts.requests.read.EXECUTION(at);
      const code = await client.getCode({ address: emitter, ...at });
      if (!code || code === '0x') throw new AvaReceiptError('helper_mismatch');
      const host = source === 'corrections'
        ? await client.readContract({ address: emitter, abi: correctionsAbi, functionName: 'GOVERNANCE_KERNEL', ...at })
        : await client.readContract({ address: emitter, abi: executionAbi, functionName: 'REQUEST_ALLOCATION', ...at });
      if (host.toLowerCase() !== expectedHost.toLowerCase()) {
        throw new AvaReceiptError('helper_mismatch');
      }
    } catch (error) {
      if (error instanceof AvaReceiptError) throw error;
      throw new AvaReceiptError('rpc_unavailable');
    }
    return readCreatedId(client, hash, { chainId, emitter, abi, eventName, idField, confirmations });
  }

  registerEvidence(input: EvidenceInput): AvaCall {
    return { to: this.deployment.addresses.evidence, data: encodeFunctionData({ abi: evidenceAbi,
      functionName: 'registerEvidence', args: [input] }) };
  }
  registerEvidencePair(first: EvidenceInput, second: EvidenceInput): AvaCall {
    return { to: this.deployment.addresses.evidence, data: encodeFunctionData({ abi: evidenceAbi,
      functionName: 'registerEvidencePair', args: [first, second] }) };
  }
  createdEvidencePair(client: PublicClient, hash: Hex, { confirmations = 1 }: { confirmations?: number } = {}) {
    return readCreatedIdPair(client, hash, { chainId: this.deployment.chainId,
      emitter: this.deployment.addresses.evidence, abi: evidenceAbi, eventName: 'EvidenceRegistered',
      idField: 'evidenceId', confirmations });
  }
  /** Builds a correction-only evidence call; the registry checks admission under historical and current rules. */
  registerCorrectionEvidence(input: EvidenceInput, admissionPackageId: bigint, reasonHash: Hex): AvaCall {
    return { to: this.deployment.addresses.evidence, data: encodeFunctionData({ abi: evidenceAbi,
      functionName: 'registerCorrectionEvidence', args: [input, admissionPackageId, reasonHash] }) };
  }
  registerObject(input: ObjectInput): AvaCall {
    return { to: this.deployment.addresses.kernel, data: encodeFunctionData({ abi: kernelAbi,
      functionName: 'registerGovernedObject', args: [input] }) };
  }
  registerObjectWithDependencies(input: ObjectInput, dependencies: readonly SourceOccurrence[]): AvaCall {
    return { to: this.deployment.addresses.kernel, data: encodeFunctionData({ abi: kernelAbi,
      functionName: 'registerGovernedObjectWithDependencies', args: [input, dependencies] }) };
  }
  formRecognition(input: FormationInput): AvaCall {
    return { to: this.deployment.addresses.kernel, data: encodeFunctionData({ abi: kernelAbi,
      functionName: 'formRecognisedState', args: [input] }) };
  }
  formChallengeable(input: FormationInput, reasonHash: Hex, reasonURI: string): AvaCall {
    return { to: this.deployment.addresses.kernel, data: encodeFunctionData({ abi: kernelAbi,
      functionName: 'formChallengeableState', args: [input, reasonHash, reasonURI] }) };
  }
  transition(input: TransitionInput): AvaCall {
    return { to: this.deployment.addresses.kernel, data: encodeFunctionData({ abi: kernelAbi,
      functionName: 'transitionRecognisedState', args: [input] }) };
  }
  vest(input: TransitionInput): AvaCall {
    return { to: this.deployment.addresses.kernel, data: encodeFunctionData({ abi: kernelAbi,
      functionName: 'vestRecognisedState', args: [input] }) };
  }
  createRequest(input: RequestInput, authority: Authority): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'createRequest', args: [input, authority.roleKey, authority.authorityId] }) };
  }
  /** One signer explicitly supplies both authorities; execution remains a separate operation. */
  createAndApproveRequest(input: RequestInput, creation: Authority, allocation: Authority): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'createAndApproveRequest', args: [input, creation.roleKey, creation.authorityId,
        allocation.roleKey, allocation.authorityId] }) };
  }
  allocate(requestId: bigint, authority: Authority): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'approve', args: [requestId, authority.roleKey, authority.authorityId] }) };
  }
  declareSplitMode(requestId: bigint, configurationHash: Hex): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'declareSplitMode', args: [requestId, configurationHash] }) };
  }
  authoriseRecovery(input: RecoveryInput): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'authoriseRecovery', args: [input] }) };
  }

  fileChallenge(input: ChallengeFilingInput): AvaCall {
    return { to: this.deployment.addresses.challenges, data: encodeFunctionData({ abi: challengesAbi,
      functionName: 'fileChallenge', args: [input] }) };
  }
  screenChallenge(challengeId: bigint, authority: Authority): AvaCall {
    return { to: this.deployment.addresses.challenges, data: encodeFunctionData({ abi: challengesAbi,
      functionName: 'screenChallenge', args: [challengeId, authority.roleKey, authority.authorityId] }) };
  }
  /** Decision evidence is explicit; the legacy entry point's evidence inference is not used. */
  resolveChallenge(input: ChallengeResolutionInput, explicitDecisionEvidenceId: bigint): AvaCall {
    return { to: this.deployment.addresses.challenges, data: encodeFunctionData({ abi: challengesAbi,
      functionName: 'resolveChallengeWithEvidence', args: [input, explicitDecisionEvidenceId] }) };
  }
  closeChallenge(challengeId: bigint, authority: Authority, reasonHash: Hex, reasonURI: string): AvaCall {
    return { to: this.deployment.addresses.challenges, data: encodeFunctionData({ abi: challengesAbi,
      functionName: 'closeChallenge', args: [challengeId, authority.roleKey, authority.authorityId, reasonHash, reasonURI] }) };
  }
  recordRestorationAvailability(challengeId: bigint, authority: Authority, reasonHash: Hex, reasonURI: string): AvaCall {
    return { to: this.deployment.addresses.challenges, data: encodeFunctionData({ abi: challengesAbi,
      functionName: 'recordRestorationAvailability',
      args: [challengeId, authority.roleKey, authority.authorityId, reasonHash, reasonURI] }) };
  }
  applyRestoration(challengeId: bigint, authority: Authority, reasonHash: Hex, reasonURI: string): AvaCall {
    return { to: this.deployment.addresses.challenges, data: encodeFunctionData({ abi: challengesAbi,
      functionName: 'applyRestoration', args: [challengeId, authority.roleKey, authority.authorityId, reasonHash, reasonURI] }) };
  }
  fileRequestChallenge(requestId: bigint, target: RequestChallengeTarget, evidenceId: bigint,
      authority: Authority, reasonHash: Hex): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'fileRequestChallenge', args: [requestId, target, evidenceId,
        authority.roleKey, authority.authorityId, reasonHash] }) };
  }
  resolveRequestChallenge(input: RequestResolutionInput): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'resolveRequestChallenge', args: [input] }) };
  }
  fundRequestCompensation(challengeId: bigint): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'fundCompensation', args: [challengeId] }) };
  }
  claimRequestCompensation(challengeId: bigint): AvaCall {
    return { to: this.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'claimCompensation', args: [challengeId] }) };
  }
  async reviewCorrection(client: PublicClient, input: CorrectionReviewInput): Promise<AvaCall> {
    const registry = await this.corrections(client);
    return { to: registry.address, data: encodeFunctionData({ abi: correctionsAbi,
      functionName: 'review', args: [input] }) };
  }
  async registerReviewEvidence(client: PublicClient, caseId: bigint, input: EvidenceInput): Promise<AvaCall> {
    const registry = await this.corrections(client);
    return { to: this.deployment.addresses.evidence, data: encodeFunctionData({ abi: evidenceAbi,
      functionName: 'registerReviewEvidence', args: [input, registry.address, caseId] }) };
  }

  /** Reads preserve provenance; Vested alone says nothing about a request's current sufficiency. */
  async recognition(client: PublicClient, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.contracts(client), at = readAt(point);
    const state = await c.kernel.read.getRecognisedState([id], at);
    const [object, transition] = await Promise.all([
      c.kernel.read.getGovernedObject([state.governedObjectId], at),
      c.kernel.read.getRecognisedStateTransition([state.lastTransitionId], at),
    ]);
    return { state, object, transition };
  }

  /** Read the exact request commitment from the configured allocation contract. */
  requestCommitment(client: PublicClient, input: RequestCommitmentInput, point?: ReadPoint) {
    return this.contracts(client).requests.read.commitmentFor([
      input.appId, input.executor, input.responseClass, input.parametersHash, input.burdenHash, input.validUntil,
    ], readAt(point));
  }

  async request(client: PublicClient, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.contracts(client), at = readAt(point);
    const [record, resolutionId, helper] = await Promise.all([
      c.requests.read.getRequest([id], at), c.requests.read.lastResolutionIdByRequest([id], at),
      this.execution(client, point),
    ]);
    const [resolution, split] = await Promise.all([
      resolutionId === 0n ? null : c.requests.read.getRequestChallenge([resolutionId], at),
      helper.read.isSplit([id], at),
    ]);
    if (!split) return { record, resolutionId, resolution, execution: null };
    const declaration = await helper.read.getDeclaration([id], at);
    const latestAttemptRead = declaration.latestAttemptId === 0n ? null
      : helper.read.getAttempt([declaration.latestAttemptId], at);
    // A live attempt can also be the latest attempt. Read that ID only once at this point.
    const liveAttemptRead = declaration.liveAttemptId === declaration.latestAttemptId ? latestAttemptRead
      : declaration.liveAttemptId === 0n ? null : helper.read.getAttempt([declaration.liveAttemptId], at);
    const [latestAttempt, liveAttempt, latestReport, latestRecovery] = await Promise.all([
      latestAttemptRead,
      liveAttemptRead,
      declaration.latestReportId === 0n ? null : helper.read.getReport([declaration.latestReportId], at),
      declaration.latestRecoveryId === 0n ? null : helper.read.getRecovery([declaration.latestRecoveryId], at),
    ]);
    return { record, resolutionId, resolution, execution: { helper: helper.address, declaration,
      latestAttempt, liveAttempt, latestReport, latestRecovery } };
  }

  /** A compensation record belongs to one challenge, independently of later request resolutions. */
  async compensation(client: PublicClient, challengeId: bigint, point?: ReadPoint) {
    return this.contracts(client).requests.read.getCompensation([challengeId], readAt(point));
  }

  /** Findings have a separate identity from business states; a finding alone grants no execution authority. */
  async correctionCase(client: PublicClient, caseId: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const at = readAt(point);
    const registry = await this.corrections(client, point);
    const [record, findingId] = await Promise.all([
      registry.read.getCase([caseId], at), registry.read.findingIdByCase([caseId], at),
    ]);
    const c = this.contracts(client), a = this.deployment.addresses;
    // The retained origin record is the disposition, distinct from the accepted finding.
    // Other installed origins remain queryable by their case/review/finding and explicit domain ABI.
    const originRead = record.input.kind === 0 && record.origin.toLowerCase() === a.challenges.toLowerCase()
      ? c.challenges.read.getChallenge([record.input.originCaseId], at)
        .then(record => ({ family: 'source' as const, record }))
      : (record.input.kind === 1 || record.input.kind === 2) && record.origin.toLowerCase() === a.requests.toLowerCase()
        ? c.requests.read.getRequestChallenge([record.input.originCaseId], at)
          .then(record => ({ family: 'request' as const, record }))
        : null;
    const [review, originRecord, finding, supersededBy] = await Promise.all([
      record.reviewId === 0n ? null : registry.read.getReview([record.reviewId], at),
      originRead,
      findingId === 0n ? null : registry.read.getFinding([findingId], at),
      findingId === 0n ? 0n : registry.read.supersededByFindingId([findingId], at),
    ]);
    const compensation = originRecord?.family === 'request'
      && originRecord.record.outcome === RequestResolutionOutcome.Compensate
      ? await this.compensation(client, record.input.originCaseId, point) : null;
    return { registry: registry.address, record, finding, supersededBy, review, originRecord, compensation };
  }

  /** Reports whether the current validation call passed. A revert can reflect witness
   * ineligibility or a rule/module fault. An institutional conclusion needs its own basis. */
  async support(client: PublicClient, requestId: bigint, point?: ReadPoint) {
    try {
      await this.contracts(client).requests.read.validateCurrentSupport([requestId], readAt(point));
      return { usable: true as const };
    } catch (error) {
      const rejection = readRejection(error);
      if (!rejection) throw new AvaReadError();
      return { usable: false as const, ...rejection };
    }
  }

  /** Read-only simulation; the caller must verify the configured chain and resolve any snapshot. */
  async simulate(client: PublicClient, account: Address, call: AvaCall, applicationAbi: Abi = [], point?: ReadPoint): Promise<void> {
    const intent = { to: call.to, data: call.data, value: call.value ?? 0n };
    await signingStep('simulation', errorsFor(applicationAbi), async () => {
      if (point && typeof point !== 'bigint') {
        await client.request({ method: 'eth_call', params: [{ from: account, to: intent.to, data: intent.data,
          value: toHex(intent.value) }, point] });
      } else {
        await client.call({ account, ...intent, ...(point === undefined ? {} : { blockNumber: point }) });
      }
      if (call.to?.toLowerCase() !== intent.to.toLowerCase() || (call.data ?? '0x').toLowerCase() !== intent.data.toLowerCase()
          || (call.value ?? 0n) !== intent.value) throw new AvaSigningError('simulation', 'intent_mismatch');
    });
  }

  /** Simulate and sign exact bytes. Submission/reconciliation is a separate service operation. */
  async sign(client: PublicClient, wallet: AvaWallet, call: AvaCall, applicationAbi: Abi = [],
    options: { nonce?: number; maxFeePerGas?: bigint; maxPriorityFeePerGas?: bigint } = {}) {
    const chainId = this.deployment.chainId, actor = wallet.account.address;
    const intent = { to: call.to, data: call.data, value: call.value ?? 0n };
    const { nonce, maxFeePerGas, maxPriorityFeePerGas } = options;
    const sameCall = (candidate: { to?: Address | null; data?: Hex; value?: bigint }) =>
      candidate.to?.toLowerCase() === intent.to.toLowerCase()
      && (candidate.data ?? '0x').toLowerCase() === intent.data.toLowerCase()
      && (candidate.value ?? 0n) === intent.value;
    const unchanged = (stage: SigningStage) => {
      if (!sameCall(call) || wallet.account.address.toLowerCase() !== actor.toLowerCase()
          || wallet.chain.id !== chainId || this.deployment.chainId !== chainId || !Object.is(options.nonce, nonce)
          || !Object.is(options.maxFeePerGas, maxFeePerGas) || !Object.is(options.maxPriorityFeePerGas, maxPriorityFeePerGas)) {
        throw new AvaSigningError(stage, 'intent_mismatch');
      }
    };
    const errors = errorsFor(applicationAbi);
    await signingStep('chain', errors, async () => {
      if (await client.getChainId() !== chainId ||
          wallet.chain.id !== chainId || await wallet.getChainId() !== chainId) {
        throw new AvaSigningError('chain', 'chain_mismatch');
      }
      unchanged('chain');
    });
    await this.simulate(client, actor, call, applicationAbi);
    unchanged('simulation');
    const request = await signingStep('preparation', errors, async () => {
      if (nonce !== undefined && (!Number.isSafeInteger(nonce) || nonce < 0)) {
        throw new AvaSigningError('preparation', 'intent_mismatch');
      }
      if ((maxFeePerGas !== undefined && (typeof maxFeePerGas !== 'bigint' || maxFeePerGas < 0n))
          || (maxPriorityFeePerGas !== undefined && (typeof maxPriorityFeePerGas !== 'bigint' || maxPriorityFeePerGas < 0n))
          || (maxFeePerGas !== undefined && maxPriorityFeePerGas !== undefined && maxPriorityFeePerGas > maxFeePerGas)) {
        throw new AvaSigningError('preparation', 'intent_mismatch');
      }
      const prepared = await wallet.prepareTransactionRequest({ account: wallet.account, chain: wallet.chain, ...intent,
        ...(nonce === undefined ? {} : { nonce }),
        ...(maxFeePerGas === undefined ? {} : { maxFeePerGas }),
        ...(maxPriorityFeePerGas === undefined ? {} : { maxPriorityFeePerGas }) });
      unchanged('preparation');
      if (prepared.chainId !== chainId || !sameCall(prepared) || (nonce !== undefined && prepared.nonce !== nonce)
          || (maxFeePerGas !== undefined && prepared.maxFeePerGas !== maxFeePerGas)
          || (maxPriorityFeePerGas !== undefined && prepared.maxPriorityFeePerGas !== maxPriorityFeePerGas)) {
        throw new AvaSigningError('preparation', 'intent_mismatch');
      }
      const payload = serializeTransaction(prepared as TransactionSerializable);
      const encoded = parseTransaction(payload);
      if (!isSupportedTransactionType(encoded.type) || (encoded.type === 'eip1559'
          && (encoded.maxPriorityFeePerGas ?? 0n) > (encoded.maxFeePerGas ?? 0n))) {
        throw new AvaSigningError('preparation', 'intent_mismatch');
      }
      if (maxFeePerGas !== undefined || maxPriorityFeePerGas !== undefined) {
        if (encoded.type !== 'eip1559'
            || (maxFeePerGas !== undefined && (encoded.maxFeePerGas ?? 0n) !== maxFeePerGas)
            || (maxPriorityFeePerGas !== undefined && (encoded.maxPriorityFeePerGas ?? 0n) !== maxPriorityFeePerGas)) {
          throw new AvaSigningError('preparation', 'intent_mismatch');
        }
      }
      return { transaction: prepared, payload };
    });
    const serializedTransaction = await signingStep('signing', errors, async () => {
      const signed = await wallet.signTransaction(request.transaction);
      unchanged('signing');
      try {
        const transaction = parseTransaction(signed);
        const { r: _r, s: _s, v: _v, yParity: _parity, ...unsigned } = transaction;
        if (!transaction.r || !transaction.s
            || BigInt(transaction.s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0n
            || serializeTransaction(transaction, { r: transaction.r, s: transaction.s,
              v: transaction.v!, yParity: transaction.yParity! }).toLowerCase() !== signed.toLowerCase()) {
          throw new Error('noncanonical signature');
        }
        const unsignedPayload = serializeTransaction(unsigned as TransactionSerializable);
        const sender = await recoverAddress({ hash: keccak256(unsignedPayload), signature: { r: transaction.r, s: transaction.s,
          v: transaction.v!, yParity: transaction.yParity! } });
        if (transaction.chainId !== chainId || !sameCall(transaction) || sender.toLowerCase() !== actor.toLowerCase()
            || unsignedPayload !== request.payload) {
          throw new Error('intent mismatch');
        }
      } catch { throw new AvaSigningError('signing', 'intent_mismatch'); }
      unchanged('signing');
      return signed;
    });
    return { serializedTransaction, hash: keccak256(serializedTransaction) };
  }
}

/** Current runnable transport deliberately excludes remote RPCs and every deployed Base chain. */
export function localClient(rpcUrl: string): PublicClient {
  const url = new URL(rpcUrl);
  if (url.protocol !== 'http:' || !['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname)
      || url.username || url.password) throw new Error('Local HTTP RPC required');
  return createPublicClient({ cacheTime: 0, transport: http(rpcUrl, {
    retryCount: 0, timeout: 10_000, fetchOptions: { redirect: 'error' },
  }) });
}

