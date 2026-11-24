import { AbiDecodingDataSizeTooSmallError, BaseError, ContractFunctionZeroDataError, InvalidBytesBooleanError,
  encodeFunctionData, getContract, isAddress, zeroAddress, zeroHash,
  type Address, type ContractFunctionArgs, type GetContractReturnType, type Hex, type PublicClient } from 'viem';
import { requestsAbi, correctionsAbi, decisionsAbi, procedureAbi, ruleGovernanceAbi, privacyAbi,
  governedDisclosureAbi, evidenceBindingsAbi } from './abi.js';
import { avaExtensionAbis } from './abi.js';
import { readCreatedId, type CreatedIdEvent } from './receipts.js';
import { resolveReadPoint } from './read-point.js';
import { AvaReadError, readRejection } from './read-errors.js';
import type { AvaSdk, AvaCall, Authority, ReadPoint, RequestInput } from './index.js';
import { verifyInstallation, type InstallationExpectations } from './installation.js';
export type { InstallationExpectations, InstallationFinding, InstallationReadiness } from './installation.js';

export interface AvaExtensionAddresses {
  decisions?: Address;
  procedure?: Address;
  ruleGovernance?: Address;
  privacy?: Address;
  governedDisclosure?: Address;
  evidenceBindings?: Address;
}
export type DecisionRequestInput = ContractFunctionArgs<typeof decisionsAbi, 'nonpayable', 'openRequest'>[0];
export type DecisionSupportPool = ContractFunctionArgs<typeof decisionsAbi, 'nonpayable', 'openRequest'>[1];
export type ProcedureResolutionInput = ContractFunctionArgs<typeof procedureAbi, 'nonpayable', 'resolve'>[0];
export type RuleProposalInput = ContractFunctionArgs<typeof ruleGovernanceAbi, 'nonpayable', 'registerProposal'>[0];
export type RulePackageInput = ContractFunctionArgs<typeof ruleGovernanceAbi, 'nonpayable', 'registerProposal'>[1];
export type RuleModuleBindings = ContractFunctionArgs<typeof ruleGovernanceAbi, 'nonpayable', 'registerProposal'>[2];
export type PrivacyRules = ContractFunctionArgs<typeof privacyAbi, 'nonpayable', 'publishPolicy'>[3];
export type PrivacyResourcePair = ContractFunctionArgs<typeof privacyAbi, 'nonpayable', 'registerResourcePair'>[1];
export type PrivacyEvidenceBindingPair = ContractFunctionArgs<typeof evidenceBindingsAbi, 'nonpayable', 'bindEvidencePair'>[1];
export type PrivacyGrantInput = ContractFunctionArgs<typeof privacyAbi, 'nonpayable', 'grantAccessMany'>[0][number];
export type DisclosureParameters = ContractFunctionArgs<typeof governedDisclosureAbi, 'nonpayable', 'executeDisclosure'>[1];
export const DecisionKind = { Substantive: 0, Withhold: 1, Pause: 2, SeekEvidence: 3,
  Escalate: 4, Resume: 5, Close: 6 } as const;
export const ProcedureOutcome = { None: 0, Affirmed: 1, Withdrawn: 2, Replaced: 3,
  EvidenceUnavailable: 4, TargetChanged: 5, ReviewedResidual: 6 } as const;
const readAt = (point?: ReadPoint) => typeof point === 'bigint' || point === undefined
  ? { blockNumber: point } : point;

/** Optional, explicit adapters. Calls use AvaSdk.sign with the caller's existing signer. */
export class AvaExtensions {
  constructor(readonly sdk: AvaSdk, readonly addresses: AvaExtensionAddresses) {
    for (const [name, address] of Object.entries(addresses)) {
      if (address !== undefined && (!isAddress(address) || address === zeroAddress)) {
        throw new Error(`Invalid ${name} address`);
      }
    }
  }

  private address(name: keyof AvaExtensionAddresses): Address {
    const address = this.addresses[name];
    if (!address) throw new Error(`Optional ${name} address is not configured`);
    return address;
  }

  decisions(client: PublicClient): GetContractReturnType<typeof decisionsAbi, PublicClient, Address> {
    return getContract({ address: this.address('decisions'), abi: decisionsAbi, client });
  }
  createdId(client: PublicClient, hash: Hex, event: CreatedIdEvent & { source: keyof AvaExtensionAddresses }, confirmations = 1) {
    return readCreatedId(client, hash, { chainId: this.sdk.deployment.chainId,
      emitter: this.address(event.source), abi: avaExtensionAbis[event.source],
      eventName: event.eventName, idField: event.idField, confirmations });
  }
  procedure(client: PublicClient): GetContractReturnType<typeof procedureAbi, PublicClient, Address> {
    return getContract({ address: this.address('procedure'), abi: procedureAbi, client });
  }
  ruleGovernance(client: PublicClient): GetContractReturnType<typeof ruleGovernanceAbi, PublicClient, Address> {
    return getContract({ address: this.address('ruleGovernance'), abi: ruleGovernanceAbi, client });
  }
  privacy(client: PublicClient): GetContractReturnType<typeof privacyAbi, PublicClient, Address> {
    return getContract({ address: this.address('privacy'), abi: privacyAbi, client });
  }
  governedDisclosure(client: PublicClient): GetContractReturnType<typeof governedDisclosureAbi, PublicClient, Address> {
    return getContract({ address: this.address('governedDisclosure'), abi: governedDisclosureAbi, client });
  }
  evidenceBindings(client: PublicClient): GetContractReturnType<typeof evidenceBindingsAbi, PublicClient, Address> {
    return getContract({ address: this.address('evidenceBindings'), abi: evidenceBindingsAbi, client });
  }

  /** Checks concrete links and code availability; package/readiness checks pin installed modules separately. */
  async verify(client: PublicClient, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    await this.sdk.verify(client, point);
    const a = this.sdk.deployment.addresses, at = readAt(point);
    // Reuse a successful contract check only within this call at a fixed block hash.
    const fixedBlock = typeof point !== 'bigint';
    let verifiedDecision: string | undefined;
    let verifiedPrivacy: string | undefined;
    let verifiedBindings: { address: string; privacy: Address } | undefined;
    const same = (actual: string, expected: string, label: string) => {
      if (actual.toLowerCase() !== expected.toLowerCase()) throw new Error(`AVA ${label} mismatch`);
    };
    const code = async (address: Address, label: string) => {
      if (!await client.getCode({ address, ...at })) throw new Error(`No code at ${label}`);
    };
    const decision = async (address: Address) => {
      const identity = address.toLowerCase();
      if (fixedBlock && verifiedDecision === identity) return;
      await code(address, 'decisions');
      const c = getContract({ address, abi: decisionsAbi, client });
      same(await c.read.GOVERNANCE_KERNEL(at), a.kernel, 'decisions GOVERNANCE_KERNEL');
      same(await c.read.REQUEST_ALLOCATION(at), a.requests, 'decisions REQUEST_ALLOCATION');
      // A zero authority is always refused; probe capability without granting or using authority.
      let supported = false;
      try {
        supported = await this.sdk.contracts(client).authority.read.isAuthorisedSubject([
          zeroAddress, zeroHash, zeroHash, zeroHash, zeroHash], at) === false;
      } catch (error) {
        const malformed = error instanceof BaseError && error.walk(cause =>
          cause instanceof ContractFunctionZeroDataError || cause instanceof AbiDecodingDataSizeTooSmallError
          || cause instanceof InvalidBytesBooleanError);
        if (!readRejection(error) && !malformed) throw error;
      }
      if (!supported) throw new Error('AVA decisions authority capability mismatch');
      if (fixedBlock) verifiedDecision = identity;
    };
    const privacy = async (address: Address) => {
      const identity = address.toLowerCase();
      if (fixedBlock && verifiedPrivacy === identity) return;
      await code(address, 'privacy');
      const c = getContract({ address, abi: privacyAbi, client });
      same(await c.read.AUTHORITY_MATRIX(at), a.authority, 'privacy AUTHORITY_MATRIX');
      if (fixedBlock) verifiedPrivacy = identity;
    };
    const bindings = async (address: Address) => {
      const identity = address.toLowerCase();
      let linkedPrivacy = verifiedBindings?.address === identity ? verifiedBindings.privacy : undefined;
      if (linkedPrivacy === undefined) {
        await code(address, 'evidenceBindings');
        const c = getContract({ address, abi: evidenceBindingsAbi, client });
        same(await c.read.EVIDENCE_REGISTRY(at), a.evidence, 'evidenceBindings EVIDENCE_REGISTRY');
        linkedPrivacy = await c.read.PRIVACY_REGISTRY(at);
      }
      if (this.addresses.privacy) same(linkedPrivacy, this.addresses.privacy, 'evidenceBindings PRIVACY_REGISTRY');
      await privacy(linkedPrivacy);
      if (fixedBlock) verifiedBindings = { address: identity, privacy: linkedPrivacy };
      return linkedPrivacy;
    };
    if (this.addresses.decisions) await decision(this.addresses.decisions);
    if (this.addresses.procedure) {
      const c = this.procedure(client);
      await code(c.address, 'procedure');
      same(await c.read.GOVERNANCE_KERNEL(at), a.kernel, 'procedure GOVERNANCE_KERNEL');
      const linkedDecision = await c.read.DECISION_REGISTRY(at);
      if (this.addresses.decisions) same(linkedDecision, this.addresses.decisions, 'procedure DECISION_REGISTRY');
      await decision(linkedDecision);
      const policy = await c.read.REVIEW_POLICY(at);
      await code(policy, 'procedure REVIEW_POLICY');
      const identity = await client.readContract({ address: policy, abi: decisionsAbi,
        functionName: 'moduleIdentityHash', ...at });
      same(identity, await c.read.REVIEW_POLICY_IDENTITY(at), 'procedure REVIEW_POLICY_IDENTITY');
    }
    if (this.addresses.ruleGovernance) {
      const c = this.ruleGovernance(client);
      await code(c.address, 'ruleGovernance');
      same(await c.read.GOVERNANCE_KERNEL(at), a.kernel, 'ruleGovernance GOVERNANCE_KERNEL');
      same(await c.read.RULE_PACKAGE_REGISTRY(at), a.packages, 'ruleGovernance RULE_PACKAGE_REGISTRY');
    }
    if (this.addresses.privacy) await privacy(this.addresses.privacy);
    if (this.addresses.evidenceBindings) await bindings(this.addresses.evidenceBindings);
    if (this.addresses.governedDisclosure) {
      const c = this.governedDisclosure(client);
      await code(c.address, 'governedDisclosure');
      same(await c.read.REQUEST_ALLOCATION(at), a.requests, 'governedDisclosure REQUEST_ALLOCATION');
      const linkedPrivacy = await c.read.PRIVACY_REGISTRY(at);
      const linkedBindings = await c.read.EVIDENCE_BINDINGS(at);
      if (this.addresses.privacy) same(linkedPrivacy, this.addresses.privacy, 'governedDisclosure PRIVACY_REGISTRY');
      if (this.addresses.evidenceBindings) same(linkedBindings, this.addresses.evidenceBindings, 'governedDisclosure EVIDENCE_BINDINGS');
      same(await bindings(linkedBindings), linkedPrivacy, 'governedDisclosure bindings PRIVACY_REGISTRY');
    }
  }

  verifyInstallation(client: PublicClient, expected: InstallationExpectations, point?: ReadPoint) {
    return verifyInstallation(this, client, expected, point);
  }

  openDecisionRequest(input: DecisionRequestInput, declaredPool: DecisionSupportPool, authority: Authority): AvaCall {
    return { to: this.address('decisions'), data: encodeFunctionData({ abi: decisionsAbi,
      functionName: 'openRequest', args: [input, declaredPool, authority.roleKey, authority.authorityId] }) };
  }

  createSupportedRequest(input: RequestInput, witness: DecisionSupportPool, authority: Authority): AvaCall {
    return { to: this.sdk.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'createSupportedRequest', args: [input, witness, authority.roleKey, authority.authorityId] }) };
  }
  createSupportedAndApproveRequest(input: RequestInput, witness: DecisionSupportPool,
      creation: Authority, allocation: Authority): AvaCall {
    return { to: this.sdk.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'createSupportedAndApproveRequest', args: [input, witness, {
        creatorRole: creation.roleKey, creatorAuthority: creation.authorityId,
        allocatorRole: allocation.roleKey, allocatorAuthority: allocation.authorityId,
      }] }) };
  }
  createDecisionRequest(decisionRequestId: bigint, input: RequestInput,
      witness: DecisionSupportPool, authority: Authority): AvaCall {
    return { to: this.sdk.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'createDecisionRequest', args: [decisionRequestId, input, witness,
        authority.roleKey, authority.authorityId] }) };
  }
  createDecisionRequestForPackage(decisionRequestId: bigint, receivingPackageId: bigint,
      input: RequestInput, witness: DecisionSupportPool, authority: Authority): AvaCall {
    return { to: this.sdk.deployment.addresses.requests, data: encodeFunctionData({ abi: requestsAbi,
      functionName: 'createDecisionRequestForPackage', args: [decisionRequestId, receivingPackageId,
        input, witness, authority.roleKey, authority.authorityId] }) };
  }

  updateDecisionSupport(requestId: bigint, declaredPool: DecisionSupportPool,
      expectedRevision: bigint, authority: Authority): AvaCall {
    return { to: this.address('decisions'), data: encodeFunctionData({ abi: decisionsAbi,
      functionName: 'updateSupport', args: [requestId, declaredPool, expectedRevision,
        authority.roleKey, authority.authorityId] }) };
  }
  chooseDecision(requestId: bigint, optionKey: Hex, executionRequestId: bigint,
      expectedPreviousDecisionId: bigint, authority: Authority, reasonHash: Hex): AvaCall {
    return { to: this.address('decisions'), data: encodeFunctionData({ abi: decisionsAbi,
      functionName: 'choose', args: [requestId, optionKey, executionRequestId,
        expectedPreviousDecisionId, authority.roleKey, authority.authorityId, reasonHash] }) };
  }
  fileProcedureChallenge(decisionId: bigint, evidenceId: bigint, authority: Authority, reasonHash: Hex): AvaCall {
    return { to: this.address('procedure'), data: encodeFunctionData({ abi: procedureAbi,
      functionName: 'file', args: [decisionId, evidenceId, authority.roleKey, authority.authorityId, reasonHash] }) };
  }
  resolveProcedureChallenge(input: ProcedureResolutionInput): AvaCall {
    return { to: this.address('procedure'), data: encodeFunctionData({ abi: procedureAbi,
      functionName: 'resolve', args: [input] }) };
  }
  async setRequestOriginEnabled(client: PublicClient, appId: Hex, origin: Address,
      enabled: boolean, point?: ReadPoint): Promise<AvaCall> {
    const registry = await this.sdk.corrections(client, point);
    return { to: registry.address, data: encodeFunctionData({ abi: correctionsAbi,
      functionName: 'setRequestOriginEnabled', args: [appId, origin, enabled] }) };
  }
  registerRuleProposal(input: RuleProposalInput, proposed: RulePackageInput,
      bindings: RuleModuleBindings, authority: Authority): AvaCall {
    return { to: this.address('ruleGovernance'), data: encodeFunctionData({ abi: ruleGovernanceAbi,
      functionName: 'registerProposal', args: [input, proposed, bindings, authority.roleKey, authority.authorityId] }) };
  }
  executeRuleProposal(proposalId: bigint, proposed: RulePackageInput,
      bindings: RuleModuleBindings, authority: Authority): AvaCall {
    return { to: this.address('ruleGovernance'), data: encodeFunctionData({ abi: ruleGovernanceAbi,
      functionName: 'executeProposal', args: [proposalId, proposed, bindings, authority.roleKey, authority.authorityId] }) };
  }
  publishPrivacyPolicy(appId: Hex, authority: Authority, rules: PrivacyRules): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'publishPolicy', args: [appId, authority.roleKey, authority.authorityId, rules] }) };
  }
  openPrivacyCase(caseId: Hex, appId: Hex, policyId: bigint, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'openCase', args: [caseId, appId, policyId, authority.roleKey, authority.authorityId] }) };
  }
  advancePrivacyPhase(caseId: Hex, phase: number, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'advancePhase', args: [caseId, phase, authority.roleKey, authority.authorityId] }) };
  }
  setPrivacyMember(caseId: Hex, persona: Hex, readerRole: Hex, expiresAt: bigint,
      enabled: boolean, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'setMember', args: [caseId, persona, readerRole, expiresAt, enabled,
        authority.roleKey, authority.authorityId] }) };
  }
  registerPrivateResource(resourceId: Hex, caseId: Hex, materialClass: Hex,
      ciphertextHash: Hex, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'registerResource', args: [resourceId, caseId, materialClass, ciphertextHash,
        authority.roleKey, authority.authorityId] }) };
  }
  registerPrivateResourcePair(caseId: Hex, registrations: PrivacyResourcePair, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'registerResourcePair', args: [caseId, registrations, authority.roleKey, authority.authorityId] }) };
  }
  grantPrivacyAccess(resourceId: Hex, persona: Hex, readerRole: Hex, purpose: Hex,
      expiresAt: bigint, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'grantAccess', args: [resourceId, persona, readerRole, purpose, expiresAt,
        authority.roleKey, authority.authorityId] }) };
  }
  grantPrivacyAccessMany(grants: readonly PrivacyGrantInput[], authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'grantAccessMany', args: [grants, authority.roleKey, authority.authorityId] }) };
  }
  revokePrivacyAccess(resourceId: Hex, persona: Hex, readerRole: Hex, purpose: Hex, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'revokeAccess', args: [resourceId, persona, readerRole, purpose, authority.roleKey, authority.authorityId] }) };
  }
  deactivatePrivacyPolicy(policyId: bigint, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'deactivatePolicy', args: [policyId, authority.roleKey, authority.authorityId] }) };
  }
  deactivatePrivateResource(resourceId: Hex, authority: Authority): AvaCall {
    return { to: this.address('privacy'), data: encodeFunctionData({ abi: privacyAbi,
      functionName: 'deactivateResource', args: [resourceId, authority.roleKey, authority.authorityId] }) };
  }
  bindPrivateEvidence(evidenceId: bigint, resourceId: Hex, authority: Authority): AvaCall {
    return { to: this.address('evidenceBindings'), data: encodeFunctionData({ abi: evidenceBindingsAbi,
      functionName: 'bindEvidence', args: [evidenceId, resourceId, authority.roleKey, authority.authorityId] }) };
  }
  bindPrivateEvidencePair(caseId: Hex, input: PrivacyEvidenceBindingPair, authority: Authority): AvaCall {
    return { to: this.address('evidenceBindings'), data: encodeFunctionData({ abi: evidenceBindingsAbi,
      functionName: 'bindEvidencePair', args: [caseId, input, authority.roleKey, authority.authorityId] }) };
  }
  executeDisclosure(requestId: bigint, parameters: DisclosureParameters): AvaCall {
    return { to: this.address('governedDisclosure'), data: encodeFunctionData({ abi: governedDisclosureAbi,
      functionName: 'executeDisclosure', args: [requestId, parameters] }) };
  }

  async decisionRequest(client: PublicClient, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.decisions(client), at = readAt(point);
    const record = await c.read.getRequest([id], at);
    const latestDecisionRead = record.lastDecisionId === 0n ? null
      : this.decision(client, record.lastDecisionId, point);
    const supportRead = record.supportRevision === 0n ? null : c.read.getSupportRevision([id, record.supportRevision], at);
    // Reuse the latest decision read when it is also the retained Allocation decision.
    const allocationDecisionRead = record.allocationDecisionId === record.lastDecisionId ? latestDecisionRead
      : record.allocationDecisionId === 0n ? null : this.decision(client, record.allocationDecisionId, point);
    const [support, latestDecision, allocationDecision] = await Promise.all([
      supportRead, latestDecisionRead, allocationDecisionRead,
    ]);
    return { record, support, latestDecision, allocationDecision };
  }
  async decisionSupport(client: PublicClient, requestId: bigint, revision: bigint, point?: ReadPoint) {
    return this.decisions(client).read.getSupportRevision([requestId, revision], readAt(point));
  }
  async eligibleDecisionWitnesses(client: PublicClient, requestId: bigint, point?: ReadPoint) {
    return this.decisions(client).read.getEligibleWitnesses([requestId], readAt(point));
  }
  async admissibleDecisions(client: PublicClient, requestId: bigint, actor: Address,
      authority: Authority, point?: ReadPoint) {
    return this.decisions(client).read.getAdmissibleDecisions([
      requestId, actor, authority.roleKey, authority.authorityId], readAt(point));
  }
  /** A procedural decision is a retained Allocation; execution remains a separate Core record. */
  async decision(client: PublicClient, id: bigint, point?: ReadPoint) {
    return this.readDecision(client, this.address('decisions'), id, point);
  }
  private async readDecision(client: PublicClient, address: Address, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = getContract({ address, abi: decisionsAbi, client }), at = readAt(point);
    const [record, procedureDispositionId, procedureReviewId, constitutionalReviewId] = await Promise.all([
      c.read.getDecision([id], at), c.read.procedureDisposition([id], at),
      c.read.procedureReviewIdByDecision([id], at), c.read.constitutionalReviewIdByDecision([id], at),
    ]);
    const execution = record.executionRequestId === 0n ? null
      : await this.sdk.request(client, record.executionRequestId, point);
    return { record, procedureDispositionId, procedureReviewId, constitutionalReviewId, execution };
  }
  async procedureChallenge(client: PublicClient, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.procedure(client), at = readAt(point);
    const [record, caseId, registry] = await Promise.all([
      c.read.getChallenge([id], at), c.read.correctionReviewCaseIdByChallenge([id], at),
      c.read.DECISION_REGISTRY(at),
    ]);
    const [resolution, decision, correction] = await Promise.all([
      record.resolutionId === 0n ? null : c.read.getResolution([record.resolutionId], at),
      this.readDecision(client, registry, record.decisionId, point),
      caseId === 0n ? null : this.sdk.correctionCase(client, caseId, point),
    ]);
    return { record, resolution, decision, correction };
  }
  async procedureResolution(client: PublicClient, id: bigint, point?: ReadPoint) {
    return this.procedure(client).read.getResolution([id], readAt(point));
  }
  /** Adds the optional procedural origin to Core's separate finding/disposition projection. */
  async correctionCase(client: PublicClient, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const core = await this.sdk.correctionCase(client, id, point);
    if (core.record.input.kind !== 3 || !this.addresses.procedure
        || core.record.origin.toLowerCase() !== this.addresses.procedure.toLowerCase()) return core;
    const c = this.procedure(client), at = readAt(point);
    const [record, registry] = await Promise.all([
      c.read.getChallenge([core.record.input.originCaseId], at), c.read.DECISION_REGISTRY(at),
    ]);
    const [resolution, decision] = await Promise.all([
      record.resolutionId === 0n ? null : c.read.getResolution([record.resolutionId], at),
      this.readDecision(client, registry, record.decisionId, point),
    ]);
    return { ...core, originRecord: { family: 'procedure' as const, record, resolution, decision } };
  }
  async ruleProposal(client: PublicClient, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.ruleGovernance(client), at = readAt(point);
    const record = await c.read.getProposal([id], at);
    const [ratification, activation] = await Promise.all([
      record.ratificationId === 0n ? null : c.read.getRatification([record.ratificationId], at),
      record.activationId === 0n ? null : c.read.getActivation([record.activationId], at),
    ]);
    return { record, ratification, activation };
  }
  /** Compare handed-off terms with the sealed proposal. Activation requires a fresh execution check. */
  async verifyRuleProposalTerms(client: PublicClient, id: bigint, proposed: RulePackageInput,
      bindings: RuleModuleBindings, point?: ReadPoint) {
    const terms = structuredClone({ proposed, bindings });
    const requestedPoint = typeof point === 'object' ? { ...point } : point;
    const governor = this.ruleGovernance(client), registry = this.sdk.contracts(client).packages;
    const chainId = this.sdk.deployment.chainId;
    try {
      if (await client.getChainId() !== chainId) throw new AvaReadError();
      let snapshot: ReadPoint;
      if (typeof requestedPoint === 'bigint') {
        const block = await client.getBlock({ blockNumber: requestedPoint });
        if (!block.hash || block.number !== requestedPoint) throw new AvaReadError();
        snapshot = { blockHash: block.hash, requireCanonical: true };
      } else snapshot = await resolveReadPoint(client, requestedPoint);
      const at = readAt(snapshot);
      const proposal = await governor.read.getProposal([id], at);
      const [sealed, identity] = await Promise.all([
        registry.read.getGovernanceBinding([proposal.appId, proposal.targetWorkflowKey], at),
        governor.read.moduleIdentityHash(at),
      ]);
      if (proposal.id !== id || sealed.controller.toLowerCase() !== governor.address.toLowerCase()
          || identity === zeroHash || identity !== sealed.identityHash) throw new AvaReadError();
      const revisionCommitment = await registry.read.revisionCommitment([
        terms.proposed, proposal.expectedTargetPackageId, terms.bindings,
      ], at);
      return { matches: revisionCommitment === proposal.revisionCommitment,
        previousPackageId: proposal.expectedTargetPackageId, revisionCommitment, point: snapshot };
    } catch { throw new AvaReadError(); }
  }
  async ruleRatification(client: PublicClient, id: bigint, point?: ReadPoint) {
    return this.ruleGovernance(client).read.getRatification([id], readAt(point));
  }
  async ruleActivation(client: PublicClient, id: bigint, point?: ReadPoint) {
    return this.ruleGovernance(client).read.getActivation([id], readAt(point));
  }
  async privacyPolicy(client: PublicClient, id: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.privacy(client), at = readAt(point);
    const [[appId, active], rules] = await Promise.all([
      c.read.policyContext([id], at), c.read.getPolicyRules([id], at),
    ]);
    return { appId, active, rules };
  }
  async privacyCase(client: PublicClient, caseId: Hex, point?: ReadPoint) {
    const [appId, policyId, phase] = await this.privacy(client).read.caseContext([caseId], readAt(point));
    return { appId, policyId, phase };
  }
  async privacyResource(client: PublicClient, resourceId: Hex, point?: ReadPoint) {
    const [appId, caseId, policyId, materialClass, ciphertextHash, active] =
      await this.privacy(client).read.resourceContext([resourceId], readAt(point));
    return { appId, caseId, policyId, materialClass, ciphertextHash, active };
  }
  async privacyMembership(client: PublicClient, caseId: Hex, persona: Hex, readerRole: Hex, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.privacy(client), at = readAt(point), args = [caseId, persona, readerRole] as const;
    const [member, generation, expiresAt] = await Promise.all([
      c.read.isMember(args, at), c.read.membershipGeneration(args, at), c.read.membershipDeadline(args, at),
    ]);
    return { member, generation, expiresAt };
  }
  async privacyAccess(client: PublicClient, resourceId: Hex, persona: Hex,
      readerRole: Hex, purpose: Hex, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.privacy(client), at = readAt(point), args = [resourceId, persona, readerRole, purpose] as const;
    const [allowed, expiresAt, revision, [executor, requestId, effectHash]] = await Promise.all([
      c.read.canAccess(args, at), c.read.accessDeadline(args, at),
      c.read.grantRevision(args, at), c.read.accessBasis(args, at),
    ]);
    return { allowed, expiresAt, revision, executor, requestId, effectHash };
  }
  async privateEvidence(client: PublicClient, evidenceId: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.evidenceBindings(client), at = readAt(point);
    const binding = await c.read.getBinding([evidenceId], at);
    const [, , , , usable] = await c.read.resourceBinding([binding.resourceId], at);
    return { binding, usable };
  }
  /** This effect authorises access; it is never evidence that plaintext was delivered. */
  async disclosureReceipt(client: PublicClient, requestId: bigint, point?: ReadPoint) {
    point = await resolveReadPoint(client, point);
    const c = this.governedDisclosure(client), at = readAt(point);
    const [record, current, execution] = await Promise.all([
      c.read.getReceipt([requestId], at), c.read.isGrantCurrent([requestId], at),
      this.sdk.request(client, requestId, point),
    ]);
    return { record, current, execution };
  }
}
