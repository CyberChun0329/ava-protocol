import { randomBytes } from 'node:crypto';
import { isAddress, keccak256, toHex, zeroAddress, type Hex, type PublicClient } from 'viem';
import { DecisionKind, jsonValue, withCanonicalSnapshot, type AvaCall, type AvaExtensions } from '@ava-protocol/sdk';
import type { AgentActor, AgentInput, ChoiceProvider, ChoiceAnswer, DecisionAdvice, DecisionSnapshot, AdviceReceipt } from './types.js';
import { AvaAgentError, providerFailure } from './errors.js';
import { adviceReceiptHash, adviceSnapshotHash } from './history.js';
export * from './types.js';
export * from './providers.js';
export { AvaAgentError, type AgentErrorCode } from './errors.js';
export * from './ollama.js';
export * from './local-systemone.js';
export { adviceReceiptHash, linkAdvice } from './history.js';

const digest = (value: unknown) => keccak256(toHex(JSON.stringify(jsonValue(value))));
const active = (signal?: AbortSignal) => {
  if (signal?.aborted) throw providerFailure(undefined, signal, 'Agent operation aborted');
};

/** Optional app-side advice. This module never owns a signer or submits a transaction. */
export class AvaDecisionAgent {
  private readonly actor: AgentActor;
  constructor(private readonly extensions: AvaExtensions, actor: AgentActor) {
    if (!isAddress(actor.account) || actor.account === zeroAddress) throw new AvaAgentError('invalid_configuration', 'Invalid agent account');
    this.actor = { ...actor };
  }

  private async snapshot(client: PublicClient, requestId: bigint): Promise<DecisionSnapshot> {
    const chainId = await client.getChainId();
    if (chainId !== this.extensions.sdk.deployment.chainId) throw new AvaAgentError('invalid_configuration', 'Agent chain mismatch');
    return withCanonicalSnapshot(client, async ({ point, blockNumber, blockHash }) => {
      const contract = this.extensions.decisions(client);
      const [record, options] = await Promise.all([
        contract.read.getRequest([requestId], { ...point }),
        this.extensions.admissibleDecisions(client, requestId, this.actor.account, this.actor, point),
      ]);
      return { chainId, registry: contract.address, requestId, appId: record.input.appId,
        workflowKey: record.input.workflowKey, packageId: record.input.packageId,
        actor: { ...this.actor }, blockNumber, blockHash,
        supportRevision: record.supportRevision, lastDecisionId: record.lastDecisionId,
        options, contextHash: digest([chainId, contract.address.toLowerCase(), requestId,
          this.actor.account.toLowerCase(), this.actor.roleKey, this.actor.authorityId, record, options]) };
    });
  }

  async advise(client: PublicClient, requestId: bigint, provider: ChoiceProvider,
      input: AgentInput): Promise<DecisionAdvice> {
    const { configurationId, instructions, input: material, minimumConfidence, signal, parentReceiptHash } = input;
    const descriptions = { ...input.descriptions };
    const providerId = provider.id, model = provider.model;
    active(signal);
    if (![configurationId, instructions, providerId, model].every(
      text => typeof text === 'string' && text.trim().length > 0) || typeof material !== 'string'
        || (minimumConfidence !== undefined && (typeof minimumConfidence !== 'number'
          || !Number.isFinite(minimumConfidence) || minimumConfidence < 0 || minimumConfidence > 1))
        || (parentReceiptHash !== undefined && (!/^0x[0-9a-fA-F]{64}$/.test(parentReceiptHash)
          || /^0x0{64}$/i.test(parentReceiptHash)))) {
      throw new AvaAgentError('invalid_configuration', 'Invalid agent configuration');
    }
    const snapshot = await this.snapshot(client, requestId);
    active(signal);
    if (snapshot.options.length === 0) return { status: 'unavailable', snapshot };
    const question = { input: material, instructions,
      choices: snapshot.options.map(option => ({ value: option.key, description: descriptions[option.key] })) };
    if (!question.choices.every(choice => typeof choice.description === 'string' && choice.description.trim())) {
      throw new AvaAgentError('invalid_configuration', 'Invalid agent option descriptions');
    }
    const salt = `0x${randomBytes(32).toString('hex')}` as Hex;
    const inputCommitment = digest([salt, question]);
    let answer: ChoiceAnswer;
    active(signal);
    try { answer = await provider.choose(question, signal); }
    catch (error) { active(signal); throw providerFailure(error, signal); }
    active(signal);
    if (!answer || (answer.kind !== 'choice' && answer.kind !== 'abstain')) throw new AvaAgentError('invalid_response', 'Invalid provider answer');
    if (answer.kind === 'choice' && (!snapshot.options.some(option => option.key === answer.choice)
        || (answer.confidence !== undefined && (typeof answer.confidence !== 'number'
          || !Number.isFinite(answer.confidence) || answer.confidence < 0 || answer.confidence > 1)))) {
      throw new AvaAgentError('invalid_response', 'Invalid provider choice or confidence');
    }
    if (![answer.responseId, answer.servedModel].every(
      value => value === undefined || (typeof value === 'string' && value.length > 0))) {
      throw new AvaAgentError('invalid_response', 'Invalid provider metadata');
    }
    if (answer.kind === 'abstain' && answer.reason !== undefined
        && !['insufficient_options', 'provider_refusal', 'provider_abstained'].includes(answer.reason)) {
      throw new AvaAgentError('invalid_response', 'Invalid provider abstention reason');
    }
    const abstentionReason = answer.kind === 'abstain' ? answer.reason ?? 'provider_abstained'
      : minimumConfidence !== undefined && answer.confidence === undefined ? 'missing_confidence'
        : minimumConfidence !== undefined && answer.confidence! < minimumConfidence ? 'low_confidence' : undefined;
    const status = abstentionReason === undefined ? 'recommended' : 'abstained';
    const receipt: AdviceReceipt = { version: 'ava.agent-advice.v1', provider: providerId,
      model, configurationId,
      snapshotHash: adviceSnapshotHash(snapshot),
      contextHash: snapshot.contextHash, blockHash: snapshot.blockHash, blockNumber: snapshot.blockNumber,
      salt, inputCommitment, minimumConfidence, status,
      ...(answer.kind === 'choice' ? { choice: answer.choice as Hex, confidence: answer.confidence } : {}),
      ...(answer.responseId !== undefined ? { responseId: answer.responseId } : {}),
      ...(answer.servedModel !== undefined ? { servedModel: answer.servedModel } : {}),
      ...(abstentionReason !== undefined ? { abstentionReason } : {}),
      ...(parentReceiptHash !== undefined ? { parentReceiptHash } : {}) };
    if (status === 'abstained') return { status, snapshot, receipt };
    return { status: 'recommended', snapshot, receipt, reasonHash: adviceReceiptHash(receipt) };
  }

  /** Recheck now, then return calldata. AvaSdk.sign and the chain still validate again. */
  async buildCommand(client: PublicClient, advice: DecisionAdvice, executionRequestId: bigint): Promise<AvaCall> {
    if (advice.status !== 'recommended') throw new AvaAgentError('invalid_advice', 'Agent advice has no actionable choice');
    const current = await this.snapshot(client, advice.snapshot.requestId);
    // The actor's current request and options must still match the recommended context.
    if (current.contextHash !== advice.snapshot.contextHash || advice.receipt.contextHash !== current.contextHash
        || advice.receipt.status !== advice.status) {
      throw new AvaAgentError('invalid_advice', 'Stale or modified agent advice');
    }
    // New receipts also bind every public snapshot field; legacy command receipts may omit this.
    if (advice.receipt.snapshotHash !== undefined
        && advice.receipt.snapshotHash !== adviceSnapshotHash(advice.snapshot)) {
      throw new AvaAgentError('invalid_advice', 'Stale or modified agent advice');
    }
    // Both receipt generations must preserve the exact commitment used as the decision reason.
    if (adviceReceiptHash(advice.receipt) !== advice.reasonHash) {
      throw new AvaAgentError('invalid_advice', 'Stale or modified agent advice');
    }
    const option = current.options.find(item => item.key === advice.receipt.choice);
    if (!option) throw new AvaAgentError('invalid_advice', 'Agent choice is not currently admissible');
    if (option.kind === DecisionKind.Substantive ? executionRequestId <= 0n : executionRequestId !== 0n) {
      throw new AvaAgentError('invalid_advice', 'Execution request does not match decision kind');
    }
    return this.extensions.chooseDecision(current.requestId, option.key, executionRequestId,
      current.lastDecisionId, this.actor, advice.reasonHash);
  }
}
