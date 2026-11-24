import type { Address, Hex } from 'viem';
import type { Authority } from '@ava-protocol/sdk';

export interface AgentActor extends Authority { account: Address }
export interface ChoiceQuestion {
  input: string;
  instructions: string;
  choices: { value: Hex; description: string }[];
}
export type ProviderAbstentionReason = 'insufficient_options' | 'provider_refusal' | 'provider_abstained';
export type AbstentionReason = ProviderAbstentionReason | 'low_confidence' | 'missing_confidence';
export type ChoiceAnswer =
  | { kind: 'choice'; choice: string; confidence?: number; responseId?: string; servedModel?: string }
  | { kind: 'abstain'; reason?: ProviderAbstentionReason; responseId?: string; servedModel?: string };
/** The application supplies credentials and provider client. No wallet enters this interface. */
export interface ChoiceProvider {
  readonly id: string;
  readonly model: string;
  choose(question: ChoiceQuestion, signal?: AbortSignal): Promise<ChoiceAnswer>;
}
export interface AgentInput {
  configurationId: string;
  instructions: string;
  /** Already authorised for disclosure to the configured provider by the application. */
  input: string;
  descriptions: Readonly<Record<string, string>>;
  minimumConfidence?: number;
  signal?: AbortSignal;
  /** Optional off-chain provenance; it grants no authority and does not select a fallback. */
  parentReceiptHash?: Hex;
}
export interface DecisionOption {
  key: Hex;
  kind: number;
  actionKey: Hex;
  parametersHash: Hex;
  notBefore: bigint;
  conditionsHash: Hex;
}
export interface DecisionSnapshot {
  chainId: number;
  registry: Address;
  requestId: bigint;
  appId: Hex;
  workflowKey: Hex;
  packageId: bigint;
  actor: AgentActor;
  blockNumber: bigint;
  blockHash: Hex;
  supportRevision: bigint;
  lastDecisionId: bigint;
  options: readonly DecisionOption[];
  contextHash: Hex;
}
export interface AdviceReceipt {
  version: 'ava.agent-advice.v1';
  provider: string;
  model: string;
  configurationId: string;
  /** Newly generated receipts bind every public snapshot field for offline handoff verification. */
  snapshotHash?: Hex;
  contextHash: Hex;
  blockHash: Hex;
  blockNumber: bigint;
  salt: Hex;
  inputCommitment: Hex;
  minimumConfidence?: number;
  status: 'recommended' | 'abstained';
  choice?: Hex;
  confidence?: number;
  responseId?: string;
  servedModel?: string;
  abstentionReason?: AbstentionReason;
  parentReceiptHash?: Hex;
}
export interface AdviceHandoff {
  version: 'ava.agent-handoff.v1';
  previousReceiptHash: Hex;
  nextReceiptHash: Hex;
}
export type DecisionAdvice =
  | { status: 'unavailable'; snapshot: DecisionSnapshot }
  | { status: 'abstained'; snapshot: DecisionSnapshot; receipt: AdviceReceipt }
  | { status: 'recommended'; snapshot: DecisionSnapshot; receipt: AdviceReceipt; reasonHash: Hex };
