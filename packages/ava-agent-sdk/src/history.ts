import { keccak256, toHex, type Hex } from 'viem';
import { jsonValue } from '@ava-protocol/sdk';
import { AvaAgentError } from './errors.js';
import type { AdviceHandoff, AdviceReceipt, DecisionAdvice, DecisionSnapshot } from './types.js';

/** Internal binding: contextHash alone cannot authenticate the public snapshot labels offline. */
export function adviceSnapshotHash(snapshot: DecisionSnapshot): Hex {
  return keccak256(toHex(JSON.stringify(jsonValue(snapshot))));
}

/** Same commitment used by a recommended advice's on-chain reasonHash. */
export function adviceReceiptHash(receipt: AdviceReceipt): Hex {
  return keccak256(toHex(JSON.stringify(jsonValue(receipt))));
}

/** Validate off-chain provenance only; never choose, authorise, sign or execute a fallback. */
export function linkAdvice(previous: DecisionAdvice, next: DecisionAdvice): AdviceHandoff {
  const invalid = (): never => { throw new AvaAgentError('invalid_advice', 'Invalid advice handoff'); };
  for (const advice of [previous, next]) {
    if (!advice || advice.status === 'unavailable' || !advice.receipt || !advice.snapshot
        || advice.status !== advice.receipt.status || advice.snapshot.contextHash !== advice.receipt.contextHash) invalid();
    if (advice.status !== 'unavailable' && advice.receipt.snapshotHash !== adviceSnapshotHash(advice.snapshot)) invalid();
    if (advice.status === 'recommended' && advice.reasonHash !== adviceReceiptHash(advice.receipt)) invalid();
  }
  if (previous.status === 'unavailable' || next.status === 'unavailable') return invalid();
  const a = previous.snapshot, b = next.snapshot;
  const previousReceiptHash = adviceReceiptHash(previous.receipt), nextReceiptHash = adviceReceiptHash(next.receipt);
  if (a.chainId !== b.chainId || a.registry.toLowerCase() !== b.registry.toLowerCase()
      || a.requestId !== b.requestId || a.appId !== b.appId || a.workflowKey !== b.workflowKey
      || next.receipt.parentReceiptHash !== previousReceiptHash) invalid();
  return { version: 'ava.agent-handoff.v1', previousReceiptHash, nextReceiptHash };
}
