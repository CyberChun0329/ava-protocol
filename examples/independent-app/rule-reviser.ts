import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { createWalletClient, decodeEventLog, http, type Address } from 'viem';
import { mnemonicToAccount } from 'viem/accounts';
import { foundry } from 'viem/chains';
import { AvaExtensions, AvaSdk, AvaServiceClient, AvaSigningError, avaExtensionAbis, localClient,
  type Authority, type AvaCall, type AvaDeployment, type RuleModuleBindings, type RulePackageInput } from '@ava-protocol/sdk';

interface Handoff {
  deployment: AvaDeployment;
  governor: Address;
  authority: Authority;
  proposalId: string;
  competingId: string;
  competingUri: string;
  proposed: Omit<RulePackageInput, 'version'> & { version: string };
  bindings: RuleModuleBindings;
  originalPackageId: string;
}

const [handoffFile, resultFile] = process.argv.slice(2);
assert(handoffFile && resultFile, 'Expected handoff and result paths');
const rpcUrl = process.env.AVA_RULE_RPC_URL;
const serviceUrl = process.env.AVA_RULE_SERVICE_URL;
const token = process.env.AVA_RULE_SERVICE_TOKEN;
assert(rpcUrl && serviceUrl && token, 'Expected local RPC and service configuration');
for (const address of [rpcUrl, serviceUrl]) {
  const url = new URL(address);
  assert(url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), 'Local HTTP endpoints required');
}
const handoff = JSON.parse(await readFile(handoffFile, 'utf8')) as Handoff;
const proposed: RulePackageInput = { ...handoff.proposed, version: BigInt(handoff.proposed.version) };
const { bindings, authority } = handoff;
const proposalId = BigInt(handoff.proposalId), competingId = BigInt(handoff.competingId);
const originalPackageId = BigInt(handoff.originalPackageId);
assert(bindings.length >= 2, 'Module-order check requires at least two bindings');
assert.notDeepEqual(bindings, [...bindings].reverse(), 'Module-order check requires distinct bindings');
const sdk = new AvaSdk(handoff.deployment);
const extensions = new AvaExtensions(sdk, { ruleGovernance: handoff.governor });
const client = localClient(rpcUrl);
assert.equal(handoff.deployment.chainId, 31337);
assert.equal(await client.getChainId(), 31337);
await extensions.verify(client);
const account = mnemonicToAccount('test test test test test test test test test test test junk', { addressIndex: 3 });
const wallet = createWalletClient({ account, chain: foundry, transport: http(rpcUrl, { retryCount: 0 }) });
const service = new AvaServiceClient(serviceUrl, token);
const packages = sdk.contracts(client).packages;
const previous = await packages.read.getRulePackageById([originalPackageId]);
assert.equal(await packages.read.getActivePackageId([proposed.appId, proposed.workflowKey]), originalPackageId);
const before = await extensions.ruleProposal(client, proposalId);
const competingBefore = await extensions.ruleProposal(client, competingId);
assert.equal(before.record.expectedTargetPackageId, originalPackageId);
assert.equal(competingBefore.record.expectedTargetPackageId, originalPackageId);
assert.equal(before.record.activationId, 0n);
assert.equal(competingBefore.record.activationId, 0n);

const terms = await extensions.verifyRuleProposalTerms(client, proposalId, proposed, bindings);
assert.equal(terms.matches, true);
assert.equal(terms.previousPackageId, originalPackageId);
const competingTerms = { ...proposed, uri: handoff.competingUri };
assert.equal((await extensions.verifyRuleProposalTerms(client, competingId, competingTerms, bindings)).matches, true);
const changed = { ...proposed, uri: `${proposed.uri}#altered` };
const reordered = [...bindings].reverse();
assert.equal((await extensions.verifyRuleProposalTerms(client, proposalId, changed, bindings)).matches, false);
assert.equal((await extensions.verifyRuleProposalTerms(client, proposalId, proposed, reordered)).matches, false);
const refused = async (call: AvaCall) => assert.rejects(() => sdk.sign(client, wallet, call), (error: unknown) => {
  assert(error instanceof AvaSigningError);
  assert.equal(error.stage, 'simulation');
  assert.equal(error.code, 'contract_reverted');
  return true;
});
await refused(extensions.executeRuleProposal(proposalId, changed, bindings, authority));
await refused(extensions.executeRuleProposal(proposalId, proposed, reordered, authority));
// The competing proposal is executable before the active pointer changes.
await sdk.sign(client, wallet, extensions.executeRuleProposal(competingId, competingTerms, bindings, authority));
const signed = await sdk.sign(client, wallet, extensions.executeRuleProposal(proposalId, proposed, bindings, authority));
const txKey = `rule-revision:${proposalId}`;
const submitted = await service.submit(txKey, signed.serializedTransaction);
assert.equal(submitted.hash, signed.hash);
const observed = await service.observeTransaction({ key: txKey, hash: signed.hash }, { pollIntervalMs: 20 });
assert.equal(observed.status, 'confirmed');
const activated = await extensions.createdId(client, signed.hash,
  { source: 'ruleGovernance', eventName: 'RuleRevisionActivated', idField: 'activationId' });
const ratified = await extensions.createdId(client, signed.hash,
  { source: 'ruleGovernance', eventName: 'RuleRevisionRatified', idField: 'ratificationId' });
const { id: activationId } = activated, { id: ratificationId } = ratified;
const receipt = await client.getTransactionReceipt({ hash: signed.hash });
assert.equal(receipt.blockHash, activated.blockHash);
assert.equal(receipt.blockHash, ratified.blockHash);
const receiptLog = (index: number) => {
  const log = receipt.logs.find(log => log.logIndex === index && log.address.toLowerCase() === handoff.governor.toLowerCase());
  assert(log, `Missing rule-governance receipt log ${index}`);
  return { abi: avaExtensionAbis.ruleGovernance, data: log.data, topics: log.topics };
};
const activationEvent = decodeEventLog({ ...receiptLog(activated.logIndex), eventName: 'RuleRevisionActivated' });
const ratificationEvent = decodeEventLog({ ...receiptLog(ratified.logIndex), eventName: 'RuleRevisionRatified' });
assert.equal(activationEvent.args.proposalId, proposalId);
assert.equal(ratificationEvent.args.proposalId, proposalId);
assert.equal(ratificationEvent.args.actor.toLowerCase(), account.address.toLowerCase());
const after = await extensions.ruleProposal(client, proposalId, { blockHash: receipt.blockHash, requireCanonical: true });
assert(after.activation && after.ratification);
assert.equal(after.record.activationId, activationId);
assert.equal(after.record.ratificationId, ratificationId);
assert.equal(after.activation.id, activationId);
assert.equal(after.ratification.id, ratificationId);
assert.equal(after.activation.proposalId, proposalId);
assert.equal(after.ratification.proposalId, proposalId);
assert.equal(after.activation.ratificationId, ratificationId);
assert.equal(after.activation.previousPackageId, originalPackageId);
assert.equal(after.ratification.previousPackageId, originalPackageId);
assert.equal(after.ratification.actor.toLowerCase(), account.address.toLowerCase());
assert.equal(after.activation.actor.toLowerCase(), account.address.toLowerCase());
assert.equal(after.activation.revisionCommitment, before.record.revisionCommitment);
assert.equal(after.ratification.revisionCommitment, before.record.revisionCommitment);
const replacementPackageId = after.activation.replacementPackageId;
assert.equal(activationEvent.args.replacementPackageId, replacementPackageId);
assert.notEqual(replacementPackageId, originalPackageId);
assert.equal(await packages.read.getActivePackageId([proposed.appId, proposed.workflowKey]), replacementPackageId);
assert.deepEqual(await packages.read.getRulePackageById([originalPackageId]), previous);
const replacement = await packages.read.getRulePackageById([replacementPackageId]);
assert.equal(replacement.version, proposed.version);
assert.equal(replacement.uri, proposed.uri);
assert.equal(replacement.authorityId, proposed.authorityId);
for (const binding of bindings) {
  assert.equal((await packages.read.getModule([replacementPackageId, binding.capabilityKey])).toLowerCase(),
    binding.module.toLowerCase());
}
await refused(extensions.executeRuleProposal(competingId, competingTerms, bindings, authority));
await refused(extensions.executeRuleProposal(proposalId, proposed, bindings, authority));
const competingAfter = await extensions.ruleProposal(client, competingId);
assert.equal(competingAfter.record.activationId, 0n);
assert.equal(competingAfter.record.ratificationId, 0n);
assert.equal(competingAfter.activation, null);
assert.equal(competingAfter.ratification, null);
await writeFile(resultFile, JSON.stringify({ activationId, ratificationId, replacementPackageId, hash: signed.hash,
  receipt: { blockHash: receipt.blockHash, blockNumber: receipt.blockNumber,
    activationLogIndex: activated.logIndex, ratificationLogIndex: ratified.logIndex },
  checks: { localChain: true, exactTerms: true, alteredUriMismatch: true, alteredOrderMismatch: true,
    alteredUriRejected: true, alteredOrderRejected: true, confirmed: true, recordsLinked: true,
    previousRetained: true, activePointer: true, competingExecutableBeforeActivation: true,
    staleRejected: true, replayRejected: true,
    staleUnactivated: true } }, (_, value) => typeof value === 'bigint' ? value.toString() : value, 2) + '\n');
