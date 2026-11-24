import assert from 'node:assert/strict';
import { AvaExtensions, type AvaSdk } from '@ava-protocol/sdk';
import type { Address, Hex } from 'viem';
import { artifact, type localChain } from './local-chain.js';

type Chain = Awaited<ReturnType<typeof localChain>>;

export async function deployDecisionContract(chain: Chain, name: string, args: unknown[], witnessValidation?: Address) {
  const a = await artifact(name);
  let bytecode = a.bytecode.object;
  if (name === 'AVADecisionRegistry') {
    const references = Object.values(a.bytecode.linkReferences ?? {}).flatMap(source => source.AVADecisionWitnessValidation ?? []);
    assert(witnessValidation && references?.length, 'Decision witness validation link missing');
    for (const reference of references) {
      assert.equal(reference.length, 20);
      const start = 2 + reference.start * 2;
      bytecode = `${bytecode.slice(0, start)}${witnessValidation.slice(2)}${bytecode.slice(start + 40)}` as Hex;
    }
  }
  const hash = await chain.wallets[0].deployContract({ abi: a.abi, bytecode, args });
  const receipt = await chain.client.waitForTransactionReceipt({ hash });
  assert.equal(receipt.status, 'success');
  assert(receipt.contractAddress);
  return receipt.contractAddress;
}

export async function deployDecisionHost(chain: Chain, sdk: AvaSdk): Promise<{
  extensions: AvaExtensions; bridge: Address; deploymentTransactions: number;
}> {
  const witnessValidation = await deployDecisionContract(chain, 'AVADecisionWitnessValidation', []);
  const decisions = await deployDecisionContract(chain, 'AVADecisionRegistry',
    [sdk.deployment.addresses.kernel, sdk.deployment.addresses.requests], witnessValidation);
  const bridge = await deployDecisionContract(chain, 'AVAResolvedDecisionPolicy', [decisions]);
  return { extensions: new AvaExtensions(sdk, { decisions }), bridge, deploymentTransactions: 3 };
}

