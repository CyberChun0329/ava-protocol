import { readFile, writeFile, mkdir } from 'node:fs/promises';

if (process.argv.slice(2).some(argument => argument !== '--check')) throw new Error('Usage: generate_sdk_abi.mjs [--check]');

const contracts = {
  applications: 'AVAApplicationRegistry', identities: 'AVAIdentityRegistry',
  authority: 'AVAAuthorityMatrix', packages: 'AVACoreRulePackageRegistry',
  disclosure: 'AVADisclosurePolicyRegistry', evidence: 'AVAEvidenceRegistry',
  kernel: 'AVAGovernanceKernel', requests: 'AVARequestAllocation', challenges: 'AVAChallengeExtension',
};
let source = '// Generated from this project\'s Forge artifacts. Run npm run abi after forge build.\n';
const fixedHelpers = { corrections: 'AVACorrectionRegistry', execution: 'AVAExecutionLifecycle' };
const extensions = {
  decisions: 'AVADecisionRegistry', procedure: 'AVAProcedureAdjudication',
  ruleGovernance: 'AVARecognisedRuleGovernance', privacy: 'AVAPrivacyRegistry',
  governedDisclosure: 'AVAGovernedDisclosure', evidenceBindings: 'AVAEvidenceResourceBinding',
};
for (const [name, contract] of Object.entries({ ...contracts, ...fixedHelpers, ...extensions })) {
  const artifact = JSON.parse(await readFile(`.build/out/${contract}.sol/${contract}.json`, 'utf8'));
  source += `export const ${name}Abi = ${JSON.stringify(artifact.abi)} as const;\n`;
}
source += `export const avaAbis = {${Object.keys(contracts).map(name => `${name}: ${name}Abi`).join(',')}} as const;\n`;
source += `export const avaExtensionAbis = {${Object.keys(extensions).map(name => `${name}: ${name}Abi`).join(',')}} as const;\n`;
if (process.argv.includes('--check')) {
  if (await readFile('packages/ava-sdk/src/abi.ts', 'utf8') !== source) {
    throw new Error('SDK ABI differs from current Forge artifacts; run npm run abi and review the source change');
  }
  console.log('SDK ABI matches current Forge artifacts.');
} else {
  await mkdir('packages/ava-sdk/src', { recursive: true });
  await writeFile('packages/ava-sdk/src/abi.ts', source);
  console.log(`Generated ${Object.keys(contracts).length + Object.keys(fixedHelpers).length + Object.keys(extensions).length} AVA contract ABIs (${Object.keys(contracts).length} configured Core components, ${Object.keys(extensions).length} optional extensions).`);
}
