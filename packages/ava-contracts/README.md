# AVA Protocol contracts

Solidity source distribution for AVA's recognised-state, authority, Allocation,
execution, correction and optional extension contracts. It contains no Peer
Review, Spark DAO or Project Grants application sources. Version 0.1.0 is a local
developer preview, aligned with the 0.1.0 SDK; it is not an audited production
deployment.

Install the supplied archive in your own project:

```sh
npm install ./ava-protocol-contracts-0.1.0.tgz
```

Use Foundry with solc 0.8.26, Cancun, viaIR, optimizer enabled with 200 runs and
`bytecode_hash = "none"`. Add this remapping:

```toml
libs = ["node_modules"]
remappings = ["@ava-protocol/contracts/=node_modules/@ava-protocol/contracts/"]
```

```solidity
import {IAVAApplicationModule} from "@ava-protocol/contracts/src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "@ava-protocol/contracts/src/interfaces/IRuleModuleIdentity.sol";
```

Use `src/canonical/AVAProtocolSurface.sol` for the standard interfaces and import
the optional extensions your application uses. `script/AVADefaultBindings.sol`
assembles the default contract bindings. `script/AVADefaultPolicies.sol` checks
the stateless policies you can reuse. Your application declares its policies,
actors, permissions, effects and allowed sources of correction.

For a disposable chain 31337, initialize just the shared Core:

```sh
forge script node_modules/@ava-protocol/contracts/script/DeployAVACore.s.sol:DeployAVACore \
  --sig 'run(address)' "$AVA_ROOT_ADMIN" --sender "$AVA_ROOT_ADMIN" \
  --rpc-url http://127.0.0.1:8545 --chain-id 31337 --unlocked --broadcast
```

The local node must own that disposable account. The script installs no sample
application, subject or actor permission, and never selects a model or signer.
Its `run()` alternative reads `AVA_ROOT_ADMIN`. It intentionally refuses other
chains. Application installation is a separate authorised operation.

Generate a public declaration from the resulting broadcasts with
`exportPublicDeployment` and `foundryArtifactLoader` from the separately installed
`@ava-protocol/sdk/deployment` Node subpath. Explicitly pass `allowCoreOnly: true`
for an empty Core; merge Core and application broadcasts for an app declaration,
then call the SDK's `verifyInstallation` before using it. Export is an offline
declaration; on-chain installation checks remain separate.

AVA-owned source is Apache-2.0; see LICENSE and NOTICE. The vendored OpenZeppelin
4.9.6 signature utilities retain their own MIT license and notices under
`src/vendor/openzeppelin-v4.9.6/`.
