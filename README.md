# The AVA Protocol

AVA is a governance protocol with Solidity contracts and a TypeScript SDK for applications built around *recognised states*. An application can use a recognised state as evidence for an Allocation, which authorises a specific action. An authorised executor can then carry out that action under its terms. Formal correction can establish a new, limited conclusion while retaining the earlier records and recorded effects.

## Start here

This source tree is the `0.1.0-preview.12` developer preview.

The WorkOrder preview installs an independent application on a disposable local chain and exercises recognition, Allocation, execution and correction. With the preview archive, extract it and open its README. From this source tree, install the dependencies and run `npm run pack:preview` first. The generated bundle is under `.local/developer-preview/ava-core-sdk-0.1.0-preview.12/`. Run the verifier from the bundle directory with its manifest and component archives present. [WorkOrder verification instructions](examples/developer-preview/README.md)

| Purpose | Guide |
| --- | --- |
| Understand governance records and correction | [Governance](docs/governance.md) |
| Build or install Core contracts | [Contracts package](packages/ava-contracts/README.md) |
| Read records and build calls | [TypeScript SDK](packages/ava-sdk/README.md) |
| Run the optional local query and relay service | [Local service](packages/ava-service/README.md) |
| Recover an uncertain local transaction | [Transaction recovery](docs/transaction-recovery.md) |
| Add optional decision advice | [Agent SDK](packages/ava-agent-sdk/README.md) |
| Inspect the independent application source | [WorkOrder source](examples/independent-app/README.md) |

The package guides use the `0.1.0` filenames produced by `npm run pack:sdk`. Use the exact `0.1.0-preview.12` filenames from the manifest when installing the portable preview.

## Source checks and preview packaging

Use Node.js 24 or newer, Foundry (reference 1.5.1-stable), and solc 0.8.26. Install the compiler before running Foundry offline. Python 3 and the dependencies in `requirements-privacy.txt` are needed for the applicable Python tests. Install Node dependencies and run the source checks:

```sh
npm ci --ignore-scripts
mkdir -p .tmp
python3 -m venv .local/privacy-venv
.local/privacy-venv/bin/python -m pip install -r requirements-privacy.txt
forge test --offline
npm run abi -- --check
npm run typecheck
npm test
.local/privacy-venv/bin/python -m unittest discover -s test/python
npm run pack:preview
```

The preview verifier runs from the extracted archive; see its README for toolchain prerequisites, verification options and the local WorkOrder run. Dependency installation can require network access, and the local workflow requires loopback access for Anvil. Results apply to the exact source and packages checked.

## Status and licence

This is a developer preview for local development and testing. Independent security review and production-network validation remain open. AVA-authored code is licensed under [Apache-2.0](LICENSE). See [NOTICE](NOTICE) and [licensing details](docs/licensing.md) for third-party terms.
