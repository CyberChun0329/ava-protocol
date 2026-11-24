// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAApplicationRegistry} from "../src/AVAApplicationRegistry.sol";
import {AVAIdentityRegistry} from "../src/core/AVAIdentityRegistry.sol";
import {AVAAuthorityMatrix} from "../src/core/AVAAuthorityMatrix.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVADisclosurePolicyRegistry} from "../src/core/AVADisclosurePolicyRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAWorkflowPolicyRouter} from "../src/core/AVAWorkflowPolicyRouter.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVAChallengeExtension} from "../src/extensions/challenge/AVAChallengeExtension.sol";

interface AVACoreScriptVm {
    function envAddress(string calldata name) external view returns (address);
    function startBroadcast(address sender) external;
    function stopBroadcast() external;
}

/// @notice Disposable local Core bootstrap. Application installation and permissions are separate.
contract DeployAVACore {
    AVACoreScriptVm private constant vm = AVACoreScriptVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct Deployment {
        AVAApplicationRegistry applications;
        AVAIdentityRegistry identities;
        AVAAuthorityMatrix authority;
        AVACoreRulePackageRegistry packages;
        AVADisclosurePolicyRegistry disclosure;
        AVAEvidenceRegistry evidence;
        AVAWorkflowPolicyRouter router;
        AVAGovernanceKernel kernel;
        AVARequestAllocation requests;
        AVAChallengeExtension challenges;
    }

    function run() external returns (Deployment memory) {
        return _run(vm.envAddress("AVA_ROOT_ADMIN"));
    }

    function run(address admin) external returns (Deployment memory) {
        return _run(admin);
    }

    function _run(address admin) private returns (Deployment memory d) {
        require(block.chainid == 31337, "Local chain 31337 only");
        require(admin != address(0), "Zero root administrator");
        vm.startBroadcast(admin);
        // Separate deployments preserve the normal per-contract EVM size limits.
        d.applications = new AVAApplicationRegistry(admin);
        d.identities = new AVAIdentityRegistry(d.applications);
        d.authority = new AVAAuthorityMatrix(d.applications, d.identities);
        d.packages = new AVACoreRulePackageRegistry(d.applications, d.authority);
        d.disclosure = new AVADisclosurePolicyRegistry(d.applications, d.authority);
        d.evidence = new AVAEvidenceRegistry(d.authority, d.identities, d.packages, d.disclosure);
        d.router = new AVAWorkflowPolicyRouter(d.packages, d.evidence, d.disclosure);
        d.kernel = new AVAGovernanceKernel(d.authority, d.identities, d.packages, d.evidence, d.disclosure, d.router);
        d.requests = new AVARequestAllocation(d.kernel);
        d.challenges = new AVAChallengeExtension(d.kernel, d.authority, d.identities, d.packages, d.evidence);
        vm.stopBroadcast();
    }
}
