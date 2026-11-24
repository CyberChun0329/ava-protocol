// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVADefaultBindings} from "../script/AVADefaultBindings.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";

contract DefaultBindingsHarness {
    function bindings(address application, address core, address extension, address allocation)
        external
        pure
        returns (AVACoreRulePackageRegistry.ModuleBinding[] memory)
    {
        return AVADefaultBindings.bindings(application, core, extension, allocation);
    }
}

contract DefaultBindingsTest {
    function testDefaultProfilePreservesEveryOrderedCapabilityAndAllocationOverride() public {
        AVACoreRulePackageRegistry.ModuleBinding[] memory profile =
            new DefaultBindingsHarness().bindings(address(0x101), address(0x202), address(0x303), address(0x404));

        // Independent literals from the existing deployment profile, including its exact order.
        require(profile.length == 19, "default capability count");
        _assertBinding(profile[0], keccak256("ava.capability.application.v1"), address(0x101));
        _assertBinding(profile[1], keccak256("ava.capability.attribution.v1"), address(0x202));
        _assertBinding(profile[2], keccak256("ava.capability.verification.v1"), address(0x202));
        _assertBinding(profile[3], keccak256("ava.capability.transition-rule.v1"), address(0x202));
        _assertBinding(profile[4], keccak256("ava.capability.evidence-policy.v1"), address(0x202));
        _assertBinding(profile[5], keccak256("ava.capability.disclosure-policy.v1"), address(0x202));
        _assertBinding(profile[6], keccak256("ava.capability.challenge-policy.v1"), address(0x202));
        _assertBinding(profile[7], keccak256("ava.capability.authority-policy.v1"), address(0x202));
        _assertBinding(profile[8], keccak256("ava.capability.standing.v1"), address(0x202));
        _assertBinding(profile[9], keccak256("ava.capability.allocation.v1"), address(0x404));
        _assertBinding(profile[10], keccak256("ava.capability.consequence.v1"), address(0x202));
        _assertBinding(profile[11], keccak256("ava.capability.evidence-lifecycle.v1"), address(0x202));
        _assertBinding(profile[12], keccak256("ava.capability.standing-computation.v1"), address(0x303));
        _assertBinding(profile[13], keccak256("ava.capability.standing-credential.v1"), address(0x303));
        _assertBinding(profile[14], keccak256("ava.capability.reward.v1"), address(0x303));
        _assertBinding(profile[15], keccak256("ava.capability.administrative-priority.v1"), address(0x303));
        _assertBinding(profile[16], keccak256("ava.capability.penalty.v1"), address(0x303));
        _assertBinding(profile[17], keccak256("ava.capability.restoration.v1"), address(0x303));
        _assertBinding(profile[18], keccak256("ava.capability.value-execution.v1"), address(0x303));
    }

    function _assertBinding(AVACoreRulePackageRegistry.ModuleBinding memory binding, bytes32 key, address module)
        private
        pure
    {
        require(binding.capabilityKey == key, "default capability order");
        require(address(binding.module) == module, "default policy binding");
    }
}
