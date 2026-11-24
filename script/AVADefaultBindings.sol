// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {IRuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";

/// @notice The existing 19-capability app deployment profile; this helper only assembles bindings.
library AVADefaultBindings {
    function bindings(address application, address core, address extension, address allocation)
        internal
        pure
        returns (AVACoreRulePackageRegistry.ModuleBinding[] memory profile)
    {
        profile = new AVACoreRulePackageRegistry.ModuleBinding[](19);
        profile[0] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.APPLICATION, IRuleModuleIdentity(application));
        profile[1] = AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.ATTRIBUTION, IRuleModuleIdentity(core));
        profile[2] = AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.VERIFICATION, IRuleModuleIdentity(core));
        profile[3] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.TRANSITION_RULE, IRuleModuleIdentity(core));
        profile[4] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.EVIDENCE_POLICY, IRuleModuleIdentity(core));
        profile[5] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.DISCLOSURE_POLICY, IRuleModuleIdentity(core));
        profile[6] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.CHALLENGE_POLICY, IRuleModuleIdentity(core));
        profile[7] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.AUTHORITY_POLICY, IRuleModuleIdentity(core));
        profile[8] = AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.STANDING, IRuleModuleIdentity(core));
        profile[9] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.ALLOCATION, IRuleModuleIdentity(allocation));
        profile[10] = AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.CONSEQUENCE, IRuleModuleIdentity(core));
        profile[11] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.EVIDENCE_LIFECYCLE, IRuleModuleIdentity(core));
        profile[12] = AVACoreRulePackageRegistry.ModuleBinding(
            AVACapabilityKeys.STANDING_COMPUTATION, IRuleModuleIdentity(extension)
        );
        profile[13] = AVACoreRulePackageRegistry.ModuleBinding(
            AVACapabilityKeys.STANDING_CREDENTIAL, IRuleModuleIdentity(extension)
        );
        profile[14] = AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.REWARD, IRuleModuleIdentity(extension));
        profile[15] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.PRIORITY, IRuleModuleIdentity(extension));
        profile[16] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.PENALTY, IRuleModuleIdentity(extension));
        profile[17] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.RESTORATION, IRuleModuleIdentity(extension));
        profile[18] =
            AVACoreRulePackageRegistry.ModuleBinding(AVACapabilityKeys.VALUE_EXECUTION, IRuleModuleIdentity(extension));
    }
}
