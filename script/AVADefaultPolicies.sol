// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {DefaultAVACorePolicyBundle} from "../src/core/modules/DefaultAVACoreRuleModules.sol";
import {DefaultAVAExtensionPolicyModule} from "../src/extensions/shared/DefaultAVAExtensionPolicyModule.sol";

/// @notice Deployment-only verification of the two stateless defaults compiled with this project.
/// @dev Exact runtime includes their module identity implementation. App-bound policies are excluded.
library AVADefaultPolicies {
    error InvalidDefaultPolicies(address corePolicy, address extensionPolicy);

    function requireExact(DefaultAVACorePolicyBundle corePolicy, DefaultAVAExtensionPolicyModule extensionPolicy)
        internal
        view
    {
        if (
            address(corePolicy).codehash != keccak256(type(DefaultAVACorePolicyBundle).runtimeCode)
                || address(extensionPolicy).codehash != keccak256(type(DefaultAVAExtensionPolicyModule).runtimeCode)
        ) revert InvalidDefaultPolicies(address(corePolicy), address(extensionPolicy));
    }
}
