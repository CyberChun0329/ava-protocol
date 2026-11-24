// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAGovernanceKernel} from "./AVAGovernanceKernel.sol";
import {AVACorrectionRegistry} from "./AVACorrectionRegistry.sol";

/// @notice Constructor-only creation code; CREATE retains the Kernel's context.
library AVACorrectionDeployment {
    function deploy(AVAGovernanceKernel host) external returns (AVACorrectionRegistry) {
        return new AVACorrectionRegistry(host);
    }
}
