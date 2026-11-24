// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {AVARequestSupport} from "./AVARequestSupport.sol";

/// @notice Linked creation code used by the allocation constructor.
/// @dev Solidity's library delegatecall keeps CREATE in the allocation's context, so the
/// helper's immutable owner is the allocation itself. No later binding step is needed.
library AVARequestSupportDeployment {
    function deploy(AVAGovernanceKernel kernel, address executionHelper, AVARequestSupport.HostComponents memory host)
        external
        returns (AVARequestSupport)
    {
        return new AVARequestSupport(kernel, executionHelper, host);
    }
}
