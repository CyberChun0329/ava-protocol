// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;
import {IRuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

interface IAVARuleGovernance is IRuleModuleIdentity {
    function RULE_PACKAGE_REGISTRY() external view returns (address);
    function validateGovernanceEnrollment(bytes32 appId, bytes32 workflowKey, uint256 packageId) external view;
    function validateRuleRevision(bytes32 commitment) external view;
}
