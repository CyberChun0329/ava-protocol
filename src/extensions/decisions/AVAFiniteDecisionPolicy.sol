// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {IAVADecisionPolicy} from "../../core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

/// @notice A closed, immutable decision catalogue for one application's declared workflow.
/// @dev Applications with joint, non-monotone or capacity rules override the predicates/resolver.
contract AVAFiniteDecisionPolicy is IAVADecisionPolicy, RuleModuleIdentity {
    bytes32 public immutable APP_ID;
    bytes32 public immutable WORKFLOW_KEY;
    bytes32 public immutable CONFIGURATION_HASH;
    Option[] private options;

    constructor(bytes32 appId, bytes32 workflowKey, Option[] memory catalogue_) {
        if (appId == bytes32(0) || workflowKey == bytes32(0)) revert AVACoreTypes.EmptyValue();
        APP_ID = appId;
        WORKFLOW_KEY = workflowKey;
        CONFIGURATION_HASH = keccak256(abi.encode(appId, workflowKey, catalogue_));
        for (uint256 i; i < catalogue_.length; ++i) {
            options.push(catalogue_[i]);
        }
    }

    function catalogue(Request calldata) external view virtual returns (Option[] memory) {
        return options;
    }

    function ruleValid(Request calldata request, uint64) external view virtual returns (bool) {
        return request.appId == APP_ID && request.workflowKey == WORKFLOW_KEY;
    }

    function allocationAllowed(Request calldata, Process calldata, Actor calldata, Option calldata)
        external
        view
        virtual
        returns (bool)
    {
        return true;
    }

    function witnessFor(Request calldata request, Option calldata, IAVARequestPolicy.Witness[] calldata eligible)
        external
        view
        virtual
        returns (uint256[] memory indices)
    {
        // One matching recognition is the concrete sufficient witness for this basic domain.
        for (uint256 i; i < eligible.length; ++i) {
            IAVARequestPolicy.RecognitionScope calldata scope = eligible[i].scope;
            if (
                scope.claimHash == request.requestHash && scope.useHash == request.responseClass
                    && scope.burdenHash == request.burdenHash
            ) {
                indices = new uint256[](1);
                indices[0] = i;
                return indices;
            }
        }
        return new uint256[](0);
    }

    function _moduleConfigurationHash() internal view virtual override returns (bytes32) {
        return CONFIGURATION_HASH;
    }
}
