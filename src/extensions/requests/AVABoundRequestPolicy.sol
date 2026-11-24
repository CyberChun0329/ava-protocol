// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {DefaultCoreAllocationPolicyModule} from "../../core/modules/DefaultAVACoreRuleModules.sol";

/// @notice Exact-request policy for one configured app response and burden.
/// @dev The extension supplies canonical source/decision context and enforces actor authority.
contract AVABoundRequestPolicy is DefaultCoreAllocationPolicyModule {
    address public immutable REQUEST_ALLOCATION;
    bytes32 public immutable APP_ID;
    bytes32 public immutable WORKFLOW_KEY;
    address public immutable EXECUTOR;
    bytes32 public immutable RESPONSE_CLASS;
    bytes32 public immutable BURDEN_HASH;

    constructor(
        address requestAllocation,
        bytes32 appId,
        bytes32 workflowKey,
        address executor,
        bytes32 responseClass,
        bytes32 burdenHash
    ) {
        if (
            requestAllocation.code.length == 0 || appId == bytes32(0) || workflowKey == bytes32(0)
                || executor.code.length == 0 || responseClass == bytes32(0) || burdenHash == bytes32(0)
        ) revert InvalidRequestPolicyContext(0);
        REQUEST_ALLOCATION = requestAllocation;
        APP_ID = appId;
        WORKFLOW_KEY = workflowKey;
        EXECUTOR = executor;
        RESPONSE_CLASS = responseClass;
        BURDEN_HASH = burdenHash;
    }

    function _validateResponseSupport(RequestContext calldata request, Witness[] calldata witness)
        internal
        view
        override
    {
        if (
            request.requestAllocation != REQUEST_ALLOCATION || request.appId != APP_ID
                || request.workflowKey != WORKFLOW_KEY || request.executor != EXECUTOR
                || request.responseClass != RESPONSE_CLASS || request.burdenHash != BURDEN_HASH
        ) revert InvalidRequestPolicyContext(request.requestId);
        super._validateResponseSupport(request, witness);
    }

    function validateAllocation(AllocationPolicyContext calldata context) external view override {
        if (
            context.record.appId != APP_ID || context.record.workflowKey != WORKFLOW_KEY
                || context.record.recordTypeKey != RESPONSE_CLASS
        ) revert InvalidRequestPolicyContext(context.record.recognisedStateId);
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(REQUEST_ALLOCATION, APP_ID, WORKFLOW_KEY, EXECUTOR, RESPONSE_CLASS, BURDEN_HASH));
    }
}
