// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";

/// @notice Real-Core request creation cost; fixture setup and transaction intrinsic gas excluded.
contract RequestSupportGasTest is DecisionSetFixture {
    IAVADecisionPolicy.Request private input;
    IAVARequestPolicy.WitnessInput[] private pool;
    uint256 private genericId;

    event log_named_uint(string key, uint256 value);

    function setUp() public override {
        super.setUp();
        input = _input(keccak256("support creation gas"));
        IAVARequestPolicy.WitnessInput[] memory prepared = _pool(input, 1);
        pool.push(prepared[0]);
        genericId = _open(input, prepared);
    }

    function testCreationCostAndSupportStillPermitOneLegalEffect() public {
        bytes memory data = abi.encodeCall(
            requestAllocation.createDecisionRequest,
            (genericId, _executionInput(input, pool, PARAMETERS), pool, ROLE_SOURCE, _authority(ROLE_SOURCE))
        );
        requestVm.prank(SOURCE_ACTOR);
        uint256 beforeGas = gasleft();
        (bool success, bytes memory result) = address(requestAllocation).call(data);
        uint256 creationGas = beforeGas - gasleft();
        require(success, "legal creation rejected");
        uint256 executionId = abi.decode(result, (uint256));
        emit log_named_uint("createDecisionRequest call gas", creationGas);
        emit log_named_uint("createDecisionRequest calldata bytes", data.length);
        require(creationGas <= 1_345_000, "representative creation exceeds 1.345m call gas");
        AVARequestSupport support = requestAllocation.SUPPORT();
        beforeGas = gasleft();
        support.validateSupport(executionId);
        emit log_named_uint("subsequent validateSupport call gas", beforeGas - gasleft());

        uint256 nextTransition = kernel.nextTransitionId();
        bytes32 originalState = keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId)));
        require(requestAllocation.getRequest(executionId).allocator == address(0), "support assigned authority");
        _choose(genericId, POSITIVE, executionId, 0);
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionId);
        require(completed.consumed && completed.completed, "effect incomplete");
        require(completed.creator == SOURCE_ACTOR && completed.allocator == ALLOCATOR_ACTOR, "actor history lost");
        require(kernel.nextTransitionId() == nextTransition, "execution formed a recognition");
        require(
            keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId))) == originalState,
            "recognition changed"
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == keccak256(abi.encode(completed)),
            "replay changed history"
        );
    }
}
