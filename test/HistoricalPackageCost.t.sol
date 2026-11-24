// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {DecisionSetFixture, JointDecisionPolicy} from "./DecisionSet.t.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

/// @notice Real Core historical support; setup and transaction intrinsic gas are excluded.
contract HistoricalPackageCostTest is DecisionSetFixture {
    uint256 private genericId;
    uint256 private executionId;
    uint256 private sourcePackage;
    uint256 private nextTransition;
    bytes32 private originalStates;
    IAVARequestPolicy.WitnessInput[] private retainedPool;

    event log_named_uint(string key, uint256 value);

    function setUp() public override {
        super.setUp();
        IAVADecisionPolicy.Request memory input = _input(keccak256("historical pair cost"));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 2);
        sourcePackage = requestPackageId;
        retainedPool.push(pool[0]);
        retainedPool.push(pool[1]);
        originalStates = _states();
        nextTransition = kernel.nextTransitionId();
        _install(new JointDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        input.packageId = requestPackageId;
        genericId = _open(input, pool);
        requestVm.prank(SOURCE_ACTOR);
        executionId = requestAllocation.createDecisionRequestForPackage(
            genericId,
            input.packageId,
            _executionInput(input, pool, PARAMETERS),
            pool,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE)
        );
    }

    function testHistoricalPairResolvesAndExecutesOneLegalEffect() public {
        AVARequestSupport support = requestAllocation.SUPPORT();
        uint256 beforeGas = gasleft();
        (IAVARequestPolicy.RequestContext memory context, IAVARequestPolicy.Witness[] memory resolved) =
            support.resolve(executionId);
        uint256 resolveGas = beforeGas - gasleft();
        emit log_named_uint("historical pair resolve call gas", resolveGas);
        require(resolveGas <= 425_000, "historical pair resolution exceeds 425k call gas");
        require(context.packageId == requestPackageId && context.packageId != sourcePackage, "receiver missing");
        require(resolved.length == 2, "historical pair truncated");
        require(resolved[0].packageId == sourcePackage && resolved[1].packageId == sourcePackage, "source rewritten");

        beforeGas = gasleft();
        support.validateSupport(executionId);
        emit log_named_uint("historical pair warmed validateSupport call gas", beforeGas - gasleft());
        require(requestAllocation.getRequest(executionId).allocator == address(0), "support granted authority");
        beforeGas = gasleft();
        uint256 decisionId = _choose(genericId, POSITIVE, executionId, 0);
        emit log_named_uint("historical pair warmed choose call gas", beforeGas - gasleft());
        require(registry.getDecision(decisionId).witness.length == 2, "decision subset changed");
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionId);
        require(completed.consumed && completed.completed && completed.effectHash != bytes32(0), "effect incomplete");
        require(completed.creator == SOURCE_ACTOR && completed.allocator == ALLOCATOR_ACTOR, "actor history lost");
        require(kernel.nextTransitionId() == nextTransition && _states() == originalStates, "recognition changed");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == keccak256(abi.encode(completed)),
            "replay changed history"
        );
    }

    function _states() private view returns (bytes32) {
        return keccak256(
            abi.encode(
                kernel.getRecognisedState(retainedPool[0].recognisedStateId),
                kernel.getRecognisedState(retainedPool[1].recognisedStateId)
            )
        );
    }
}

contract HistoricalDistinctPackageTest is DecisionSetFixture {
    function testDistinctHistoricalPackageLossRejectsThenRestoredExecutionPreservesHistory() public {
        IAVADecisionPolicy.Request memory input = _input(keccak256("two distinct historical packages"));
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](2);
        pool[0] = _scopedState(scope);
        uint256 firstPackage = requestPackageId;
        application = new M14PermissiveApplicationModule(APP);
        _install(new JointDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        pool[1] = _scopedState(scope);
        uint256 secondPackage = requestPackageId;
        address secondApplication = address(application);
        application = new M14PermissiveApplicationModule(APP);
        _install(new JointDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        input.packageId = requestPackageId;
        uint256 id = _open(input, pool);
        requestVm.prank(SOURCE_ACTOR);
        uint256 executionId = requestAllocation.createDecisionRequestForPackage(
            id, input.packageId, _executionInput(input, pool, PARAMETERS), pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        _choose(id, POSITIVE, executionId, 0);
        bytes32 requestBefore = keccak256(abi.encode(requestAllocation.getRequest(executionId)));
        bytes32 historyBefore = keccak256(
            abi.encode(
                kernel.getRecognisedState(pool[0].recognisedStateId),
                kernel.getRecognisedState(pool[1].recognisedStateId),
                registry.getRequest(id)
            )
        );
        bytes memory code = secondApplication.code;
        AVARequestSupport support = requestAllocation.SUPPORT();
        requestVm.etch(secondApplication, hex"00");
        requestVm.expectRevert();
        support.resolve(executionId);
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == requestBefore,
            "invalid second source changed approval"
        );
        requestVm.etch(secondApplication, code);
        (, IAVARequestPolicy.Witness[] memory resolved) = support.resolve(executionId);
        require(
            resolved[0].packageId == firstPackage && resolved[1].packageId == secondPackage,
            "historical source identity rewritten"
        );
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "restored source could not execute");
        require(
            keccak256(
                abi.encode(
                    kernel.getRecognisedState(pool[0].recognisedStateId),
                    kernel.getRecognisedState(pool[1].recognisedStateId),
                    registry.getRequest(id)
                )
            ) == historyBefore,
            "recognition or selection history changed"
        );
    }
}
