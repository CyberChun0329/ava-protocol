// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";

contract RequestPackageVerificationTest is DecisionSetFixture {
    function testSamePackageIdentityIsRecheckedAndRestoredExecutionCompletes() public {
        _identityFailureThenRecovery(false);
    }

    function testHistoricalSourcePackageIdentityIsRecheckedAndRestoredExecutionCompletes() public {
        _identityFailureThenRecovery(true);
    }

    function _identityFailureThenRecovery(bool historicalSource) private {
        IAVADecisionPolicy.Request memory input =
            _input(keccak256(abi.encode("package verification", historicalSource)));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 sourcePackageId = requestPackageId;
        address sourcePolicy = address(policy);
        bytes memory originalCode = sourcePolicy.code;
        if (historicalSource) {
            _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
            input.packageId = requestPackageId;
        }
        uint256 id = _open(input, pool);
        uint256 nextRequest = requestAllocation.nextRequestId();
        AVARequestAllocation.RequestInput memory executionInput = _executionInput(input, pool, PARAMETERS);
        requestVm.etch(sourcePolicy, hex"00");
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.createDecisionRequestForPackage(
            id, requestPackageId, executionInput, pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        require(requestAllocation.nextRequestId() == nextRequest, "failed creation reserved a request");
        requestVm.etch(sourcePolicy, originalCode);
        requestVm.prank(SOURCE_ACTOR);
        uint256 executionId = requestAllocation.createDecisionRequestForPackage(
            id, requestPackageId, executionInput, pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        require(
            registry.getDecision(decisionId).witness[0].packageId == sourcePackageId, "source package was substituted"
        );
        require(requestAllocation.getRequest(executionId).packageId == requestPackageId, "receiving package changed");
        AVARequestSupport support = requestAllocation.SUPPORT();
        (IAVARequestPolicy.RequestContext memory context, IAVARequestPolicy.Witness[] memory resolved) =
            support.resolve(executionId);
        require(context.packageId == requestPackageId && context.requestId == executionId, "resolution context changed");
        require(
            resolved.length == 1 && resolved[0].packageId == sourcePackageId
                && resolved[0].recognisedStateId == pool[0].recognisedStateId
                && resolved[0].transitionId == pool[0].transitionId,
            "resolved historical witness changed"
        );
        bytes32 resolvedBefore = keccak256(abi.encode(resolved));
        bytes32 requestBefore = keccak256(abi.encode(requestAllocation.getRequest(executionId)));
        bytes32 decisionBefore = keccak256(abi.encode(registry.getDecision(decisionId)));
        bytes32 stateBefore = keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId)));
        bytes32 transitionBefore = keccak256(abi.encode(kernel.getRecognisedStateTransition(pool[0].transitionId)));
        uint256 nextTransition = kernel.nextTransitionId();

        requestVm.etch(sourcePolicy, hex"00");
        requestVm.expectRevert();
        support.resolve(executionId);
        requestVm.expectRevert();
        requestAllocation.validateExecution(executionId, RESPONSE, PARAMETERS, address(executor));
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == requestBefore,
            "failed verification changed the request"
        );

        requestVm.etch(sourcePolicy, originalCode);
        (, IAVARequestPolicy.Witness[] memory restored) = support.resolve(executionId);
        require(keccak256(abi.encode(restored)) == resolvedBefore, "restored public resolution changed");
        require(
            requestAllocation.validateExecution(executionId, RESPONSE, PARAMETERS, address(executor)),
            "restored identity did not recover"
        );
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionId);
        require(completed.consumed && completed.completed, "legal execution incomplete");
        require(completed.effectHash == keccak256(abi.encode("decision effect", executionId)), "effect lost");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == keccak256(abi.encode(completed)),
            "replay changed execution history"
        );
        require(keccak256(abi.encode(registry.getDecision(decisionId))) == decisionBefore, "decision changed");
        require(
            keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId))) == stateBefore,
            "recognition changed"
        );
        require(
            keccak256(abi.encode(kernel.getRecognisedStateTransition(pool[0].transitionId))) == transitionBefore,
            "source occurrence changed"
        );
        require(kernel.nextTransitionId() == nextTransition, "execution created a recognition");
    }
}
