// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVARecognisedDecisionPolicy} from "../src/extensions/decisions/AVARecognisedDecisionPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";
import {UnselectedFailurePolicy} from "./DecisionEfficiency.t.sol";

contract DecisionSupportCostTest is DecisionSetFixture {
    uint256 private genericRequestId;
    uint256 private executionRequestId;
    IAVARequestPolicy.WitnessInput private source;
    bytes32 private sourceBefore;
    uint256 private nextTransitionBefore;

    event log_named_uint(string key, uint256 value);

    function setUp() public override {
        super.setUp();
        IAVADecisionPolicy.Request memory input = _input(keccak256("decision support cost"));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        genericRequestId = _open(input, pool);
        executionRequestId = _execution(input, pool, PARAMETERS);
        source = pool[0];
        sourceBefore = keccak256(abi.encode(kernel.getRecognisedState(source.recognisedStateId)));
        nextTransitionBefore = kernel.nextTransitionId();
    }

    function testSelectedDecisionValidatesBelow391kAndExecutesOnce() public {
        // Public-call costs exclude setup and transaction intrinsic gas. Validation is
        // deliberately warmed, matching the existing representative diagnostic.
        uint256 beforeGas = gasleft();
        uint256 decisionId = _choose(genericRequestId, POSITIVE, executionRequestId, 0);
        emit log_named_uint("choose call gas", beforeGas - gasleft());
        AVADecisionRegistry.DecisionRecord memory choice = registry.getDecision(decisionId);
        require(choice.actor == ALLOCATOR_ACTOR && choice.roleKey == ROLE_ALLOCATOR, "wrong decision actor");
        require(choice.authorityId == _authority(ROLE_ALLOCATOR), "wrong decision authority");
        require(choice.option.key == POSITIVE && choice.executionRequestId == executionRequestId, "wrong choice");
        require(choice.witness.length == 1, "witness changed");
        require(
            choice.witness[0].recognisedStateId == source.recognisedStateId
                && choice.witness[0].transitionId == source.transitionId
                && keccak256(abi.encode(choice.witness[0].scope)) == keccak256(abi.encode(source.scope)),
            "selected witness changed"
        );

        require(
            requestAllocation.validateExecution(executionRequestId, RESPONSE, PARAMETERS, address(executor)),
            "selected decision invalid"
        );
        beforeGas = gasleft();
        require(
            requestAllocation.validateExecution(executionRequestId, RESPONSE, PARAMETERS, address(executor)),
            "selected decision invalid on repeat"
        );
        uint256 validationGas = beforeGas - gasleft();
        emit log_named_uint("repeated warm validate call gas", validationGas);
        require(validationGas < 391_000, "selected decision validation exceeds measured 391k call budget");

        executor.execute(requestAllocation, executionRequestId, RESPONSE, PARAMETERS);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionRequestId);
        require(completed.consumed && completed.completed && completed.allocator == ALLOCATOR_ACTOR, "effect missing");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionRequestId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == keccak256(abi.encode(completed)),
            "replay changed effect history"
        );
        require(
            keccak256(abi.encode(kernel.getRecognisedState(source.recognisedStateId))) == sourceBefore
                && kernel.nextTransitionId() == nextTransitionBefore,
            "decision or execution rewrote recognition"
        );
    }

    function testBothPolicyCallbacksKeepCallerAndContextBinding() public {
        _choose(genericRequestId, POSITIVE, executionRequestId, 0);
        (IAVARequestPolicy.RequestContext memory context, IAVARequestPolicy.Witness[] memory witness) =
            requestAllocation.SUPPORT().resolve(executionRequestId);
        IAVARequestPolicy.DecisionContext memory decision = IAVARequestPolicy.DecisionContext(
            ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), ALLOCATOR_ACTOR, uint64(block.timestamp)
        );
        for (uint256 i; i < 2; ++i) {
            address caller = i == 0 ? address(requestAllocation) : address(requestAllocation.SUPPORT());
            requestVm.prank(caller);
            bridge.validateResponseSupport(context, witness);
            requestVm.prank(caller);
            bridge.validateRequestAllocation(context, witness, decision);
        }

        requestVm.expectRevert(AVARecognisedDecisionPolicy.InvalidDecisionBinding.selector);
        bridge.validateResponseSupport(context, witness);
        requestVm.expectRevert(AVARecognisedDecisionPolicy.InvalidDecisionBinding.selector);
        bridge.validateRequestAllocation(context, witness, decision);

        context.requestAllocation = address(0xBAD);
        requestVm.prank(address(requestAllocation));
        requestVm.expectRevert(AVARecognisedDecisionPolicy.InvalidDecisionBinding.selector);
        bridge.validateResponseSupport(context, witness);
        requestVm.prank(address(requestAllocation));
        requestVm.expectRevert(AVARecognisedDecisionPolicy.InvalidDecisionBinding.selector);
        bridge.validateRequestAllocation(context, witness, decision);
        context.requestAllocation = address(requestAllocation);

        context.appId = keccak256("foreign decision context");
        requestVm.prank(address(requestAllocation.SUPPORT()));
        requestVm.expectRevert();
        bridge.validateResponseSupport(context, witness);
        requestVm.prank(address(requestAllocation.SUPPORT()));
        requestVm.expectRevert();
        bridge.validateRequestAllocation(context, witness, decision);
        context.appId = APP;

        decision.actor = SOURCE_ACTOR;
        requestVm.prank(address(requestAllocation.SUPPORT()));
        requestVm.expectRevert();
        bridge.validateRequestAllocation(context, witness, decision);
        decision.actor = ALLOCATOR_ACTOR;
        decision.evaluatedAt++;
        requestVm.prank(address(requestAllocation.SUPPORT()));
        requestVm.expectRevert(AVARecognisedDecisionPolicy.InvalidDecisionBinding.selector);
        bridge.validateRequestAllocation(context, witness, decision);

        executor.execute(requestAllocation, executionRequestId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionRequestId).completed, "legal execution rejected");
    }

    function testRevokedAllocationPermissionRejectsChoiceAndConsumptionThenRecovers() public {
        uint256 nextDecision = registry.nextDecisionId();
        bytes32 pendingBefore = keccak256(abi.encode(requestAllocation.getRequest(executionRequestId)));
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.expectRevert();
        _choose(genericRequestId, POSITIVE, executionRequestId, 0);
        require(registry.nextDecisionId() == nextDecision, "revoked choice reserved a decision");
        require(registry.getRequest(genericRequestId).lastDecisionId == 0, "revoked choice changed history");
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == pendingBefore,
            "revoked choice approved execution"
        );

        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        uint256 decisionId = _choose(genericRequestId, POSITIVE, executionRequestId, 0);
        bytes32 choiceBefore = keccak256(abi.encode(registry.getDecision(decisionId)));
        bytes32 approvedBefore = keccak256(abi.encode(requestAllocation.getRequest(executionRequestId)));
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.expectRevert();
        requestAllocation.validateExecution(executionRequestId, RESPONSE, PARAMETERS, address(executor));
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionRequestId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(registry.getDecision(decisionId))) == choiceBefore
                && keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == approvedBefore,
            "revoked consumption changed approval or choice"
        );

        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        executor.execute(requestAllocation, executionRequestId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionRequestId).completed, "restored permission could not execute");
        require(keccak256(abi.encode(registry.getDecision(decisionId))) == choiceBefore, "execution rewrote choice");
        require(
            keccak256(abi.encode(kernel.getRecognisedState(source.recognisedStateId))) == sourceBefore,
            "permission recovery rewrote recognition"
        );
    }

    function testUnselectedResolverFailureAfterApprovalRejectsConsumptionThenRecovers() public {
        // setUp already has a pending execution; this separate scenario needs
        // a distinct substantive meaning rather than only a new request label.
        bytes32 parameters = keccak256("unselected resolver recovery execution");
        IAVADecisionPolicy.Option[] memory options = _options(2, false, 0);
        options[0].parametersHash = parameters;
        UnselectedFailurePolicy selected =
            new UnselectedFailurePolicy(APP, REQUEST_WORKFLOW, options, address(registry), ALLOCATOR_ACTOR);
        _install(selected);
        IAVADecisionPolicy.Request memory input = _input(keccak256("post-approval unselected resolver failure"));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, parameters);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        bytes32 choiceBefore = keccak256(abi.encode(registry.getDecision(decisionId)));
        bytes32 approvedBefore = keccak256(abi.encode(requestAllocation.getRequest(executionId)));
        bytes32 recognitionBefore = keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId)));

        selected.setBroken(true);
        requestVm.expectRevert(UnselectedFailurePolicy.ResolverUnavailable.selector);
        requestAllocation.validateExecution(executionId, RESPONSE, parameters, address(executor));
        requestVm.expectRevert(UnselectedFailurePolicy.ResolverUnavailable.selector);
        executor.execute(requestAllocation, executionId, RESPONSE, parameters);
        require(
            keccak256(abi.encode(registry.getDecision(decisionId))) == choiceBefore
                && keccak256(abi.encode(requestAllocation.getRequest(executionId))) == approvedBefore,
            "resolver failure changed approval or choice"
        );

        selected.setBroken(false);
        executor.execute(requestAllocation, executionId, RESPONSE, parameters);
        require(requestAllocation.getRequest(executionId).completed, "restored resolver could not execute");
        require(keccak256(abi.encode(registry.getDecision(decisionId))) == choiceBefore, "execution rewrote choice");
        require(
            keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId))) == recognitionBefore,
            "resolver recovery rewrote recognition"
        );
    }
}
