// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVADecisionWitnessValidation} from "../src/extensions/decisions/AVADecisionWitnessValidation.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";

/// @dev A live technical failure on an unselected option must veto the whole evaluation.
contract UnselectedFailurePolicy is AVAFiniteDecisionPolicy {
    address private immutable REGISTRY;
    address private immutable ALLOCATOR;
    bytes32 private immutable FAILING_KEY;
    bool public broken;
    bool public alternativeDenied;
    error ResolverUnavailable();

    constructor(bytes32 app, bytes32 workflow, Option[] memory options, address registry, address allocator)
        AVAFiniteDecisionPolicy(app, workflow, options)
    {
        REGISTRY = registry;
        ALLOCATOR = allocator;
        FAILING_KEY = options[1].key;
    }

    function setBroken(bool value) external {
        broken = value;
    }

    function setAlternativeDenied(bool value) external {
        alternativeDenied = value;
    }

    function allocationAllowed(Request calldata, Process calldata, Actor calldata actor, Option calldata option)
        external
        view
        override
        returns (bool)
    {
        require(msg.sender == REGISTRY, "decision policy caller changed");
        return actor.account == ALLOCATOR && actor.evaluatedAt == block.timestamp
            && (!alternativeDenied || option.key != FAILING_KEY);
    }

    function witnessFor(Request calldata request, Option calldata option, IAVARequestPolicy.Witness[] calldata eligible)
        external
        view
        override
        returns (uint256[] memory indices)
    {
        require(msg.sender == REGISTRY, "resolver caller changed");
        if (broken && option.key == FAILING_KEY) revert ResolverUnavailable();
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

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(CONFIGURATION_HASH, REGISTRY, ALLOCATOR, FAILING_KEY));
    }
}

/// @dev A permitted pre-write selection can still be vetoed at the approval checkpoint.
contract PostWriteVetoPolicy is AVAFiniteDecisionPolicy {
    constructor(bytes32 app, bytes32 workflow, Option[] memory options)
        AVAFiniteDecisionPolicy(app, workflow, options)
    {}

    function allocationAllowed(Request calldata, Process calldata process, Actor calldata, Option calldata)
        external
        pure
        override
        returns (bool)
    {
        return process.allocationDecisionId == 0;
    }
}

contract DecisionEfficiencyTest is DecisionSetFixture {
    function testMixedCatalogueRechecksEachActionAcrossCallsThenExecutesOnce() public {
        UnselectedFailurePolicy policy = new UnselectedFailurePolicy(
            APP, REQUEST_WORKFLOW, _options(2, true, 0), address(registry), ALLOCATOR_ACTOR
        );
        _install(policy);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, PROCEDURE_ACTION, true);
        IAVADecisionPolicy.Request memory input = _input(keccak256("mixed catalogue current authority"));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        bytes32 sourceBefore = keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId)));
        uint256 nextTransition = kernel.nextTransitionId();
        uint256 nextDecision = registry.nextDecisionId();

        policy.setAlternativeDenied(true);
        IAVADecisionPolicy.Option[] memory options = _d(id);
        require(
            options.length == 2 && options[0].key == POSITIVE && options[1].key == PROCEDURE, "option policy skipped"
        );
        policy.setAlternativeDenied(false);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        options = _d(id);
        require(options.length == 1 && options[0].key == PROCEDURE, "allocation permission leaked into procedure");
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(id, POSITIVE, executionId, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        require(registry.nextDecisionId() == nextDecision, "refusal wrote decision");
        require(requestAllocation.getRequest(executionId).allocator == address(0), "refusal allocated execution");

        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        require(_d(id).length == 3, "old refusal cached across calls");
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, PROCEDURE_ACTION, false);
        options = _d(id);
        require(options.length == 2 && options[0].key == POSITIVE && options[1].key == ALTERNATIVE, "action isolation");
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        require(registry.getDecision(decisionId).actor == ALLOCATOR_ACTOR, "actor changed");
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "legal continuation blocked");
        require(kernel.nextTransitionId() == nextTransition, "execution formed recognition");
        require(
            keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId))) == sourceBefore,
            "recognition history changed"
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
    }

    function testUnselectedResolverFailureRejectsThenLegalChoiceStillExecutes() public {
        UnselectedFailurePolicy selected = new UnselectedFailurePolicy(
            APP, REQUEST_WORKFLOW, _options(2, false, 0), address(registry), ALLOCATOR_ACTOR
        );
        _install(selected);
        IAVADecisionPolicy.Request memory input = _input(keccak256("complete evaluation after transient error"));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        bytes32 sourceBefore = keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId)));
        uint256 nextDecision = registry.nextDecisionId();
        selected.setBroken(true);
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert(UnselectedFailurePolicy.ResolverUnavailable.selector);
        registry.choose(id, POSITIVE, executionId, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        require(registry.nextDecisionId() == nextDecision && registry.getRequest(id).lastDecisionId == 0);
        require(requestAllocation.getRequest(executionId).allocator == address(0), "rejection approved execution");
        selected.setBroken(false);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        AVADecisionRegistry.DecisionRecord memory choice = registry.getDecision(decisionId);
        require(choice.actor == ALLOCATOR_ACTOR && choice.option.key == POSITIVE && choice.witness.length == 1);
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "legal retry failed");
        require(
            keccak256(abi.encode(kernel.getRecognisedState(pool[0].recognisedStateId))) == sourceBefore,
            "decision or execution rewrote recognition"
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
    }

    function testApprovalRechecksPostWritePolicyAndRollsBackChoice() public {
        _install(new PostWriteVetoPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        IAVADecisionPolicy.Request memory input = _input("post-write approval veto");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        require(_d(id).length == 1, "pre-write decision should be permitted");
        bytes32 requestBefore = keccak256(abi.encode(requestAllocation.getRequest(executionId)));
        uint256 nextDecision = registry.nextDecisionId();
        uint256 nextTransition = kernel.nextTransitionId();
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(id, POSITIVE, executionId, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        require(registry.nextDecisionId() == nextDecision, "failed approval reserved decision");
        require(registry.getRequest(id).allocationDecisionId == 0 && registry.getRequest(id).lastDecisionId == 0);
        require(keccak256(abi.encode(requestAllocation.getRequest(executionId))) == requestBefore);
        require(kernel.nextTransitionId() == nextTransition && _d(id).length == 1);
    }

    function testDecisionRuntimeLeavesAtLeastOneKiBOfHeadroom() public view {
        require(address(registry).code.length <= 24_576 - 1_024, "decision runtime lacks 1 KiB headroom");
    }

    function testMissingWitnessLibraryCannotProducePartialDecisionSetOrApproval() public {
        IAVADecisionPolicy.Request memory input = _input(keccak256("missing witness validation library"));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        uint256 nextDecision = registry.nextDecisionId();
        requestVm.etch(address(AVADecisionWitnessValidation), hex"");
        requestVm.expectRevert();
        registry.getAdmissibleDecisions(id, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(id, POSITIVE, executionId, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        require(registry.nextDecisionId() == nextDecision && registry.getRequest(id).lastDecisionId == 0);
        require(requestAllocation.getRequest(executionId).allocator == address(0));
    }
}
