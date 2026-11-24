// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVAAllocationPolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {IAVADecisionRegistry} from "../src/extensions/decisions/IAVADecisionRegistry.sol";
import {DecisionSetFixture, DecisionExecutor} from "./DecisionSet.t.sol";

interface CrossVersionVm {
    function expectRevert(bytes calldata revertData) external;
}

/// @notice A receiving rule may retain historical witnesses and independently veto the response.
contract CrossVersionReceivingPolicy is IAVARequestPolicy, IAVAAllocationPolicyModule, RuleModuleIdentity {
    address public immutable DECISION_REGISTRY;
    uint256 public immutable SOURCE_PACKAGE;
    uint256 public immutable VETO;
    error ReceivingVeto(uint256 gate);

    constructor(address registry, uint256 sourcePackage, uint256 veto) {
        DECISION_REGISTRY = registry;
        SOURCE_PACKAGE = sourcePackage;
        VETO = veto;
    }

    function validateResponseSupport(RequestContext calldata context, Witness[] calldata witness) external view {
        _support(context, witness);
    }

    function validateRequestAllocation(
        RequestContext calldata context,
        Witness[] calldata witness,
        DecisionContext calldata decision
    ) external view {
        _support(context, witness);
        if (VETO == 2) revert ReceivingVeto(2);
        IAVADecisionRegistry(DECISION_REGISTRY).validateExecutionDecision(context, decision);
    }

    function validateAllocation(AllocationPolicyContext calldata context) external view {
        require(context.units == 1 && context.record.packageId != SOURCE_PACKAGE, "receiving allocation context");
        if (VETO == 1) revert ReceivingVeto(1);
    }

    function _support(RequestContext calldata context, Witness[] calldata witness) private view {
        require(!context.exactCommitment && context.packageId != SOURCE_PACKAGE, "receiving package");
        require(witness.length == 1 && witness[0].packageId == SOURCE_PACKAGE, "source package rewritten");
        IAVADecisionRegistry(DECISION_REGISTRY).validateExecutionSupport(context, witness);
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(DECISION_REGISTRY, SOURCE_PACKAGE, VETO));
    }
}

contract CrossVersionRelianceTest is DecisionSetFixture {
    CrossVersionVm private constant crossVm = CrossVersionVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testHistoricalSupportReceivesNewDecisionChoosesAndActuallyExecutes() public {
        IAVADecisionPolicy.Request memory oldInput = _input("retained historical request");
        IAVARequestPolicy.WitnessInput[] memory oldPool = _pool(oldInput, 1);
        uint256 oldRequest = _open(oldInput, oldPool);
        uint256 oldExecution = _execution(oldInput, oldPool, PARAMETERS);
        uint256 oldDecision = _choose(oldRequest, POSITIVE, oldExecution, 0);
        IAVADecisionPolicy.Request memory input = _input("receiving historical support");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 sourcePackage = requestPackageId;
        uint256 sourceTransition = pool[0].transitionId;
        _installReceiving(new CrossVersionReceivingPolicy(address(registry), sourcePackage, 0));
        input.packageId = requestPackageId;
        input.executor = address(new DecisionExecutor());
        uint256 id = _open(input, pool);
        uint256 executionId = _receivingExecution(id, input, pool);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        DecisionExecutor(input.executor).execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "actual execution not completed");
        require(requestAllocation.getRequest(executionId).packageId == requestPackageId, "receiving package lost");
        require(registry.getDecision(decisionId).witness[0].packageId == sourcePackage, "decision source rewritten");
        require(
            kernel.getRecognisedStateReference(pool[0].recognisedStateId).lastTransitionId == sourceTransition,
            "source transitioned"
        );
        require(registry.getDecision(oldDecision).executionRequestId == oldExecution, "old decision rewritten");
        require(requestAllocation.getRequest(oldExecution).packageId == sourcePackage, "old request package rewritten");
        require(requestAllocation.getRequest(oldExecution).allocator == ALLOCATOR_ACTOR, "old approval erased");
    }

    function testReceivingAllocationPolicyCanVetoHistoricalSupport() public {
        _receivingVeto(1);
    }

    function testReceivingTypedPolicyCanVetoHistoricalSupport() public {
        _receivingVeto(2);
    }

    function testHistoricalSourceLossCannotBeBypassedByReceivingPackage() public {
        IAVADecisionPolicy.Request memory input = _input("stale historical source");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        _installReceiving(new CrossVersionReceivingPolicy(address(registry), requestPackageId, 0));
        input.packageId = requestPackageId;
        uint256 id = _open(input, pool);
        uint256 executionId = _receivingExecution(id, input, pool);
        _choose(id, POSITIVE, executionId, 0);
        _change(
            pool[0].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(_d(id).length == 0, "stale source admitted by receiver");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(!requestAllocation.getRequest(executionId).consumed, "stale source consumed");
    }

    function _receivingVeto(uint256 gate) private {
        IAVADecisionPolicy.Request memory input = _input(keccak256(abi.encode("receiver veto", gate)));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        _installReceiving(new CrossVersionReceivingPolicy(address(registry), requestPackageId, gate));
        input.packageId = requestPackageId;
        uint256 id = _open(input, pool);
        uint256 executionId = _receivingExecution(id, input, pool);
        require(_d(id).length == 1, "support improperly removed");
        crossVm.expectRevert(abi.encodeWithSelector(CrossVersionReceivingPolicy.ReceivingVeto.selector, gate));
        requestVm.prank(ALLOCATOR_ACTOR);
        registry.choose(id, POSITIVE, executionId, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON);
        require(registry.getRequest(id).lastDecisionId == 0, "failed choice retained");
        require(requestAllocation.getRequest(executionId).allocator == address(0), "veto granted approval");
    }

    function _receivingExecution(
        uint256 id,
        IAVADecisionPolicy.Request memory input,
        IAVARequestPolicy.WitnessInput[] memory pool
    ) private returns (uint256) {
        requestVm.prank(SOURCE_ACTOR);
        return requestAllocation.createDecisionRequestForPackage(
            id, input.packageId, _executionInput(input, pool, PARAMETERS), pool, ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
    }

    function _installReceiving(CrossVersionReceivingPolicy receiving) private {
        AVACoreRulePackageRegistry.ModuleBinding[] memory base = _coreBindings(application);
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = new AVACoreRulePackageRegistry.ModuleBinding[](20);
        for (uint256 i; i < base.length; ++i) {
            bindings[i] = base[i];
        }
        bindings[9] = _coreBinding(AVACapabilityKeys.ALLOCATION, address(receiving));
        bindings[19] = _coreBinding(AVACapabilityKeys.DECISION_SET, address(policy));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                ++version,
                keccak256("request.compatibility"),
                "test:receiving"
            ),
            requestPackageId,
            bindings
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
    }
}
