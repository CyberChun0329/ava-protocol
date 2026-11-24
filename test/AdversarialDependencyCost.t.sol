// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVARecognitionDependencies} from "../src/core/AVARecognitionDependencies.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {RecognitionDependenciesFixture} from "./RecognitionDependencies.t.sol";

/// @notice Public real-Core calls, with deterministic graphs created entirely in setUp.
/// @dev Call-gas deltas exclude setup, logs and transaction intrinsic gas. The first
/// dependency call has no explicit warm-up; obtaining the helper and history counters
/// has touched Kernel. It is not claimed to be a completely cold transaction. The
/// second call is explicitly warmed. Formation follows both reads and source-history
/// snapshots, so its metric is deliberately warm. No cache survives these calls.
contract AdversarialDependencyCostTest is RecognitionDependenciesFixture {
    uint256 private noDependencyRoot;
    uint256 private singletonRoot;
    uint256 private chainRoot;
    uint256 private diamondRoot;
    uint256 private denseRoot;
    uint256 private fanoutRoot;

    event log_named_uint(string key, uint256 value);
    event log_named_bytes32(string key, bytes32 value);

    function setUp() public override {
        super.setUp();
        IAVADecisionPolicy.Request memory input = _input(keccak256("adversarial dependency cost"));
        noDependencyRoot = _registerDependent(new AVACoreTypes.SourceOccurrence[](0), input, "independent");
        IAVARequestPolicy.WitnessInput memory single = _pool(input, 1)[0];
        singletonRoot = _registerDependent(_deps(single), input, "singleton");
        chainRoot = _chain(input, 8);
        diamondRoot = _diamond(input);
        denseRoot = _dense(input, 8);
        IAVARequestPolicy.WitnessInput[] memory fanout = _pool(input, 16);
        fanoutRoot = _registerDependent(_occurrences(fanout, 16), input, "fanout16");
    }

    function testAdversarialCostNoDependencies() public {
        _measure("none", noDependencyRoot, 0, 0, 0);
    }

    function testAdversarialCostSingleton() public {
        _measure("singleton", singletonRoot, 1, 1, 1);
    }

    function testAdversarialCostDistinctChain8() public {
        _measure("chain8", chainRoot, 8, 8, 1);
    }

    function testAdversarialCostSharedDiamond() public {
        _measure("diamond", diamondRoot, 4, 3, 2);
    }

    function testAdversarialCostDense8() public {
        _measure("dense8", denseRoot, 28, 7, 7);
    }

    function testAdversarialCostDistinctFanout16() public {
        _measure("fanout16", fanoutRoot, 16, 16, 16);
    }

    function testAdversarialDependencyRestorationKeepsExactOldPinIneligible() public {
        IAVADecisionPolicy.Request memory input = _input(keccak256("adversarial exact occurrence"));
        IAVARequestPolicy.WitnessInput memory source = _pool(input, 1)[0];
        uint256 oldRoot = _registerDependent(_deps(source), input, "old pin");
        uint256 oldTransition = source.transitionId;
        bytes32 transitionHistory = keccak256(abi.encode(kernel.getRecognisedStateTransition(oldTransition)));
        _change(
            source.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        _change(
            source.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Restored,
            AVACoreTypes.TransitionKind.Restoration
        );
        source.transitionId = kernel.getRecognisedStateReference(source.recognisedStateId).lastTransitionId;
        require(source.transitionId != oldTransition, "restoration reused occurrence");
        uint256 freshRoot = _registerDependent(_deps(source), input, "fresh pin");
        require(!kernel.DEPENDENCIES().dependenciesCurrent(oldRoot), "old occurrence silently substituted");
        require(kernel.DEPENDENCIES().dependenciesCurrent(freshRoot), "fresh restored pin excluded");
        require(kernel.DEPENDENCIES().getDependencies(oldRoot)[0].transitionId == oldTransition, "pin rewritten");
        require(
            keccak256(abi.encode(kernel.getRecognisedStateTransition(oldTransition))) == transitionHistory,
            "old transition rewritten"
        );
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        kernel.formRecognisedState(_formation(oldRoot));
        requestVm.prank(VERIFIER_ACTOR);
        uint256 freshState = kernel.formRecognisedState(_formation(freshRoot));
        require(kernel.getRecognisedStateReference(freshState).governedObjectId == freshRoot, "fresh formation lost");
    }

    function testAdversarialDependencyKnownLossCannotHideLaterBranchFailure() public {
        IAVADecisionPolicy.Request memory input = _input(keccak256("adversarial mixed branches"));
        IAVARequestPolicy.WitnessInput[] memory sources = new IAVARequestPolicy.WitnessInput[](2);
        sources[0] = _pool(input, 1)[0];
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        input.packageId = requestPackageId;
        sources[1] = _pool(input, 1)[0];
        uint256 root = _registerDependent(_occurrences(sources, 2), input, "mixed branches");
        uint256 filingEvidence = kernel.getRecognisedStateReference(sources[0].recognisedStateId).evidenceReceiptId;
        bytes32 sourceHistory = _recognitionHash(kernel.nextRecognisedStateId());
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            filingEvidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            REASON,
            "test:adversarial-revoke"
        );
        require(!kernel.DEPENDENCIES().dependenciesCurrent(root), "known loss remained eligible");
        bytes memory originalPolicy = address(policy).code;
        requestVm.etch(address(policy), hex"00");
        AVARecognitionDependencies dependencies = kernel.DEPENDENCIES();
        requestVm.expectRevert();
        dependencies.dependenciesCurrent(root);
        requestVm.etch(address(policy), originalPolicy);
        require(!dependencies.dependenciesCurrent(root), "technical recovery erased known loss");
        require(_recognitionHash(kernel.nextRecognisedStateId()) == sourceHistory, "source history rewritten");
        uint256 healthyRoot = _registerDependent(_deps(sources[1]), input, "independent healthy branch");
        requestVm.prank(VERIFIER_ACTOR);
        uint256 healthyState = kernel.formRecognisedState(_formation(healthyRoot));
        require(kernel.getRecognisedStateReference(healthyState).governedObjectId == healthyRoot, "healthy path lost");
    }

    function _measure(string memory shape, uint256 root, uint256 edges, uint256 uniqueSources, uint256 direct)
        private
    {
        AVARecognitionDependencies dependencies = kernel.DEPENDENCIES();
        uint256 nextState = kernel.nextRecognisedStateId();
        uint256 nextTransition = kernel.nextTransitionId();
        bytes memory dependencyInput = abi.encodeCall(AVARecognitionDependencies.dependenciesCurrent, (root));
        uint256 beforeGas = gasleft();
        bool eligible = dependencies.dependenciesCurrent(root);
        uint256 firstGas = beforeGas - gasleft();
        require(eligible, "legal graph excluded");
        beforeGas = gasleft();
        eligible = dependencies.dependenciesCurrent(root);
        uint256 warmGas = beforeGas - gasleft();
        require(eligible, "repeat changed eligibility");
        require(dependencies.getDependencies(root).length == direct, "wrong direct dependency count");
        require(kernel.nextRecognisedStateId() == nextState && kernel.nextTransitionId() == nextTransition);
        emit log_named_uint(string.concat(shape, " closure edges"), edges);
        emit log_named_uint(string.concat(shape, " unique pinned sources"), uniqueSources);
        emit log_named_uint(string.concat(shape, " dependenciesCurrent calldata bytes"), dependencyInput.length);
        emit log_named_bytes32(string.concat(shape, " dependenciesCurrent calldata hash"), keccak256(dependencyInput));
        emit log_named_uint(string.concat(shape, " first dependenciesCurrent call gas"), firstGas);
        emit log_named_uint(string.concat(shape, " repeated warm dependenciesCurrent call gas"), warmGas);
        if (edges == 4 && uniqueSources == 3) require(warmGas < 269_200, "shared diamond cost not reduced");
        if (edges == 28 && uniqueSources == 7) require(warmGas < 1_907_768, "dense shared closure cost not reduced");

        bytes32 history = _recognitionHash(nextState);
        AVAGovernanceKernel.RecognisedStateFormationInput memory formation = _formation(root);
        bytes memory formationInput = abi.encodeCall(AVAGovernanceKernel.formRecognisedState, (formation));
        requestVm.prank(VERIFIER_ACTOR);
        beforeGas = gasleft();
        uint256 formed = kernel.formRecognisedState(formation);
        uint256 formationGas = beforeGas - gasleft();
        emit log_named_uint(string.concat(shape, " warm formation call gas"), formationGas);
        emit log_named_uint(string.concat(shape, " formation calldata bytes"), formationInput.length);
        emit log_named_bytes32(string.concat(shape, " formation calldata hash"), keccak256(formationInput));
        AVACoreTypes.RecognisedStateRecord memory state = kernel.getRecognisedState(formed);
        require(
            formed == nextState && state.governedObjectId == root && state.createdBy == VERIFIER_ACTOR
                && state.authorityId == _authority(ROLE_VERIFIER) && state.stage == AVACoreTypes.Stage.Verification
                && state.status == AVACoreTypes.RecognisedStateStatus.Provisional,
            "formation changed actor or recognised meaning"
        );
        require(kernel.nextTransitionId() == nextTransition + 1 && _recognitionHash(nextState) == history);
    }

    function _chain(IAVADecisionPolicy.Request memory input, uint256 edges) private returns (uint256) {
        IAVARequestPolicy.WitnessInput memory tip = _pool(input, 1)[0];
        for (uint256 i = 1; i < edges; ++i) {
            tip = _dependent(tip, input, bytes32(i));
        }
        return _registerDependent(_deps(tip), input, "chain root");
    }

    function _diamond(IAVADecisionPolicy.Request memory input) private returns (uint256) {
        IAVARequestPolicy.WitnessInput memory ancestor = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput[] memory branches = new IAVARequestPolicy.WitnessInput[](2);
        branches[0] = _dependent(ancestor, input, "diamond left");
        branches[1] = _dependent(ancestor, input, "diamond right");
        return _registerDependent(_occurrences(branches, 2), input, "diamond root");
    }

    function _dense(IAVADecisionPolicy.Request memory input, uint256 nodes) private returns (uint256) {
        IAVARequestPolicy.WitnessInput[] memory sources = new IAVARequestPolicy.WitnessInput[](nodes - 1);
        sources[0] = _pool(input, 1)[0];
        for (uint256 i = 1; i < sources.length; ++i) {
            uint256 objectId = _registerDependent(_occurrences(sources, i), input, bytes32(i));
            sources[i] = _recognise(objectId, input);
        }
        return _registerDependent(_occurrences(sources, sources.length), input, "dense root");
    }

    function _occurrences(IAVARequestPolicy.WitnessInput[] memory sources, uint256 length)
        private
        pure
        returns (AVACoreTypes.SourceOccurrence[] memory result)
    {
        result = new AVACoreTypes.SourceOccurrence[](length);
        for (uint256 i; i < length; ++i) {
            result[i] = AVACoreTypes.SourceOccurrence(sources[i].recognisedStateId, sources[i].transitionId);
        }
    }

    function _formation(uint256 root)
        private
        view
        returns (AVAGovernanceKernel.RecognisedStateFormationInput memory)
    {
        return AVAGovernanceKernel.RecognisedStateFormationInput(
            root,
            ROLE_VERIFIER,
            _authority(ROLE_VERIFIER),
            AVACoreTypes.Stage.Verification,
            AVACoreTypes.RecognisedStateStatus.Provisional,
            REASON,
            "test:adversarial-cost-formation"
        );
    }

    function _recognitionHash(uint256 limit) private view returns (bytes32 hash) {
        for (uint256 id = 1; id < limit; ++id) {
            hash = keccak256(abi.encode(hash, kernel.getRecognisedState(id)));
        }
    }
}
