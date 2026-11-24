// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVARequestSupport} from "../src/extensions/requests/AVARequestSupport.sol";
import {AVARecognitionDependencies} from "../src/core/AVARecognitionDependencies.sol";
import {AVABoundRequestPolicy} from "../src/extensions/requests/AVABoundRequestPolicy.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAAllocationRecordExtension} from "../src/extensions/downstream/AVADownstreamRecordExtensions.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";

interface RecognitionDependenciesVm {
    function mockCall(address callee, bytes calldata data, bytes calldata returnData) external;
    function mockCallRevert(address callee, bytes calldata data, bytes calldata revertData) external;
    function clearMockedCalls() external;
}

abstract contract RecognitionDependenciesFixture is DecisionSetFixture {
    function _single(IAVARequestPolicy.WitnessInput memory item)
        internal
        pure
        returns (IAVARequestPolicy.WitnessInput[] memory result)
    {
        result = new IAVARequestPolicy.WitnessInput[](1);
        result[0] = item;
    }

    function _dependent(
        IAVARequestPolicy.WitnessInput memory source,
        IAVADecisionPolicy.Request memory input,
        bytes32 label
    ) internal returns (IAVARequestPolicy.WitnessInput memory) {
        AVACoreTypes.SourceOccurrence[] memory deps = _deps(source);
        uint256 objectId = _registerDependent(deps, input, label);
        return _recognise(objectId, input);
    }

    function _registerDependent(
        AVACoreTypes.SourceOccurrence[] memory deps,
        IAVADecisionPolicy.Request memory input,
        bytes32 label
    ) internal returns (uint256 objectId) {
        return _registerDependent(deps, input, label, bytes32(0));
    }

    function _registerDependent(
        AVACoreTypes.SourceOccurrence[] memory deps,
        IAVADecisionPolicy.Request memory input,
        bytes32 label,
        bytes32 exactCommitment
    ) internal returns (uint256 objectId) {
        requestVm.startPrank(SOURCE_ACTOR);
        bytes32 commitment = exactCommitment == bytes32(0)
            ? keccak256(abi.encode(label, evidenceRegistry.nextEvidenceId()))
            : exactCommitment;
        uint256 evidence = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: _authority(ROLE_SOURCE),
                commitment: commitment,
                evidenceTypeHash: keccak256("dependent evidence"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:dependent-evidence"
            })
        );
        AVAGovernanceKernel.GovernedObjectInput memory objectInput = AVAGovernanceKernel.GovernedObjectInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: requestPackageId,
            roleKey: ROLE_SOURCE,
            objectTypeKey: OBJECT,
            objectCommitment: commitment,
            parentObjectId: 0,
            subjectId: _authority(ROLE_SOURCE),
            evidenceReceiptId: evidence,
            disclosurePolicyId: requestPolicyId,
            metadataHash: requestAllocation.recognitionScopeHash(
                IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash)
            ),
            authorityId: _authority(ROLE_SOURCE),
            uri: "test:dependent-object"
        });
        objectId = deps.length == 0
            ? kernel.registerGovernedObject(objectInput)
            : kernel.registerGovernedObjectWithDependencies(objectInput, deps);
        requestVm.stopPrank();
    }

    function _deps(IAVARequestPolicy.WitnessInput memory item)
        internal
        pure
        returns (AVACoreTypes.SourceOccurrence[] memory result)
    {
        result = new AVACoreTypes.SourceOccurrence[](1);
        result[0] = AVACoreTypes.SourceOccurrence(item.recognisedStateId, item.transitionId);
    }

    function _installExactPolicy() internal {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _coreBindings(application);
        bindings[9] = _coreBinding(
            AVACapabilityKeys.ALLOCATION,
            address(
                new AVABoundRequestPolicy(
                    address(requestAllocation), APP, REQUEST_WORKFLOW, address(executor), RESPONSE, BURDEN
                )
            )
        );
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                ++version,
                keccak256("request.compatibility"),
                "test:exact-dependencies"
            ),
            requestPackageId,
            bindings
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
    }

    function _recognise(uint256 objectId, IAVADecisionPolicy.Request memory input)
        internal
        returns (IAVARequestPolicy.WitnessInput memory)
    {
        requestVm.startPrank(VERIFIER_ACTOR);
        uint256 state = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: REASON,
                reasonURI: "test:dependent-recognition"
            })
        );
        kernel.transitionRecognisedState(_transitionInput(state, AVACoreTypes.RecognisedStateStatus.Challengeable));
        kernel.vestRecognisedState(_transitionInput(state, AVACoreTypes.RecognisedStateStatus.Vested));
        requestVm.stopPrank();
        return IAVARequestPolicy.WitnessInput(
            state,
            kernel.getRecognisedStateReference(state).lastTransitionId,
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash)
        );
    }
}

contract RecognitionDependenciesTest is RecognitionDependenciesFixture {
    function testLaterSamePackageEvidenceFailurePropagatesAndRepairRestoresTraversal() public {
        IAVADecisionPolicy.Request memory input = _input("later evidence failure");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput memory b = _dependent(a, input, "later evidence B");
        IAVARequestPolicy.WitnessInput memory c = _dependent(b, input, "later evidence C");
        uint256 root = kernel.getRecognisedStateReference(c.recognisedStateId).governedObjectId;
        uint256 evidenceId = kernel.getRecognisedStateReference(a.recognisedStateId).evidenceReceiptId;
        bytes memory failure = abi.encodeWithSignature("Error(string)", "later evidence failure");
        RecognitionDependenciesVm vm = RecognitionDependenciesVm(address(requestVm));
        vm.mockCallRevert(
            address(evidenceRegistry),
            abi.encodeCall(evidenceRegistry.isEvidenceAvailableForPackage, (evidenceId, requestPackageId)),
            failure
        );
        (bool ok, bytes memory result) =
            address(kernel.DEPENDENCIES()).staticcall(abi.encodeCall(kernel.DEPENDENCIES().dependenciesCurrent, (root)));
        require(!ok && keccak256(result) == keccak256(failure), "later evidence failure hidden");
        vm.clearMockedCalls();
        require(kernel.DEPENDENCIES().dependenciesCurrent(root), "repaired evidence did not recover");
        IAVARequestPolicy.WitnessInput[] memory pool = _single(c);
        uint256 requestId = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        _choose(requestId, POSITIVE, executionId, 0);
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(requestAllocation.getRequest(executionId).completed, "repaired support did not complete");
    }

    function testHistoricalTransitionPackageIsIndependentlyVerifiedAndRecovers() public {
        IAVADecisionPolicy.Request memory input = _input("historical transition package");
        IAVARequestPolicy.WitnessInput memory source = _pool(input, 1)[0];
        uint256 sourcePackage = requestPackageId;
        _change(
            source.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        uint256 decisionPackage = requestPackageId;
        IAVARequestPolicy.WitnessInput memory decisionEvidence = _pool(input, 1)[0];
        AVAGovernanceKernel.RecognisedStateReference memory state =
            kernel.getRecognisedStateReference(source.recognisedStateId);
        transitionRequester.change(
            kernel,
            AVAGovernanceKernel.SourceBoundTransitionInput({
                recognisedStateId: source.recognisedStateId,
                expectedTransitionId: state.lastTransitionId,
                decisionPackageId: decisionPackage,
                sourceRecordId: 1,
                decisionEvidenceReceiptId: kernel.getRecognisedStateReference(decisionEvidence.recognisedStateId)
                .evidenceReceiptId,
                disclosureTargetId: state.governedObjectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                actionKey: AVACoreTypes.ACTION_APPLY_RESTORATION,
                decisionHash: keccak256("historical restoration"),
                toStatus: AVACoreTypes.RecognisedStateStatus.Restored,
                kind: AVACoreTypes.TransitionKind.Restoration,
                reasonHash: REASON,
                reasonURI: "test:historical-restoration"
            })
        );
        source.transitionId = kernel.getRecognisedStateReference(source.recognisedStateId).lastTransitionId;
        require(
            kernel.getRecognisedStateTransitionReference(source.transitionId).decisionPackageId == decisionPackage
                && sourcePackage != decisionPackage,
            "transition package not distinct"
        );
        IAVARequestPolicy.WitnessInput memory child = _dependent(source, input, "historical child");
        IAVARequestPolicy.WitnessInput memory grandchild = _dependent(child, input, "historical grandchild");
        uint256 childObject = kernel.getRecognisedStateReference(child.recognisedStateId).governedObjectId;
        uint256 root = kernel.getRecognisedStateReference(grandchild.recognisedStateId).governedObjectId;
        require(kernel.DEPENDENCIES().dependenciesCurrent(root), "mixed package traversal failed");
        RecognitionDependenciesVm vm = RecognitionDependenciesVm(address(requestVm));
        vm.mockCall(address(policy), abi.encodeWithSignature("moduleIdentityHash()"), abi.encode(bytes32(uint256(1))));
        (bool ok, bytes memory result) = address(kernel.DEPENDENCIES())
            .staticcall(abi.encodeCall(kernel.DEPENDENCIES().dependenciesCurrent, (childObject)));
        require(
            !ok
                && keccak256(result)
                    == keccak256(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, decisionPackage)),
            "decision package identity failure hidden"
        );
        vm.clearMockedCalls();
        require(kernel.DEPENDENCIES().dependenciesCurrent(root), "repaired decision package did not recover");
    }

    function testDenseSharedClosureUsesItsTwentyEightEdgesAndPreservesCorrection() public {
        IAVADecisionPolicy.Request memory input = _input("dense shared closure");
        IAVARequestPolicy.WitnessInput[] memory nodes = new IAVARequestPolicy.WitnessInput[](8);
        nodes[0] = _pool(input, 1)[0];
        for (uint256 i = 1; i < nodes.length; ++i) {
            AVACoreTypes.SourceOccurrence[] memory deps = new AVACoreTypes.SourceOccurrence[](i);
            for (uint256 j; j < i; ++j) {
                deps[j] = AVACoreTypes.SourceOccurrence(nodes[j].recognisedStateId, nodes[j].transitionId);
            }
            uint256 objectId = _registerDependent(deps, input, bytes32(i));
            nodes[i] = _recognise(objectId, input);
        }
        uint256 root = kernel.getRecognisedStateReference(nodes[7].recognisedStateId).governedObjectId;
        require(kernel.DEPENDENCIES().dependenciesCurrent(root), "28-edge closure rejected");
        require(kernel.DEPENDENCIES().getDependencies(root).length == 7, "direct pins lost");
        _change(
            nodes[0].recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(!kernel.DEPENDENCIES().dependenciesCurrent(root), "shared ancestor correction ignored");
        require(
            kernel.getRecognisedStateReference(nodes[7].recognisedStateId).lastTransitionId == nodes[7].transitionId,
            "dependency correction rewrote descendant history"
        );
    }

    function testLegacyAllocationCannotBypassLostAncestorAndKeepsEarlierRecord() public {
        IAVADecisionPolicy.Request memory input = _input("legacy dependency use");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput memory b = _dependent(a, input, "legacy B");
        AVAAllocationRecordExtension records = new AVAAllocationRecordExtension(
            kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry
        );
        AVAAllocationRecordExtension.AllocationInput memory allocation = AVAAllocationRecordExtension.AllocationInput(
            b.recognisedStateId,
            ROLE_ALLOCATOR,
            _authority(ROLE_ALLOCATOR),
            _authority(ROLE_SOURCE),
            kernel.getRecognisedStateReference(b.recognisedStateId).evidenceReceiptId,
            RESPONSE,
            1,
            REASON,
            "test:legacy"
        );
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 recordId = records.recordAllocation(allocation);
        _change(
            a.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        records.recordAllocation(allocation);
        require(records.nextAllocationId() == recordId + 1, "ineligible record partly appended");
        require(
            records.getAllocation(recordId).recognisedStateTransitionId == b.transitionId,
            "ancestor correction erased prior allocation"
        );
    }

    function testIndependentSupportSurvivesUnrelatedAncestorCorrection() public {
        IAVADecisionPolicy.Request memory input = _input("independent");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        IAVARequestPolicy.WitnessInput memory other = _pool(_input("other ancestor"), 1)[0];
        _change(
            other.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(_d(id).length == 1, "independent support lost");
        require(
            kernel.DEPENDENCIES()
            .getDependencies(kernel.getRecognisedStateReference(pool[0].recognisedStateId).governedObjectId)
            .length == 0,
            "independent object acquired dependencies"
        );
    }

    function testFormationAfterAncestorLossIsDenied() public {
        IAVADecisionPolicy.Request memory input = _input("formation dependency");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        AVACoreTypes.SourceOccurrence[] memory deps = _deps(a);
        uint256 objectId = _registerDependent(deps, input, "unformed");
        _change(
            a.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: REASON,
                reasonURI: "test:loss-before-formation"
            })
        );
    }

    function testDiamondRetainsEachPinAndRejectsAncestorLoss() public {
        IAVADecisionPolicy.Request memory input = _input("diamond");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput memory b = _dependent(a, input, "left");
        IAVARequestPolicy.WitnessInput memory c = _dependent(a, input, "right");
        AVACoreTypes.SourceOccurrence[] memory deps = new AVACoreTypes.SourceOccurrence[](2);
        deps[0] = AVACoreTypes.SourceOccurrence(b.recognisedStateId, b.transitionId);
        deps[1] = AVACoreTypes.SourceOccurrence(c.recognisedStateId, c.transitionId);
        uint256 objectId = _registerDependent(deps, input, "diamond root");
        _recognise(objectId, input);
        require(kernel.DEPENDENCIES().dependenciesCurrent(objectId), "diamond failed");
        require(kernel.DEPENDENCIES().getDependencies(objectId).length == 2, "pins not retained");
        _change(
            a.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(!kernel.DEPENDENCIES().dependenciesCurrent(objectId), "diamond ancestor lost");
    }

    function testDependencyRegistrationRejectsDuplicatesMismatchedPinsAndOversizedSet() public {
        IAVADecisionPolicy.Request memory input = _input("invalid dependencies");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput memory b = _pool(input, 1)[0];
        AVACoreTypes.SourceOccurrence[] memory deps = new AVACoreTypes.SourceOccurrence[](2);
        deps[0] = AVACoreTypes.SourceOccurrence(a.recognisedStateId, a.transitionId);
        deps[1] = deps[0];
        requestVm.expectRevert();
        this.registerForTest(deps, input);
        requestVm.stopPrank();
        deps = _deps(a);
        deps[0].transitionId = b.transitionId;
        requestVm.expectRevert();
        this.registerForTest(deps, input);
        requestVm.stopPrank();
        deps = new AVACoreTypes.SourceOccurrence[](17);
        requestVm.expectRevert();
        this.registerForTest(deps, input);
        requestVm.stopPrank();
        uint256 objectId = kernel.getRecognisedStateReference(a.recognisedStateId).governedObjectId;
        AVARecognitionDependencies dependencyRegistry = kernel.DEPENDENCIES();
        requestVm.expectRevert();
        dependencyRegistry.bind(objectId, _deps(b));

        uint256 boundObject = _registerDependent(_deps(a), input, "bound once");
        requestVm.prank(address(kernel));
        requestVm.expectRevert();
        dependencyRegistry.bind(boundObject, _deps(b));
        AVACoreTypes.SourceOccurrence[] memory recorded = dependencyRegistry.getDependencies(boundObject);
        require(keccak256(abi.encode(recorded)) == keccak256(abi.encode(_deps(a))), "source overwritten");
    }

    function testTraversalBudgetRejectsTheFirstOverBudgetChain() public {
        IAVADecisionPolicy.Request memory input = _input("bounded chain");
        IAVARequestPolicy.WitnessInput memory tip = _pool(input, 1)[0];
        for (uint256 i; i < 64; ++i) {
            tip = _dependent(tip, input, bytes32(i + 1));
        }
        uint256 objectId = kernel.getRecognisedStateReference(tip.recognisedStateId).governedObjectId;
        require(kernel.DEPENDENCIES().dependenciesCurrent(objectId), "budget boundary rejected");
        requestVm.expectRevert();
        this.registerForTest(_deps(tip), input);
        requestVm.stopPrank();
    }

    function testExactRequestAlsoRejectsAncestorLoss() public {
        _installExactPolicy();
        IAVADecisionPolicy.Request memory input = _input("exact dependency");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        bytes32 commitment =
            requestAllocation.commitmentFor(APP, address(executor), RESPONSE, PARAMETERS, BURDEN, input.validUntil);
        uint256 objectId = _registerDependent(_deps(a), input, "exact", commitment);
        IAVARequestPolicy.WitnessInput memory b = _recognise(objectId, input);
        uint256 id = _createRequest(_executionInput(input, _single(b), PARAMETERS));
        _approveRequest(id);
        _change(
            a.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(requestAllocation.SUPPORT().occurrenceChanged(id), "exact occurrence unchanged");
        AVARequestSupport support = requestAllocation.SUPPORT();
        requestVm.expectRevert();
        support.resolve(id);
        requestVm.expectRevert();
        executor.execute(requestAllocation, id, RESPONSE, PARAMETERS);
    }

    function registerForTest(AVACoreTypes.SourceOccurrence[] memory deps, IAVADecisionPolicy.Request memory input)
        external
        returns (uint256)
    {
        return _registerDependent(deps, input, "rejected candidate");
    }

    function testAncestorCorrectionExcludesBOnlySupportWithoutRewritingDescendants() public {
        IAVADecisionPolicy.Request memory input = _input("dependency-chain");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput memory b = _dependent(a, input, "B");
        IAVARequestPolicy.WitnessInput memory c = _dependent(b, input, "C");
        IAVARequestPolicy.WitnessInput[] memory pool = _single(c);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS);
        _choose(id, POSITIVE, executionId, 0);
        uint256 cObject = kernel.getRecognisedStateReference(c.recognisedStateId).governedObjectId;
        require(kernel.DEPENDENCIES().dependenciesCurrent(cObject), "current chain rejected");
        _change(
            a.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(!kernel.DEPENDENCIES().dependenciesCurrent(cObject), "ancestor loss ignored");
        require(kernel.DEPENDENCIES().dependenciesChanged(cObject), "successor loss missing");
        require(registry.getEligibleWitnesses(id).length == 0 && _d(id).length == 0, "dependent support retained");
        AVARequestSupport support = requestAllocation.SUPPORT();
        requestVm.expectRevert();
        support.resolve(executionId);
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            kernel.getRecognisedStateReference(c.recognisedStateId).lastTransitionId == c.transitionId,
            "descendant history changed"
        );
        _change(
            a.recognisedStateId, AVACoreTypes.RecognisedStateStatus.Restored, AVACoreTypes.TransitionKind.Restoration
        );
        require(!kernel.DEPENDENCIES().dependenciesCurrent(cObject), "new occurrence silently substituted");
        require(requestAllocation.getRequest(executionId).allocator == ALLOCATOR_ACTOR, "approval erased");
    }

    function testBOnlyScopedWitnessCannotHideItsAncestor() public {
        IAVADecisionPolicy.Request memory input = _input("B-only dependency");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput memory b = _dependent(a, input, "B");
        uint256 id = _open(input, _single(b));
        uint256 executionId = _execution(input, _single(b), PARAMETERS);
        require(_d(id).length == 1, "initial B-only support missing");
        _change(
            a.recognisedStateId,
            AVACoreTypes.RecognisedStateStatus.Downgraded,
            AVACoreTypes.TransitionKind.ChallengeCorrection
        );
        require(_d(id).length == 0, "B-only ancestor omitted");
        AVARequestSupport support = requestAllocation.SUPPORT();
        requestVm.expectRevert();
        support.resolve(executionId);
    }

    function testKnownAncestorEvidenceLossIsAnExclusionAndModuleFailurePropagates() public {
        IAVADecisionPolicy.Request memory input = _input("ancestor evidence");
        IAVARequestPolicy.WitnessInput memory a = _pool(input, 1)[0];
        IAVARequestPolicy.WitnessInput memory b = _dependent(a, input, "B");
        uint256 objectId = kernel.getRecognisedStateReference(b.recognisedStateId).governedObjectId;
        uint256 evidenceId = kernel.getRecognisedStateReference(a.recognisedStateId).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidenceId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            REASON,
            "test:ancestor-revoked"
        );
        AVARecognitionDependencies dependencyRegistry = kernel.DEPENDENCIES();
        require(!dependencyRegistry.dependenciesCurrent(objectId), "inactive evidence remained support");
        requestVm.etch(address(policy), hex"00");
        requestVm.expectRevert();
        dependencyRegistry.dependenciesCurrent(objectId);
    }
}
