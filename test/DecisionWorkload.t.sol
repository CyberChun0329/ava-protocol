// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";
import {GasAllWitnessDecisionPolicy} from "./DecisionGasBudget.t.sol";

interface DecisionWorkloadVm {
    function envOr(string calldata name, uint256 defaultValue) external returns (uint256);
    function pauseGasMetering() external;
    function resumeGasMetering() external;
}

/// @notice Parameterised public-call diagnostics, with a tiny default for the normal suite.
/// @dev Independent chains contain pool * (depth + 1) objects and pool * depth edges.
/// Setup, assertions and transaction intrinsic gas are excluded from the call measurements.
/// Calls share a test transaction, with accesses warmed by setup/assertions and earlier calls.
/// These are not cold Base transaction estimates or a Base gas-limit guarantee.
contract DecisionWorkloadTest is DecisionSetFixture {
    uint256 private constant CALL_GAS_BUDGET = 16_000_000;
    uint256 private poolSize;
    uint256 private optionCount;
    uint256 private dependencyDepth;
    uint256 private genericRequestId;
    uint256 private executionRequestId;
    uint256 private nextObjectBefore;
    uint256 private nextStateBefore;
    uint256 private nextTransitionBefore;
    bytes32 private recognitionBefore;
    IAVARequestPolicy.WitnessInput[] private declaredPool;
    uint256 private sourcePackageCount;

    event log_named_uint(string key, uint256 value);

    function setUp() public override {
        DecisionWorkloadVm vm = DecisionWorkloadVm(address(requestVm));
        poolSize = vm.envOr("AVA_WORKLOAD_POOL", uint256(1));
        optionCount = vm.envOr("AVA_WORKLOAD_OPTIONS", uint256(1));
        dependencyDepth = vm.envOr("AVA_WORKLOAD_DEPTH", uint256(0));
        sourcePackageCount = vm.envOr("AVA_WORKLOAD_SOURCE_PACKAGES", uint256(1));
        require(poolSize == 1 || poolSize == 4 || poolSize == 8 || poolSize == 16, "unsupported workload pool");
        require(optionCount == 1 || optionCount == 8 || optionCount == 32, "unsupported workload options");
        require(dependencyDepth == 0 || dependencyDepth == 8 || dependencyDepth == 16, "unsupported workload depth");
        require(
            sourcePackageCount != 0 && sourcePackageCount <= poolSize && poolSize % sourcePackageCount == 0,
            "source packages must divide the declared pool"
        );
        vm.pauseGasMetering();
        super.setUp();
        _install(new GasAllWitnessDecisionPolicy(APP, REQUEST_WORKFLOW, _workloadOptions(), poolSize));
        IAVADecisionPolicy.Request memory input = _input(keccak256("decision workload"));
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](poolSize);
        uint256 firstObject = kernel.nextGovernedObjectId();
        for (uint256 i; i < poolSize; ++i) {
            if (i != 0 && i % (poolSize / sourcePackageCount) == 0) {
                _install(new GasAllWitnessDecisionPolicy(APP, REQUEST_WORKFLOW, _workloadOptions(), poolSize));
            }
            pool[i] = _scopedState(_scope(input));
            for (uint256 j; j < dependencyDepth; ++j) {
                pool[i] = _dependent(input, pool[i]);
            }
            declaredPool.push(pool[i]);
        }
        input.packageId = requestPackageId;
        require(kernel.nextGovernedObjectId() - firstObject == poolSize * (dependencyDepth + 1), "wrong shape");
        genericRequestId = _open(input, pool);
        requestVm.prank(SOURCE_ACTOR);
        executionRequestId = requestAllocation.createDecisionRequestForPackage(
            genericRequestId,
            input.packageId,
            _executionInput(input, pool, PARAMETERS),
            pool,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE)
        );
        nextObjectBefore = kernel.nextGovernedObjectId();
        nextStateBefore = kernel.nextRecognisedStateId();
        nextTransitionBefore = kernel.nextTransitionId();
        recognitionBefore = _recognitionHash();
        vm.resumeGasMetering();
    }

    function testPublicDecisionWorkload() public {
        emit log_named_uint("workload pool", poolSize);
        emit log_named_uint("workload options", optionCount);
        emit log_named_uint("workload depth", dependencyDepth);
        emit log_named_uint("workload source packages", sourcePackageCount);
        emit log_named_uint("workload objects", poolSize * (dependencyDepth + 1));
        emit log_named_uint("workload dependency edges", poolSize * dependencyDepth);
        emit log_named_uint("workload local call gas budget", CALL_GAS_BUDGET);

        bytes32 requestBefore = keccak256(abi.encode(registry.getRequest(genericRequestId)));
        bytes32 executionBefore = keccak256(abi.encode(requestAllocation.getRequest(executionRequestId)));
        bytes32 supportBefore = keccak256(abi.encode(registry.getSupportRevision(genericRequestId, 1)));
        uint256 nextDecision = registry.nextDecisionId();
        uint256 nextRequest = registry.nextRequestId();
        uint256 nextExecution = requestAllocation.nextRequestId();
        (bool chosen, uint256 decisionId, uint256 chooseGas, uint256 revertBytes) =
            _budgetedChoose(genericRequestId, executionRequestId);
        emit log_named_uint("workload choose gas", chooseGas);
        emit log_named_uint("workload choose success", chosen ? 1 : 0);
        emit log_named_uint("workload choose revert bytes", revertBytes);
        bool target = poolSize == 4 && optionCount == 8 && dependencyDepth == 8 && sourcePackageCount == 1;
        if (target) require(chosen, "4/8/8 choice exceeds call budget");
        if (poolSize == 1 && optionCount == 32 && dependencyDepth == 0) {
            // Measured commitment-reference baseline: 3,375,602 call gas.
            require(chosen && chooseGas < 3_300_000, "wide catalogue exceeds measured call budget");
        }
        require(registry.nextRequestId() == nextRequest, "choice created a request");
        require(requestAllocation.nextRequestId() == nextExecution, "choice created execution");
        require(
            keccak256(abi.encode(registry.getSupportRevision(genericRequestId, 1))) == supportBefore,
            "choice changed declared pool"
        );
        _assertRecognitionUnchanged();
        if (!chosen) {
            require(registry.nextDecisionId() == nextDecision, "failed choice reserved a decision");
            require(keccak256(abi.encode(registry.getRequest(genericRequestId))) == requestBefore, "request changed");
            require(
                keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == executionBefore,
                "failed choice changed execution"
            );
            require(poolSize != 1 || optionCount != 1 || dependencyDepth != 0, "default singleton failed");
            emit log_named_uint("workload lifecycle complete", 0);
            _assertSingletonRecovery();
            return;
        }

        require(registry.nextDecisionId() == nextDecision + 1 && decisionId == nextDecision, "decision count");
        AVADecisionRegistry.DecisionRecord memory selected = registry.getDecision(decisionId);
        require(selected.actor == ALLOCATOR_ACTOR && selected.roleKey == ROLE_ALLOCATOR, "wrong allocating actor");
        require(selected.authorityId == _authority(ROLE_ALLOCATOR), "wrong allocating authority");
        require(selected.option.key == POSITIVE && selected.executionRequestId == executionRequestId, "wrong choice");
        require(selected.witness.length == poolSize, "selected witness truncated");
        for (uint256 i; i < poolSize; ++i) {
            require(
                selected.witness[i].recognisedStateId == declaredPool[i].recognisedStateId
                    && selected.witness[i].transitionId == declaredPool[i].transitionId
                    && keccak256(abi.encode(selected.witness[i].scope)) == keccak256(abi.encode(declaredPool[i].scope)),
                "selected witness changed"
            );
        }
        emit log_named_uint("workload selected witnesses", selected.witness.length);
        bytes32 choiceBefore = keccak256(abi.encode(selected));
        bytes32 approvedBefore = keccak256(abi.encode(requestAllocation.getRequest(executionRequestId)));
        uint256 beforeGas = gasleft();
        (bool valid, bytes memory result) = address(requestAllocation).staticcall{gas: CALL_GAS_BUDGET}(
            abi.encodeCall(
                requestAllocation.validateExecution, (executionRequestId, RESPONSE, PARAMETERS, address(executor))
            )
        );
        uint256 validationGas = beforeGas - gasleft();
        emit log_named_uint("workload warm validate gas", validationGas);
        emit log_named_uint("workload warm validate success", valid ? 1 : 0);
        if (target) require(valid, "4/8/8 validation exceeds call budget");
        if (poolSize == 16 && optionCount == 1 && dependencyDepth == 0 && sourcePackageCount == 1) {
            // Accepted prior implementation: 3,437,551 warm public-call gas.
            require(valid && validationGas < 3_250_000, "declared pool exceeds measured validation budget");
        }
        if (valid) require(abi.decode(result, (bool)), "validation returned false");
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == approvedBefore,
            "validation changed execution"
        );
        if (!valid) {
            require(poolSize != 1 || optionCount != 1 || dependencyDepth != 0, "default validation failed");
            emit log_named_uint("workload lifecycle complete", 0);
            _assertRecognitionUnchanged();
            _assertSingletonRecovery();
            return;
        }

        // The live permission remains necessary after selection, not only during intake.
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.consume(executionRequestId, RESPONSE, PARAMETERS, address(this));
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == approvedBefore,
            "revoked permission consumed execution"
        );
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, true);
        requestVm.prank(address(executor));
        beforeGas = gasleft();
        (bool consumed,) = address(requestAllocation).call{gas: CALL_GAS_BUDGET}(
            abi.encodeCall(requestAllocation.consume, (executionRequestId, RESPONSE, PARAMETERS, address(this)))
        );
        emit log_named_uint("workload warm consume gas", beforeGas - gasleft());
        emit log_named_uint("workload warm consume success", consumed ? 1 : 0);
        if (target) require(consumed, "4/8/8 consumption exceeds call budget");
        if (!consumed) {
            require(poolSize != 1 || optionCount != 1 || dependencyDepth != 0, "default consumption failed");
            emit log_named_uint("workload lifecycle complete", 0);
            require(
                keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == approvedBefore,
                "failed consume changed execution"
            );
            _assertRecognitionUnchanged();
            _assertSingletonRecovery();
            return;
        }
        bytes32 effect = keccak256("decision workload effect");
        requestVm.prank(address(executor));
        beforeGas = gasleft();
        requestAllocation.complete(executionRequestId, effect);
        emit log_named_uint("workload complete gas", beforeGas - gasleft());
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionRequestId);
        require(completed.consumed && completed.completed && completed.effectHash == effect, "effect missing");
        require(completed.allocator == ALLOCATOR_ACTOR && completed.triggeredBy == address(this), "wrong effect actors");
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.consume(executionRequestId, RESPONSE, PARAMETERS, address(this));
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.complete(executionRequestId, effect);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == keccak256(abi.encode(completed)),
            "replay changed execution history"
        );
        require(keccak256(abi.encode(registry.getDecision(decisionId))) == choiceBefore, "execution changed choice");
        _assertRecognitionUnchanged();
        emit log_named_uint("workload lifecycle complete", 1);
    }

    function _budgetedChoose(uint256 requestId, uint256 executionId)
        private
        returns (bool success, uint256 decisionId, uint256 callGas, uint256 revertBytes)
    {
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 beforeGas = gasleft();
        bytes memory result;
        (success, result) = address(registry).call{gas: CALL_GAS_BUDGET}(
            abi.encodeCall(
                registry.choose,
                (requestId, POSITIVE, executionId, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON)
            )
        );
        callGas = beforeGas - gasleft();
        if (success) decisionId = abi.decode(result, (uint256));
        else revertBytes = result.length;
    }

    function _assertSingletonRecovery() private {
        // A fresh one-option package/request proves the bounded diagnostic did not block legal progress.
        DecisionWorkloadVm(address(requestVm)).pauseGasMetering();
        IAVADecisionPolicy.Option[] memory options = _options(1, false, 0);
        // Separate substantive meaning; never bypass the pending profile's once-only lock.
        options[0].parametersHash = PARAMETERS_B;
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, options));
        IAVADecisionPolicy.Request memory input = _input(keccak256("workload legal singleton recovery"));
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 1);
        uint256 id = _open(input, pool);
        uint256 executionId = _execution(input, pool, PARAMETERS_B);
        DecisionWorkloadVm(address(requestVm)).resumeGasMetering();
        (bool success,, uint256 callGas,) = _budgetedChoose(id, executionId);
        require(success, "legal singleton cannot progress");
        emit log_named_uint("workload recovery singleton choose gas", callGas);
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS_B);
        require(requestAllocation.getRequest(executionId).completed, "singleton execution failed");
        require(_recognitionHash() == recognitionBefore, "recovery rewrote prior recognition");
        emit log_named_uint("workload recovery singleton complete", 1);
    }

    function _assertRecognitionUnchanged() private view {
        require(kernel.nextGovernedObjectId() == nextObjectBefore, "decision created object");
        require(kernel.nextRecognisedStateId() == nextStateBefore, "decision created recognition");
        require(kernel.nextTransitionId() == nextTransitionBefore, "decision changed transition count");
        require(_recognitionHash() == recognitionBefore, "decision rewrote recognition history");
    }

    function _recognitionHash() private view returns (bytes32 digest) {
        for (uint256 i = 1; i < nextStateBefore; ++i) {
            digest = keccak256(abi.encode(digest, kernel.getRecognisedState(i)));
        }
        for (uint256 i = 1; i < nextTransitionBefore; ++i) {
            digest = keccak256(abi.encode(digest, kernel.getRecognisedStateTransition(i)));
        }
    }

    function _workloadOptions() private view returns (IAVADecisionPolicy.Option[] memory options) {
        options = new IAVADecisionPolicy.Option[](optionCount);
        options[0] = _options(1, false, 0)[0];
        for (uint256 i = 1; i < optionCount; ++i) {
            options[i] = IAVADecisionPolicy.Option(
                keccak256(abi.encode("workload option", i)),
                IAVADecisionPolicy.Kind.Substantive,
                AVACoreTypes.ACTION_RECORD_ALLOCATION,
                keccak256(abi.encode("workload parameters", i)),
                0,
                bytes32(0)
            );
        }
    }

    function _scope(IAVADecisionPolicy.Request memory input)
        private
        pure
        returns (IAVARequestPolicy.RecognitionScope memory)
    {
        return IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
    }

    function _dependent(IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput memory source)
        private
        returns (IAVARequestPolicy.WitnessInput memory)
    {
        requestVm.startPrank(SOURCE_ACTOR);
        bytes32 commitment = keccak256(abi.encode("workload dependency", evidenceRegistry.nextEvidenceId()));
        uint256 evidence = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: _authority(ROLE_SOURCE),
                commitment: commitment,
                evidenceTypeHash: keccak256("workload dependency evidence"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:workload-evidence"
            })
        );
        AVACoreTypes.SourceOccurrence[] memory sources = new AVACoreTypes.SourceOccurrence[](1);
        sources[0] = AVACoreTypes.SourceOccurrence(source.recognisedStateId, source.transitionId);
        uint256 objectId = kernel.registerGovernedObjectWithDependencies(
            AVAGovernanceKernel.GovernedObjectInput({
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
                metadataHash: requestAllocation.recognitionScopeHash(_scope(input)),
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:workload-object"
            }),
            sources
        );
        AVACoreTypes.SourceOccurrence[] memory recorded = kernel.DEPENDENCIES().getDependencies(objectId);
        require(
            recorded.length == 1 && recorded[0].recognisedStateId == source.recognisedStateId
                && recorded[0].transitionId == source.transitionId,
            "dependency changed"
        );
        requestVm.stopPrank();
        requestVm.startPrank(VERIFIER_ACTOR);
        uint256 state = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: REASON,
                reasonURI: "test:workload"
            })
        );
        kernel.transitionRecognisedState(_transitionInput(state, AVACoreTypes.RecognisedStateStatus.Challengeable));
        kernel.vestRecognisedState(_transitionInput(state, AVACoreTypes.RecognisedStateStatus.Vested));
        requestVm.stopPrank();
        return IAVARequestPolicy.WitnessInput(
            state, kernel.getRecognisedStateReference(state).lastTransitionId, _scope(input)
        );
    }
}
