// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";

/// @dev A concrete declared domain: every declared source is jointly necessary.
/// A pool of sixteen therefore produces a genuine sixteen-member sufficient witness.
contract GasAllWitnessDecisionPolicy is AVAFiniteDecisionPolicy {
    uint256 public immutable REQUIRED_WITNESSES;

    constructor(bytes32 app, bytes32 workflow, Option[] memory options, uint256 required)
        AVAFiniteDecisionPolicy(app, workflow, options)
    {
        REQUIRED_WITNESSES = required;
    }

    function witnessFor(Request calldata request, Option calldata, IAVARequestPolicy.Witness[] calldata eligible)
        external
        view
        override
        returns (uint256[] memory indices)
    {
        if (eligible.length != REQUIRED_WITNESSES) return new uint256[](0);
        for (uint256 i; i < eligible.length; ++i) {
            IAVARequestPolicy.RecognitionScope calldata scope = eligible[i].scope;
            if (
                scope.claimHash != request.requestHash || scope.useHash != request.responseClass
                    || scope.burdenHash != request.burdenHash
            ) return new uint256[](0);
        }
        indices = new uint256[](eligible.length);
        for (uint256 i; i < indices.length; ++i) {
            indices[i] = i;
        }
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(CONFIGURATION_HASH, REQUIRED_WITNESSES));
    }
}

/// @notice Public-call gas diagnostics; the 30m budget is local, not a Base limit assertion.
/// @dev Real Core setup is excluded by setUp. Measurements exclude transaction intrinsic gas.
/// The first choose is followed by already-warmed validation/consumption/completion calls.
interface GasFixtureVm {
    function pauseGasMetering() external;
    function resumeGasMetering() external;
}

abstract contract DecisionGasBudgetFixture is DecisionSetFixture {
    uint256 private constant ORDINARY_BLOCK_GAS_DIAGNOSTIC = 30_000_000;
    uint256 internal genericRequestId;
    uint256 internal executionRequestId;
    uint256 internal expectedWitnesses;
    uint256 internal expectedOptions;
    uint256 internal expectedObjects;
    uint256 internal expectedEdges;
    uint256 internal expectedClosureEdges;
    uint256 internal actualEdges;
    uint256 internal nextTransitionAfterSetup;

    event log_named_uint(string key, uint256 value);
    event log_string(string value);

    // 0: representative singleton; 1: shared closure; 2: independent closures.
    function _shape() internal pure virtual returns (uint256);

    function setUp() public override {
        // The large fixture represents many separate intake transactions, not one transaction.
        // Exclude only fixture construction; normal metering resumes before every measured call.
        GasFixtureVm(address(requestVm)).pauseGasMetering();
        super.setUp();
        uint256 shape = _shape();
        expectedWitnesses = shape == 0 ? 1 : 16;
        expectedOptions = shape == 0 ? 1 : 32;
        expectedObjects = shape == 0 ? 1 : (shape == 1 ? 80 : 1040);
        expectedEdges = shape == 0 ? 0 : (shape == 1 ? 79 : 1024);
        expectedClosureEdges = shape == 0 ? 0 : 64;
        _install(
            new GasAllWitnessDecisionPolicy(APP, REQUEST_WORKFLOW, _gasOptions(expectedOptions), expectedWitnesses)
        );
        IAVADecisionPolicy.Request memory input = _input(keccak256(abi.encode("public gas diagnostic", shape)));
        uint256 firstObject = kernel.nextGovernedObjectId();
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](expectedWitnesses);
        if (shape == 0) {
            pool[0] = _scopedState(_scope(input));
        } else if (shape == 1) {
            IAVARequestPolicy.WitnessInput memory sharedTip = _chain(input, 63);
            for (uint256 i; i < pool.length; ++i) {
                pool[i] = _dependent(input, sharedTip);
            }
        } else {
            for (uint256 i; i < pool.length; ++i) {
                pool[i] = _chain(input, 64);
            }
        }
        require(kernel.nextGovernedObjectId() - firstObject == expectedObjects, "wrong object count");
        require(actualEdges == expectedEdges, "wrong edge count");
        require(registry.MAX_POOL() == 16 && registry.MAX_OPTIONS() == 32, "decision caps changed");
        require(requestAllocation.MAX_SUPPORT_WITNESSES() == 16, "request cap changed");
        require(kernel.DEPENDENCIES().MAX_TRAVERSAL() == 64, "closure cap changed");
        genericRequestId = _open(input, pool);
        executionRequestId = _execution(input, pool, PARAMETERS);
        nextTransitionAfterSetup = kernel.nextTransitionId();
        GasFixtureVm(address(requestVm)).resumeGasMetering();
    }

    function testPublicDecisionGasBudgetAndOnceOnlyGates() public {
        emit log_named_uint("pool members", expectedWitnesses);
        emit log_named_uint("catalogue options", expectedOptions);
        emit log_named_uint("unique governed objects", expectedObjects);
        emit log_named_uint("unique dependency edges", expectedEdges);
        emit log_named_uint("closure edges per witness", expectedClosureEdges);
        emit log_named_uint("local ordinary block gas diagnostic", ORDINARY_BLOCK_GAS_DIAGNOSTIC);
        emit log_string("gasleft call costs; setup and transaction intrinsic gas excluded; later calls warmed");

        bytes32 beforeGeneric = keccak256(abi.encode(registry.getRequest(genericRequestId)));
        bytes32 beforeExecution = keccak256(abi.encode(requestAllocation.getRequest(executionRequestId)));
        uint256 beforeDecisionId = registry.nextDecisionId();
        requestVm.prank(ALLOCATOR_ACTOR);
        uint256 beforeGas = gasleft();
        (bool withinBudget, bytes memory result) = address(registry).call{gas: ORDINARY_BLOCK_GAS_DIAGNOSTIC}(
            abi.encodeCall(
                registry.choose,
                (genericRequestId, POSITIVE, executionRequestId, 0, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR), REASON)
            )
        );
        uint256 chooseGas = beforeGas - gasleft();
        emit log_named_uint("choose call gas including reverted work", chooseGas);
        emit log_named_uint("choose fits 30m diagnostic", withinBudget ? 1 : 0);
        if (expectedWitnesses == 1) {
            require(chooseGas <= 1_850_000, "representative choice exceeds 1.85m call gas");
        }
        if (!withinBudget) {
            require(expectedWitnesses > 1, "representative choice exceeded ordinary budget");
            require(registry.nextDecisionId() == beforeDecisionId, "failed budget reserved a decision");
            require(
                keccak256(abi.encode(registry.getRequest(genericRequestId))) == beforeGeneric,
                "failed budget changed request"
            );
            require(
                keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == beforeExecution,
                "failed budget approved effect"
            );
            require(kernel.nextTransitionId() == nextTransitionAfterSetup, "failed budget changed recognition");
            emit log_string("structural maximum is outside the local transaction budget; original records remain intact");
            return;
        }
        uint256 decisionId = abi.decode(result, (uint256));
        AVADecisionRegistry.DecisionRecord memory selected = registry.getDecision(decisionId);
        require(registry.getSupportRevision(genericRequestId, 1).pool.length == expectedWitnesses, "pool changed");
        require(selected.witness.length == expectedWitnesses, "selected witness truncated");
        require(selected.option.key == POSITIVE && selected.executionRequestId == executionRequestId, "wrong choice");
        require(requestAllocation.getRequest(executionRequestId).allocator == ALLOCATOR_ACTOR, "approval not executed");
        emit log_named_uint("actual selected witness members", selected.witness.length);

        beforeGas = gasleft();
        require(
            requestAllocation.validateExecution(executionRequestId, RESPONSE, PARAMETERS, address(executor)), "invalid"
        );
        emit log_named_uint("subsequent validate gas", beforeGas - gasleft());
        beforeGas = gasleft();
        require(
            requestAllocation.validateExecution(executionRequestId, RESPONSE, PARAMETERS, address(executor)), "invalid"
        );
        uint256 repeatedValidationGas = beforeGas - gasleft();
        emit log_named_uint("repeated warm validate gas", repeatedValidationGas);
        if (expectedWitnesses == 1) {
            require(repeatedValidationGas <= 590_000, "representative validation exceeds 590k call gas");
        }

        requestVm.prank(address(executor));
        beforeGas = gasleft();
        requestAllocation.consume(executionRequestId, RESPONSE, PARAMETERS, address(this));
        emit log_named_uint("subsequent consume gas", beforeGas - gasleft());
        bytes32 effect = keccak256(abi.encode("public gas diagnostic effect", executionRequestId));
        requestVm.prank(address(executor));
        beforeGas = gasleft();
        requestAllocation.complete(executionRequestId, effect);
        emit log_named_uint("subsequent complete gas", beforeGas - gasleft());

        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionRequestId);
        require(completed.consumed && completed.completed && completed.effectHash == effect, "effect missing");
        bytes32 meaning = keccak256(abi.encode(block.chainid, requestAllocation, APP, executor, RESPONSE, PARAMETERS));
        require(requestAllocation.consumedRequestIdByMeaning(meaning) == executionRequestId, "meaning lock missing");
        require(kernel.nextTransitionId() == nextTransitionAfterSetup, "effect rewrote recognition history");
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        registry.choose(
            genericRequestId,
            POSITIVE,
            executionRequestId,
            decisionId,
            ROLE_ALLOCATOR,
            _authority(ROLE_ALLOCATOR),
            REASON
        );
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.consume(executionRequestId, RESPONSE, PARAMETERS, address(this));
        requestVm.prank(address(executor));
        requestVm.expectRevert();
        requestAllocation.complete(executionRequestId, effect);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionRequestId))) == keccak256(abi.encode(completed)),
            "replay changed effect history"
        );
    }

    function _gasOptions(uint256 count) private pure returns (IAVADecisionPolicy.Option[] memory options) {
        options = new IAVADecisionPolicy.Option[](count);
        options[0] = _options(1, false, 0)[0];
        for (uint256 i = 1; i < count; ++i) {
            options[i] = IAVADecisionPolicy.Option(
                keccak256(abi.encode("gas option", i)),
                IAVADecisionPolicy.Kind.Substantive,
                AVACoreTypes.ACTION_RECORD_ALLOCATION,
                keccak256(abi.encode("gas parameters", i)),
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

    function _chain(IAVADecisionPolicy.Request memory input, uint256 edges)
        private
        returns (IAVARequestPolicy.WitnessInput memory tip)
    {
        tip = _scopedState(_scope(input));
        for (uint256 i; i < edges; ++i) {
            tip = _dependent(input, tip);
        }
    }

    function _dependent(IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput memory source)
        private
        returns (IAVARequestPolicy.WitnessInput memory)
    {
        requestVm.startPrank(SOURCE_ACTOR);
        bytes32 commitment = keccak256(abi.encode("gas dependency", evidenceRegistry.nextEvidenceId()));
        uint256 evidence = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: _authority(ROLE_SOURCE),
                commitment: commitment,
                evidenceTypeHash: keccak256("gas dependency evidence"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(ROLE_SOURCE),
                uri: "test:gas-evidence"
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
                uri: "test:gas-object"
            }),
            sources
        );
        AVACoreTypes.SourceOccurrence[] memory recorded = kernel.DEPENDENCIES().getDependencies(objectId);
        require(
            recorded.length == 1 && recorded[0].recognisedStateId == source.recognisedStateId
                && recorded[0].transitionId == source.transitionId,
            "dependency edge changed"
        );
        actualEdges += recorded.length;
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
                reasonURI: "test:gas-recognition"
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

contract DecisionGasRepresentativeTest is DecisionGasBudgetFixture {
    function _shape() internal pure override returns (uint256) {
        return 0;
    }
}

contract DecisionGasSharedMaximumTest is DecisionGasBudgetFixture {
    function _shape() internal pure override returns (uint256) {
        return 1;
    }
}

contract DecisionGasIndependentMaximumTest is DecisionGasBudgetFixture {
    function _shape() internal pure override returns (uint256) {
        return 2;
    }
}
