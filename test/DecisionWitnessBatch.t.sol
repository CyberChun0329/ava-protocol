// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";

interface DecisionWitnessBatchVm {
    function expectRevert(bytes calldata reason) external;
}

contract DecisionWitnessBatchTest is DecisionSetFixture {
    function testSamePackagePoolSkipsUnavailableMemberAndExecutesSurvivorOnce() public {
        IAVADecisionPolicy.Request memory input = _input("same package surviving witness");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 3);
        uint256 id = _open(input, pool);
        bytes32 sourcesBefore = _sourceHistory(pool);
        bytes32 supportBefore = keccak256(abi.encode(registry.getSupportRevision(id, 1)));
        require(registry.getEligibleWitnesses(id).length == 3, "initial same-package pool incomplete");
        _revoke(pool[0]);

        IAVARequestPolicy.Witness[] memory eligible = registry.getEligibleWitnesses(id);
        require(
            eligible.length == 2 && eligible[0].recognisedStateId == pool[1].recognisedStateId
                && eligible[1].recognisedStateId == pool[2].recognisedStateId,
            "unavailable member hid or reordered surviving witnesses"
        );
        require(_d(id).length == 1, "surviving support lost its positive option");
        _assertHistory(id, pool, sourcesBefore, supportBefore);
        IAVARequestPolicy.WitnessInput[] memory selected = _single(pool[1]);
        uint256 executionId = _execution(input, selected, PARAMETERS);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        AVADecisionRegistry.DecisionRecord memory decision = registry.getDecision(decisionId);
        require(
            decision.witness.length == 1 && decision.witness[0].recognisedStateId == pool[1].recognisedStateId
                && decision.witness[0].transitionId == pool[1].transitionId,
            "choice did not retain the surviving concrete witness"
        );
        _executeOnce(id, executionId, decisionId, pool, sourcesBefore, supportBefore);
    }

    function testUnavailableHistoricalMemberDoesNotHideLaterIdentityFailure() public {
        IAVADecisionPolicy.Request memory input = _input("historical source failures");
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, input.responseClass, input.burdenHash);
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](2);
        uint256 firstPackage = requestPackageId;
        address firstModule = address(policy);
        pool[0] = _scopedState(scope);
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        uint256 laterPackage = requestPackageId;
        address laterModule = address(policy);
        pool[1] = _scopedState(scope);
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        input.packageId = requestPackageId;
        require(
            firstPackage != laterPackage && laterPackage != input.packageId && firstModule != laterModule,
            "historical packages must be distinct from the receiving package"
        );
        uint256 id = _open(input, pool);
        bytes32 sourcesBefore = _sourceHistory(pool);
        bytes32 supportBefore = keccak256(abi.encode(registry.getSupportRevision(id, 1)));
        _revoke(pool[0]);
        IAVARequestPolicy.Witness[] memory eligible = registry.getEligibleWitnesses(id);
        require(
            eligible.length == 1 && eligible[0].recognisedStateId == pool[1].recognisedStateId
                && eligible[0].packageId == laterPackage,
            "historical surviving witness lost"
        );
        IAVARequestPolicy.WitnessInput[] memory selected = _single(pool[1]);
        requestVm.prank(SOURCE_ACTOR);
        uint256 executionId = requestAllocation.createDecisionRequestForPackage(
            id,
            input.packageId,
            _executionInput(input, selected, PARAMETERS),
            selected,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE)
        );
        bytes32 pendingBefore = _requestHistory(id, executionId);
        bytes memory firstCode = firstModule.code;
        bytes memory laterCode = laterModule.code;
        AVAFiniteDecisionPolicy changed = new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(2, false, 0));

        // The first source is known unavailable. Its ineligibility must not end the pool scan.
        requestVm.etch(laterModule, address(changed).code);
        _expectPackageFailure(laterPackage);
        registry.getEligibleWitnesses(id);
        _expectPackageFailure(laterPackage);
        registry.getAdmissibleDecisions(id, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        _expectPackageFailure(laterPackage);
        _choose(id, POSITIVE, executionId, 0);
        require(_requestHistory(id, executionId) == pendingBefore, "identity failure changed pending records");

        // With both source packages failing, the first declared source must determine the error.
        requestVm.etch(firstModule, address(changed).code);
        _expectPackageFailure(firstPackage);
        registry.getEligibleWitnesses(id);
        requestVm.etch(firstModule, firstCode);
        _expectPackageFailure(laterPackage);
        registry.getEligibleWitnesses(id);
        requestVm.etch(laterModule, laterCode);
        require(
            keccak256(firstModule.code) == keccak256(firstCode) && keccak256(laterModule.code) == keccak256(laterCode),
            "historical module code was not restored exactly"
        );
        _assertHistory(id, pool, sourcesBefore, supportBefore);
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        require(
            registry.getDecision(decisionId).witness[0].recognisedStateId == pool[1].recognisedStateId,
            "recovery selected unavailable historical support"
        );

        bytes32 approvedBefore = _requestHistory(id, executionId);
        bytes32 choiceBefore = keccak256(abi.encode(registry.getDecision(decisionId)));
        requestVm.etch(laterModule, address(changed).code);
        _expectPackageFailure(laterPackage);
        requestAllocation.validateExecution(executionId, RESPONSE, PARAMETERS, address(executor));
        _expectPackageFailure(laterPackage);
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            _requestHistory(id, executionId) == approvedBefore
                && keccak256(abi.encode(registry.getDecision(decisionId))) == choiceBefore,
            "failed consumption changed approved history"
        );
        requestVm.etch(laterModule, laterCode);
        require(keccak256(laterModule.code) == keccak256(laterCode), "recovery did not restore exact module code");
        _executeOnce(id, executionId, decisionId, pool, sourcesBefore, supportBefore);
    }

    function testEmptyPoolStillAllowsAuthorisedProcedure() public {
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, true, 0)));
        IAVARequestPolicy.WitnessInput[] memory pool = new IAVARequestPolicy.WitnessInput[](0);
        uint256 id = _open(_input("empty pool procedure"), pool);
        bytes32 sourcesBefore = _sourceHistory(pool);
        bytes32 supportBefore = keccak256(abi.encode(registry.getSupportRevision(id, 1)));
        uint256 nextExecution = requestAllocation.nextRequestId();
        require(registry.getEligibleWitnesses(id).length == 0, "empty pool invented support");
        require(_d(id).length == 0, "procedure authority was invented");
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, PROCEDURE_ACTION, true);
        IAVADecisionPolicy.Option[] memory options = _d(id);
        require(options.length == 1 && options[0].key == PROCEDURE, "authorised procedure lost on empty pool");
        uint256 decisionId = _choose(id, PROCEDURE, 0, 0);
        AVADecisionRegistry.DecisionRecord memory decision = registry.getDecision(decisionId);
        AVADecisionRegistry.AtomicRequest memory request = registry.getRequest(id);
        require(
            request.paused && !request.closed && request.allocationDecisionId == 0 && decision.witness.length == 0
                && decision.executionRequestId == 0,
            "empty-pool procedure allocated or invented substantive support"
        );
        require(requestAllocation.nextRequestId() == nextExecution, "procedure created an execution request");
        _assertHistory(id, pool, sourcesBefore, supportBefore);
        bytes32 requestBefore = keccak256(abi.encode(request));
        bytes32 decisionBefore = keccak256(abi.encode(decision));
        requestVm.expectRevert();
        _choose(id, PROCEDURE, 0, 0);
        require(
            keccak256(abi.encode(registry.getRequest(id))) == requestBefore
                && keccak256(abi.encode(registry.getDecision(decisionId))) == decisionBefore,
            "stale procedural replay changed history"
        );
    }

    function _revoke(IAVARequestPolicy.WitnessInput memory witness) private {
        uint256 evidenceId = kernel.getRecognisedStateReference(witness.recognisedStateId).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidenceId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            REASON,
            "test:unavailable-declared-pool-member"
        );
    }

    function _single(IAVARequestPolicy.WitnessInput memory witness)
        private
        pure
        returns (IAVARequestPolicy.WitnessInput[] memory selected)
    {
        selected = new IAVARequestPolicy.WitnessInput[](1);
        selected[0] = witness;
    }

    function _expectPackageFailure(uint256 packageId) private {
        DecisionWitnessBatchVm(address(requestVm))
            .expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, packageId));
    }

    function _requestHistory(uint256 genericId, uint256 executionId) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                registry.getRequest(genericId),
                requestAllocation.getRequest(executionId),
                registry.nextDecisionId(),
                requestAllocation.nextRequestId()
            )
        );
    }

    function _sourceHistory(IAVARequestPolicy.WitnessInput[] memory pool) private view returns (bytes32) {
        bytes32[] memory sourceHashes = new bytes32[](pool.length);
        for (uint256 i; i < pool.length; ++i) {
            AVAGovernanceKernel.RecognisedStateReference memory state =
                kernel.getRecognisedStateReference(pool[i].recognisedStateId);
            sourceHashes[i] = keccak256(
                abi.encode(
                    kernel.getRecognisedState(state.id),
                    kernel.getRecognisedStateTransition(pool[i].transitionId),
                    kernel.getGovernedObject(state.governedObjectId)
                )
            );
        }
        return keccak256(
            abi.encode(
                sourceHashes, kernel.nextGovernedObjectId(), kernel.nextRecognisedStateId(), kernel.nextTransitionId()
            )
        );
    }

    function _assertHistory(
        uint256 id,
        IAVARequestPolicy.WitnessInput[] memory pool,
        bytes32 sourcesBefore,
        bytes32 supportBefore
    ) private view {
        require(_sourceHistory(pool) == sourcesBefore, "source objects or recognition history changed");
        require(
            keccak256(abi.encode(registry.getSupportRevision(id, 1))) == supportBefore, "declared pool history changed"
        );
    }

    function _executeOnce(
        uint256 id,
        uint256 executionId,
        uint256 decisionId,
        IAVARequestPolicy.WitnessInput[] memory pool,
        bytes32 sourcesBefore,
        bytes32 supportBefore
    ) private {
        bytes32 choiceBefore = keccak256(abi.encode(registry.getDecision(decisionId)));
        bytes32 requestBefore = keccak256(abi.encode(registry.getRequest(id)));
        require(
            requestAllocation.validateExecution(executionId, RESPONSE, PARAMETERS, address(executor)),
            "surviving support did not validate"
        );
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionId);
        require(
            completed.consumed && completed.completed && completed.effectHash != bytes32(0)
                && completed.allocator == ALLOCATOR_ACTOR,
            "legal surviving witness did not execute"
        );
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == keccak256(abi.encode(completed))
                && keccak256(abi.encode(registry.getDecision(decisionId))) == choiceBefore
                && keccak256(abi.encode(registry.getRequest(id))) == requestBefore,
            "execution or replay changed completed decision history"
        );
        _assertHistory(id, pool, sourcesBefore, supportBefore);
    }
}
