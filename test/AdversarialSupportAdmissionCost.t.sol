// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {IAVADecisionPolicy} from "../src/core/interfaces/IAVADecisionPolicy.sol";
import {IAVARequestPolicy} from "../src/core/interfaces/IAVARequestPolicy.sol";
import {AVADecisionRegistry} from "../src/extensions/decisions/AVADecisionRegistry.sol";
import {AVAFiniteDecisionPolicy} from "../src/extensions/decisions/AVAFiniteDecisionPolicy.sol";
import {AVARequestAllocation} from "../src/extensions/requests/AVARequestAllocation.sol";
import {DecisionSetFixture} from "./DecisionSet.t.sol";

interface AdmissionExactVm {
    function expectRevert(bytes calldata reason) external;
}

/// @notice Real public admission calls, followed by retained revisions and one legal effect.
/// @dev Calls are deliberately warmed by source creation/readback in the same test transaction.
/// Gas includes the external CALL and return-data handling, excludes fixture construction,
/// calldata preparation and transaction intrinsic gas, and is not a cold-transaction estimate.
contract AdversarialSupportAdmissionCostTest is DecisionSetFixture {
    event log_named_uint(string key, uint256 value);
    event log_named_bytes32(string key, bytes32 value);
    event log_string(string value);

    function testAdversarialCostSamePackage1() public {
        _measureSamePackage(1);
    }

    function testAdversarialCostSamePackage3() public {
        _measureSamePackage(3);
    }

    function testAdversarialCostSamePackage8() public {
        _measureSamePackage(8);
    }

    function testAdversarialCostSamePackage16() public {
        _measureSamePackage(16);
    }

    function testAdversarialCostMixedHistoricalPackages() public {
        (IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput[] memory pool,) =
            _historicalPool("admission mixed historical cost");
        _measure(input, pool);
    }

    function testAdversarialAdmissionUnsortedOpenAndUpdateRollbackThenExecute() public {
        IAVADecisionPolicy.Request memory input = _input("admission unsorted rollback");
        IAVARequestPolicy.WitnessInput[] memory pool = _pool(input, 3);
        IAVARequestPolicy.WitnessInput memory first = pool[0];
        IAVARequestPolicy.WitnessInput memory second = pool[1];
        pool[0] = pool[1];
        pool[1] = first;
        uint256 nextRequest = registry.nextRequestId();
        requestVm.prank(SOURCE_ACTOR);
        _expectInvalid(first.recognisedStateId);
        registry.openRequest(input, pool, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(registry.nextRequestId() == nextRequest, "rejected open reserved request");
        require(
            registry.requestIdByHash(keccak256(abi.encode(APP, REQUEST_WORKFLOW, input.requestHash))) == 0,
            "rejected open reserved meaning"
        );

        pool[0] = first;
        pool[1] = second;
        uint256 id = _open(input, pool);
        bytes32 beforeUpdate = _requestHistory(id);
        pool[0] = second;
        pool[1] = first;
        requestVm.prank(SOURCE_ACTOR);
        _expectInvalid(first.recognisedStateId);
        registry.updateSupport(id, pool, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(_requestHistory(id) == beforeUpdate, "unsorted update changed retained history");
        pool[0] = first;
        pool[1] = second;
        _updateAndExecute(id, input, pool);
    }

    function testAdversarialAdmissionUnavailablePrecedesLaterPackageDriftThenRecovers() public {
        (IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput[] memory pool, address laterModule) =
            _historicalPool("admission ordered failures");
        uint256 id = _open(input, pool);
        bytes32 beforeUpdate = _requestHistory(id);
        uint256 evidenceId = kernel.getRecognisedStateReference(pool[0].recognisedStateId).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidenceId, ROLE_SOURCE, _authority(ROLE_SOURCE), AVACoreTypes.EvidenceLifecycleKind.Revoke, 0, REASON,
            "test:admission-unavailable"
        );
        bytes memory originalCode = laterModule.code;
        AVAFiniteDecisionPolicy changed = new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(2, false, 0));
        requestVm.etch(laterModule, address(changed).code);
        requestVm.prank(SOURCE_ACTOR);
        _expectInvalid(pool[0].recognisedStateId);
        registry.updateSupport(id, pool, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(_requestHistory(id) == beforeUpdate, "unavailable admission partly committed");

        // Removing the unavailable first member exposes the later historical identity failure.
        IAVARequestPolicy.WitnessInput[] memory surviving = new IAVARequestPolicy.WitnessInput[](1);
        surviving[0] = pool[1];
        uint256 laterPackage = kernel.getRecognisedStateReference(pool[1].recognisedStateId).packageId;
        requestVm.prank(SOURCE_ACTOR);
        _expectInvalid(laterPackage);
        registry.updateSupport(id, surviving, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(_requestHistory(id) == beforeUpdate, "identity failure partly committed");
        requestVm.etch(laterModule, originalCode);
        require(keccak256(laterModule.code) == keccak256(originalCode), "historical code not restored");
        _updateAndExecute(id, input, surviving);
    }

    function _measureSamePackage(uint256 count) private {
        IAVADecisionPolicy.Request memory input = _input(keccak256(abi.encode("admission same package", count)));
        _measure(input, _pool(input, count));
    }

    function _measure(IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput[] memory pool) private {
        bytes32 sourceHistory = _sourceHistory(pool);
        emit log_named_uint("admission pool members", pool.length);
        emit log_string("warm public CALL gas; excludes fixture/calldata preparation and transaction intrinsic gas");
        bytes memory openData = abi.encodeCall(
            registry.openRequest, (input, pool, ROLE_SOURCE, _authority(ROLE_SOURCE))
        );
        requestVm.prank(SOURCE_ACTOR);
        uint256 beforeGas = gasleft();
        (bool opened, bytes memory result) = address(registry).call(openData);
        uint256 openGas = beforeGas - gasleft();
        require(opened, "public openRequest failed");
        uint256 id = abi.decode(result, (uint256));
        emit log_named_uint("openRequest warm public call gas", openGas);
        emit log_named_uint("openRequest calldata bytes", openData.length);
        emit log_named_bytes32("openRequest calldata hash", keccak256(openData));
        _assertRevision(id, 1, pool, bytes32(0));
        _updateMeasured(id, pool);
        if (pool.length == 3) require(openGas < 1_104_262, "three-source admission cost not reduced");
        if (pool.length == 8) require(openGas < 2_036_126, "eight-source admission cost not reduced");
        if (pool.length == 16) require(openGas < 3_524_458, "sixteen-source admission cost not reduced");
        _executeOnce(id, input, pool[0]);
        require(_sourceHistory(pool) == sourceHistory, "admission or effect changed source history");
    }

    function _updateMeasured(uint256 id, IAVARequestPolicy.WitnessInput[] memory pool) private {
        AVADecisionRegistry.SupportRevision memory first = registry.getSupportRevision(id, 1);
        bytes memory updateData = abi.encodeCall(
            registry.updateSupport, (id, pool, 1, ROLE_SOURCE, _authority(ROLE_SOURCE))
        );
        requestVm.prank(SOURCE_ACTOR);
        uint256 beforeGas = gasleft();
        (bool updated,) = address(registry).call(updateData);
        uint256 updateGas = beforeGas - gasleft();
        require(updated, "public updateSupport failed");
        emit log_named_uint("updateSupport warm public call gas", updateGas);
        emit log_named_uint("updateSupport calldata bytes", updateData.length);
        emit log_named_bytes32("updateSupport calldata hash", keccak256(updateData));
        if (pool.length == 3) require(updateGas < 764_890, "three-source update cost not reduced");
        if (pool.length == 8) require(updateGas < 1_694_748, "eight-source update cost not reduced");
        if (pool.length == 16) require(updateGas < 3_183_071, "sixteen-source update cost not reduced");
        _assertRevision(id, 2, pool, first.revisionHash);
        require(
            keccak256(abi.encode(registry.getSupportRevision(id, 1))) == keccak256(abi.encode(first)),
            "update rewrote earlier support revision"
        );
    }

    function _updateAndExecute(
        uint256 id,
        IAVADecisionPolicy.Request memory input,
        IAVARequestPolicy.WitnessInput[] memory pool
    ) private {
        bytes32 previous = registry.getSupportRevision(id, 1).revisionHash;
        requestVm.prank(SOURCE_ACTOR);
        registry.updateSupport(id, pool, 1, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _assertRevision(id, 2, pool, previous);
        _executeOnce(id, input, pool[0]);
    }

    function _assertRevision(
        uint256 id,
        uint256 revision,
        IAVARequestPolicy.WitnessInput[] memory pool,
        bytes32 previousHash
    ) private view {
        AVADecisionRegistry.AtomicRequest memory request = registry.getRequest(id);
        AVADecisionRegistry.SupportRevision memory support = registry.getSupportRevision(id, revision);
        require(request.creator == SOURCE_ACTOR && request.supportRevision == revision, "wrong request history");
        require(request.lastDecisionId == 0 && request.allocationDecisionId == 0, "admission allocated a decision");
        require(support.revision == revision && support.previousHash == previousHash, "support lineage changed");
        require(support.updatedBy == SOURCE_ACTOR && support.pool.length == pool.length, "pool or actor lost");
        for (uint256 i; i < pool.length; ++i) {
            require(
                support.pool[i].recognisedStateId == pool[i].recognisedStateId
                    && support.pool[i].transitionId == pool[i].transitionId
                    && keccak256(abi.encode(support.pool[i].scope)) == keccak256(abi.encode(pool[i].scope)),
                "admission dropped, reordered or changed a witness"
            );
        }
        require(registry.getEligibleWitnesses(id).length == pool.length, "admitted live witness unavailable");
    }

    function _executeOnce(uint256 id, IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput memory source)
        private
    {
        IAVARequestPolicy.WitnessInput[] memory selected = new IAVARequestPolicy.WitnessInput[](1);
        selected[0] = source;
        requestVm.prank(SOURCE_ACTOR);
        uint256 executionId = requestAllocation.createDecisionRequestForPackage(
            id, input.packageId, _executionInput(input, selected, PARAMETERS), selected,
            ROLE_SOURCE, _authority(ROLE_SOURCE)
        );
        uint256 decisionId = _choose(id, POSITIVE, executionId, 0);
        AVADecisionRegistry.DecisionRecord memory decision = registry.getDecision(decisionId);
        require(decision.supportRevision == 2 && decision.actor == ALLOCATOR_ACTOR, "wrong selected revision/actor");
        require(
            decision.witness.length == 1 && decision.witness[0].recognisedStateId == source.recognisedStateId
                && decision.witness[0].transitionId == source.transitionId && decision.option.key == POSITIVE,
            "choice changed the sufficient witness"
        );
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        AVARequestAllocation.RequestRecord memory completed = requestAllocation.getRequest(executionId);
        require(completed.consumed && completed.completed && completed.effectHash != bytes32(0), "legal effect missing");
        requestVm.expectRevert();
        executor.execute(requestAllocation, executionId, RESPONSE, PARAMETERS);
        require(
            keccak256(abi.encode(requestAllocation.getRequest(executionId))) == keccak256(abi.encode(completed)),
            "replay changed completed history"
        );
    }

    function _historicalPool(bytes32 requestHash)
        private
        returns (IAVADecisionPolicy.Request memory input, IAVARequestPolicy.WitnessInput[] memory pool, address laterModule)
    {
        input = _input(requestHash);
        IAVARequestPolicy.RecognitionScope memory scope =
            IAVARequestPolicy.RecognitionScope(input.requestHash, RESPONSE, BURDEN);
        pool = new IAVARequestPolicy.WitnessInput[](3);
        pool[0] = _scopedState(scope);
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        laterModule = address(policy);
        pool[1] = _scopedState(scope);
        _install(new AVAFiniteDecisionPolicy(APP, REQUEST_WORKFLOW, _options(1, false, 0)));
        pool[2] = _scopedState(scope);
        input.packageId = requestPackageId;
        uint256 firstPackage = kernel.getRecognisedStateReference(pool[0].recognisedStateId).packageId;
        uint256 secondPackage = kernel.getRecognisedStateReference(pool[1].recognisedStateId).packageId;
        require(
            firstPackage != secondPackage && firstPackage != input.packageId && secondPackage != input.packageId,
            "historical control did not retain distinct packages"
        );
    }

    function _expectInvalid(uint256 id) private {
        AdmissionExactVm(address(requestVm)).expectRevert(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, id));
    }

    function _requestHistory(uint256 id) private view returns (bytes32) {
        return keccak256(abi.encode(
            registry.getRequest(id), registry.getSupportRevision(id, 1), registry.nextRequestId(), registry.nextDecisionId()
        ));
    }

    function _sourceHistory(IAVARequestPolicy.WitnessInput[] memory pool) private view returns (bytes32) {
        bytes32[] memory records = new bytes32[](pool.length);
        for (uint256 i; i < pool.length; ++i) {
            records[i] = keccak256(abi.encode(kernel.getRecognisedState(pool[i].recognisedStateId)));
        }
        return keccak256(abi.encode(records, kernel.nextTransitionId()));
    }
}
