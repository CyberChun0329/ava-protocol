// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../../src/core/AVAEvidenceRegistry.sol";
import {
    AVARequestAllocation,
    AVARequestCorrectionActions
} from "../../src/extensions/requests/AVARequestAllocation.sol";
import {RequestAllocationFixture} from "../helpers/RequestAllocationFixture.sol";
import {RequestCorrectionApplication, CorrectionExecutor} from "../RequestCorrections.t.sol";

/// @notice Bounded public-API model; the fixture deploys the actual Core and request extension.
/// Permission suspension may be reversed. Withdrawal and retired subject identities may not.
contract RequestLifecycleHandler is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("request.invariant.app");
    bytes32 private constant RESPONSE = keccak256("request.invariant.response");
    bytes32 private constant PARAMETERS = keccak256("request.invariant.parameters");
    bytes32 private constant BURDEN = keccak256("request.invariant.burden");
    bytes32 private constant REASON = keccak256("request.invariant.correction");
    uint256 private constant MAX_REQUESTS = 6;
    uint256 private constant MAX_CHALLENGES = 12;

    RequestCorrectionApplication private application;
    CorrectionExecutor private executor;
    uint256[] private requestIds;
    uint256[] private challengeIds;
    bytes32 private allocatorSubject;
    uint64 private packageVersion = 1;
    uint256 private allocatorGeneration;
    bool private invalidSuccess;

    mapping(uint256 => bytes32) private creationHash;
    mapping(uint256 => bytes32) private sourceHash;
    mapping(uint256 => bytes32) private approvalHash;
    mapping(uint256 => bytes32) private consumptionHash;
    mapping(uint256 => bytes32) private completionHash;
    mapping(uint256 => bytes32) private filingHash;
    mapping(uint256 => bytes32) private resolutionHash;
    mapping(uint256 => uint256) private consumptions;
    mapping(uint256 => uint256) private completions;
    mapping(uint256 => uint256) private withdrawnBy;
    mapping(uint256 => uint256) private lastResolution;
    mapping(uint256 => uint256) private latestRequestByState;
    mapping(bytes32 => uint256) private consumedMeaning;

    uint256 public successfulCreations;
    uint256 public successfulApprovals;
    uint256 public successfulConsumptions;
    uint256 public successfulCompletions;
    uint256 public successfulFilings;
    uint256 public successfulResolutions;
    uint256 public successfulWithdrawals;
    uint256 public successfulResiduals;
    uint256 public successfulUnavailableClosures;
    uint256 public historicalAdmissions;
    uint256 public permissionChanges;
    uint256 public subjectDeactivations;
    uint256 public subjectReplacements;
    uint256 public expiryAdvances;
    uint256 public rejectedConsumptions;

    constructor() {
        application = new RequestCorrectionApplication(APP, RESPONSE);
        _setUpRequestAllocation(APP, application, keccak256("request.invariant.object"));
        executor = new CorrectionExecutor();
        allocatorSubject = _authority(ROLE_ALLOCATOR);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVARequestCorrectionActions.FILE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.RESOLVE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        // Every run begins with two usable approvals, rather than an all-reverting empty model.
        create();
        create();
        require(approve(0) && approve(1), "seed approvals");
    }

    function create() public returns (uint256 id) {
        return _createOccurrence(keccak256(abi.encode(PARAMETERS, successfulCreations)));
    }

    /// @notice A different source state must not replay an already consumed execution meaning.
    function createReplay(uint256 seed) public returns (uint256 id) {
        return _createOccurrence(requestAt(seed).input.parametersHash);
    }

    function _createOccurrence(bytes32 parameters) private returns (uint256 id) {
        if (requestIds.length == MAX_REQUESTS) return 0;
        uint64 expiry = uint64(block.timestamp + 7 days);
        bytes32 burden = keccak256(abi.encode(BURDEN, successfulCreations));
        uint256 state = _createRequestState(address(executor), RESPONSE, parameters, burden, expiry);
        id = _createRequest(
            AVARequestAllocation.RequestInput(state, address(executor), RESPONSE, parameters, burden, expiry)
        );
        _rememberRequest(id);
    }

    function approve(uint256 seed) public returns (bool ok) {
        uint256 id = _requestId(seed);
        bool alreadyApproved = requestAllocation.getRequest(id).allocator != address(0);
        requestVm.prank(ALLOCATOR_ACTOR);
        (ok,) = address(requestAllocation)
            .call(abi.encodeCall(AVARequestAllocation.approve, (id, ROLE_ALLOCATOR, allocatorSubject)));
        if (ok) {
            if (alreadyApproved) invalidSuccess = true;
            approvalHash[id] = _approvalHash(requestAllocation.getRequest(id));
            ++successfulApprovals;
        }
    }

    /// @param role 0: allocator execution/approval; 1: filing; 2: resolution.
    function setPermission(uint8 role, bool allowed) public {
        if (role % 3 == 0) {
            authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, allowed);
        } else if (role % 3 == 1) {
            authorityMatrix.setPermission(APP, ROLE_SOURCE, AVARequestCorrectionActions.FILE, allowed);
        } else {
            authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.RESOLVE, allowed);
        }
        ++permissionChanges;
    }

    function deactivateAllocator() public {
        if (!identityRegistry.getSubjectContext(allocatorSubject).active) return;
        identityRegistry.deactivateSubject(allocatorSubject);
        ++subjectDeactivations;
    }

    function replaceAllocator() public {
        if (identityRegistry.getSubjectContext(allocatorSubject).active || allocatorGeneration == 2) return;
        allocatorSubject = keccak256(abi.encode(APP, "replacement", ++allocatorGeneration));
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, allocatorSubject, "test:replacement");
        ++subjectReplacements;
    }

    function upgradeRules() public {
        if (packageVersion == 3) return;
        requestPackageId = _registerRequestPackage(application, ++packageVersion);
    }

    function file(uint256 seed, bool effect) public returns (bool ok) {
        if (challengeIds.length == MAX_CHALLENGES) return false;
        uint256 id = _requestId(seed);
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        uint256 evidence = _newEvidence(SOURCE_ACTOR, ROLE_SOURCE, record.packageId);
        requestVm.prank(SOURCE_ACTOR);
        bytes memory result;
        (ok, result) = address(requestAllocation)
            .call(
                abi.encodeCall(
                    AVARequestAllocation.fileRequestChallenge,
                    (
                        id,
                        effect
                            ? AVARequestAllocation.ChallengeTarget.Effect
                            : AVARequestAllocation.ChallengeTarget.Allocation,
                        evidence,
                        ROLE_SOURCE,
                        _authority(ROLE_SOURCE),
                        keccak256(abi.encode(REASON, evidence))
                    )
                )
            );
        if (ok) {
            uint256 challenge = abi.decode(result, (uint256));
            challengeIds.push(challenge);
            filingHash[challenge] = _filingHash(requestAllocation.getRequestChallenge(challenge));
            ++successfulFilings;
        }
    }

    /// @param mode 0: withdraw before consumption or retain residual afterwards; 1: reject;
    /// 2: neutral unavailable-evidence closure; 3: close against an existing withdrawal.
    function resolve(uint256 seed, uint8 mode) public returns (bool ok) {
        if (challengeIds.length == 0) return false;
        uint256 id = challengeIds[seed % challengeIds.length];
        AVARequestAllocation.RequestChallenge memory challenge = requestAllocation.getRequestChallenge(id);
        if (challenge.outcome != AVARequestAllocation.ResolutionOutcome.None) return false;
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(challenge.requestId);
        AVARequestAllocation.ResolutionOutcome outcome;
        if (mode % 4 == 0) {
            outcome = record.consumed
                ? AVARequestAllocation.ResolutionOutcome.Residual
                : AVARequestAllocation.ResolutionOutcome.Withdrawn;
        } else if (mode % 4 == 1) {
            outcome = AVARequestAllocation.ResolutionOutcome.Rejected;
        } else if (mode % 4 == 2) {
            outcome = AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable;
        } else {
            outcome = AVARequestAllocation.ResolutionOutcome.AlreadyWithdrawn;
        }
        uint256 evidence = mode % 4 >= 2 ? 0 : _newEvidence(VERIFIER_ACTOR, ROLE_VERIFIER, record.packageId);
        AVARequestAllocation.ResolutionInput memory input = AVARequestAllocation.ResolutionInput({
            challengeId: id,
            expectedPreviousResolutionId: lastResolution[record.id],
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            decisionEvidenceId: evidence,
            outcome: outcome,
            reasonHash: REASON,
            remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
            finding: _findingInput(
                outcome == AVARequestAllocation.ResolutionOutcome.Rejected
                    || outcome == AVARequestAllocation.ResolutionOutcome.Withdrawn
                    || outcome == AVARequestAllocation.ResolutionOutcome.Residual
                    || outcome == AVARequestAllocation.ResolutionOutcome.Compensate
            )
        });
        requestVm.prank(VERIFIER_ACTOR);
        (ok,) = address(requestAllocation).call(abi.encodeCall(AVARequestAllocation.resolveRequestChallenge, (input)));
        if (ok) {
            AVARequestAllocation.RequestChallenge memory resolved = requestAllocation.getRequestChallenge(id);
            if (resolved.previousResolutionId != lastResolution[record.id]) invalidSuccess = true;
            lastResolution[record.id] = id;
            resolutionHash[id] = keccak256(abi.encode(resolved));
            ++successfulResolutions;
            if (outcome == AVARequestAllocation.ResolutionOutcome.Withdrawn) {
                if (withdrawnBy[record.id] != 0 || record.consumed) invalidSuccess = true;
                withdrawnBy[record.id] = id;
                ++successfulWithdrawals;
            } else if (outcome == AVARequestAllocation.ResolutionOutcome.Residual) {
                ++successfulResiduals;
            } else if (outcome == AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable) {
                ++successfulUnavailableClosures;
            }
        }
    }

    function revokeFilingEvidence(uint256 seed) public {
        if (challengeIds.length == 0) return;
        uint256 evidence = requestAllocation.getRequestChallenge(challengeIds[seed % challengeIds.length]).evidenceId;
        if (evidenceRegistry.getEvidenceReference(evidence).status != AVACoreTypes.EvidenceStatus.Active) return;
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            REASON,
            "test:revoke"
        );
    }

    function consume(uint256 seed) public returns (bool ok) {
        uint256 id = _requestId(seed);
        bytes32 parameters = requestAllocation.getRequest(id).input.parametersHash;
        (ok,) = address(executor)
            .call(abi.encodeCall(CorrectionExecutor.consume, (requestAllocation, id, RESPONSE, parameters)));
        if (ok) {
            if (++consumptions[id] != 1 || withdrawnBy[id] != 0) invalidSuccess = true;
            if (consumedMeaning[parameters] != 0) invalidSuccess = true;
            consumedMeaning[parameters] = id;
            if (consumptionHash[id] == bytes32(0)) {
                AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
                consumptionHash[id] = keccak256(abi.encode(record.triggeredBy, record.consumedAt));
            }
            ++successfulConsumptions;
        } else {
            ++rejectedConsumptions;
        }
    }

    function complete(uint256 seed) public returns (bool ok) {
        uint256 id = _requestId(seed);
        AVARequestAllocation.RequestRecord memory beforeRecord = requestAllocation.getRequest(id);
        bytes32 effect = keccak256(abi.encode("request.invariant.effect", id));
        (ok,) = address(executor).call(abi.encodeCall(CorrectionExecutor.complete, (requestAllocation, id, effect)));
        // Bound executor completion must remain possible after consumption, despite later authority/expiry changes.
        if (beforeRecord.consumed && !beforeRecord.completed && !ok) invalidSuccess = true;
        if (ok) {
            if (++completions[id] != 1 || consumptions[id] != 1) invalidSuccess = true;
            if (completionHash[id] == bytes32(0)) {
                AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
                completionHash[id] = keccak256(abi.encode(record.effectHash, record.completedAt));
            }
            ++successfulCompletions;
        }
    }

    /// @notice Let fuzzed schedules advance a legal occurrence through its public lifecycle.
    function progress(uint256 seed) public returns (bool) {
        AVARequestAllocation.RequestRecord memory record = requestAt(seed);
        if (record.allocator == address(0) && !approve(seed)) return false;
        if (!record.consumed && !consume(seed)) return false;
        return complete(seed);
    }

    function expire(uint256 seed) public {
        uint64 expiry = requestAllocation.getRequest(_requestId(seed)).input.validUntil;
        if (block.timestamp >= expiry) return;
        requestVm.warp(expiry);
        ++expiryAdvances;
    }

    function successor(uint256 seed) public returns (uint256 id) {
        uint256 previous = _requestId(seed);
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(previous);
        if (
            requestIds.length == MAX_REQUESTS || withdrawnBy[previous] == 0 || record.consumed
                || block.timestamp >= record.input.validUntil
                || requestAllocation.requestIdByRecognisedState(record.input.recognisedStateId) != previous
        ) return 0;
        id = _createRequest(record.input);
        _rememberRequest(id);
        if (requestAllocation.getRequest(id).allocator != address(0)) invalidSuccess = true;
    }

    function requestAt(uint256 seed) public view returns (AVARequestAllocation.RequestRecord memory) {
        return requestAllocation.getRequest(_requestId(seed));
    }

    function challengeAt(uint256 seed) public view returns (AVARequestAllocation.RequestChallenge memory) {
        return requestAllocation.getRequestChallenge(challengeIds[seed % challengeIds.length]);
    }

    function executable(uint256 seed) public view returns (bool ok) {
        AVARequestAllocation.RequestRecord memory record = requestAt(seed);
        (ok,) = address(requestAllocation)
            .staticcall(
                abi.encodeCall(
                    AVARequestAllocation.validateExecution,
                    (record.id, RESPONSE, record.input.parametersHash, address(executor))
                )
            );
    }

    function assertInvariants() external view {
        require(!invalidSuccess, "invalid successful lifecycle operation");
        require(successfulCreations >= 2 && successfulApprovals >= 2, "empty handler");
        uint256 observedConsumptions;
        uint256 observedCompletions;
        for (uint256 i; i < requestIds.length; ++i) {
            uint256 id = requestIds[i];
            AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
            require(_creationHash(record) == creationHash[id], "request identity changed");
            require(
                keccak256(abi.encode(kernel.getRecognisedStateReference(record.input.recognisedStateId)))
                    == sourceHash[id],
                "correction rewrote Core source"
            );
            require(_approvalHash(record) == approvalHash[id], "approval identity changed");
            require(record.consumed == (consumptions[id] == 1) && consumptions[id] <= 1, "consumption replay/erasure");
            require(record.completed == (completions[id] == 1) && completions[id] <= 1, "completion replay/erasure");
            observedConsumptions += consumptions[id];
            observedCompletions += completions[id];
            if (record.consumed) {
                require(
                    keccak256(abi.encode(record.triggeredBy, record.consumedAt)) == consumptionHash[id],
                    "trigger changed"
                );
            }
            if (record.completed) {
                require(
                    keccak256(abi.encode(record.effectHash, record.completedAt)) == completionHash[id], "effect changed"
                );
            } else {
                require(record.effectHash == bytes32(0), "invented effect");
            }
            require(requestAllocation.withdrawalResolutionIdByRequest(id) == withdrawnBy[id], "withdrawal changed");
            require(requestAllocation.lastResolutionIdByRequest(id) == lastResolution[id], "resolution head changed");
            require(
                requestAllocation.requestIdByRecognisedState(record.input.recognisedStateId)
                    == latestRequestByState[record.input.recognisedStateId],
                "request ancestry head changed"
            );
            bool lostAllocator = record.allocator != address(0)
                && identityRegistry.subjectOf(record.allocator, APP, record.allocatorRoleKey)
                    != record.allocatorAuthorityId;
            if (
                withdrawnBy[id] != 0 || consumedMeaning[record.input.parametersHash] != 0
                    || block.timestamp >= record.input.validUntil || lostAllocator
                    || !authorityMatrix.isAuthorised(
                        ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION
                    )
            ) require(!executable(i), "closed or unauthorised request executable");
            if (withdrawnBy[id] != 0) require(!record.consumed, "withdrawn request consumed");
        }
        require(observedConsumptions == successfulConsumptions, "consumption coverage count");
        require(observedCompletions == successfulCompletions, "completion coverage count");
        require(successfulCompletions <= successfulConsumptions, "completion without consumption");
        uint256 observedResolutions;
        for (uint256 i; i < challengeIds.length; ++i) {
            uint256 id = challengeIds[i];
            AVARequestAllocation.RequestChallenge memory challenge = requestAllocation.getRequestChallenge(id);
            require(_filingHash(challenge) == filingHash[id], "filing history changed");
            if (resolutionHash[id] != bytes32(0)) {
                ++observedResolutions;
                require(keccak256(abi.encode(challenge)) == resolutionHash[id], "resolution history changed");
            } else {
                require(challenge.outcome == AVARequestAllocation.ResolutionOutcome.None, "invented resolution");
            }
        }
        require(successfulFilings == challengeIds.length, "filing coverage count");
        require(successfulResolutions == observedResolutions, "resolution coverage count");
    }

    function _rememberRequest(uint256 id) private {
        AVARequestAllocation.RequestRecord memory record = requestAllocation.getRequest(id);
        requestIds.push(id);
        creationHash[id] = _creationHash(record);
        sourceHash[id] = keccak256(abi.encode(kernel.getRecognisedStateReference(record.input.recognisedStateId)));
        approvalHash[id] = _approvalHash(record);
        latestRequestByState[record.input.recognisedStateId] = id;
        ++successfulCreations;
    }

    function _newEvidence(address actor, bytes32 role, uint256 historicalPackage) private returns (uint256 id) {
        AVAEvidenceRegistry.EvidenceRegistrationInput memory input = AVAEvidenceRegistry.EvidenceRegistrationInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: historicalPackage,
            roleKey: role,
            subjectId: _authority(role),
            commitment: keccak256(abi.encode(REASON, evidenceRegistry.nextEvidenceId())),
            evidenceTypeHash: REASON,
            disclosurePolicyId: requestPolicyId,
            authorityId: _authority(role),
            uri: "test:invariant-correction"
        });
        requestVm.prank(actor);
        if (historicalPackage == requestPackageId) {
            id = evidenceRegistry.registerEvidence(input);
        } else {
            id = evidenceRegistry.registerCorrectionEvidence(input, requestPackageId, REASON);
            ++historicalAdmissions;
        }
    }

    function _requestId(uint256 seed) private view returns (uint256) {
        return requestIds[seed % requestIds.length];
    }

    function _creationHash(AVARequestAllocation.RequestRecord memory r) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                r.id,
                r.input,
                r.recognisedStateTransitionId,
                r.supersedesRequestId,
                r.appId,
                r.workflowKey,
                r.packageId,
                r.subjectId,
                r.evidenceReceiptId,
                r.creator,
                r.creatorRoleKey,
                r.creatorAuthorityId,
                r.createdAt
            )
        );
    }

    function _approvalHash(AVARequestAllocation.RequestRecord memory r) private pure returns (bytes32) {
        return keccak256(abi.encode(r.allocator, r.allocatorRoleKey, r.allocatorAuthorityId, r.approvedAt));
    }

    function _filingHash(AVARequestAllocation.RequestChallenge memory c) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                c.id,
                c.requestId,
                c.target,
                c.challengerSubjectId,
                c.evidenceId,
                c.filingReasonHash,
                c.filedBy,
                c.filedAt,
                c.consumedAtFiling,
                c.completedAtFiling,
                c.effectHashAtFiling,
                c.sourceTransitionIdAtFiling,
                c.sourceStatusAtFiling
            )
        );
    }
}

contract RequestLifecycleInvariantTest {
    struct FuzzSelector {
        address addr;
        bytes4[] selectors;
    }

    RequestLifecycleHandler private handler;

    function setUp() public {
        handler = new RequestLifecycleHandler();
    }

    // Native Foundry discovery ABI, without importing forge-std.
    function targetContracts() public view returns (address[] memory targets) {
        targets = new address[](1);
        targets[0] = address(handler);
    }

    function targetSelectors() public view returns (FuzzSelector[] memory targets) {
        bytes4[] memory selectors = new bytes4[](15);
        selectors[0] = RequestLifecycleHandler.create.selector;
        selectors[1] = RequestLifecycleHandler.approve.selector;
        selectors[2] = RequestLifecycleHandler.setPermission.selector;
        selectors[3] = RequestLifecycleHandler.deactivateAllocator.selector;
        selectors[4] = RequestLifecycleHandler.replaceAllocator.selector;
        selectors[5] = RequestLifecycleHandler.upgradeRules.selector;
        selectors[6] = RequestLifecycleHandler.file.selector;
        selectors[7] = RequestLifecycleHandler.resolve.selector;
        selectors[8] = RequestLifecycleHandler.revokeFilingEvidence.selector;
        selectors[9] = RequestLifecycleHandler.consume.selector;
        selectors[10] = RequestLifecycleHandler.complete.selector;
        selectors[11] = RequestLifecycleHandler.expire.selector;
        selectors[12] = RequestLifecycleHandler.successor.selector;
        selectors[13] = RequestLifecycleHandler.createReplay.selector;
        selectors[14] = RequestLifecycleHandler.progress.selector;
        targets = new FuzzSelector[](1);
        targets[0] = FuzzSelector(address(handler), selectors);
    }

    function invariantRequestHistoryAndExecution() public view {
        handler.assertInvariants();
    }

    function testWitnessDistinctOccurrencesBothExecuteAndComplete() public {
        require(handler.progress(0), "first occurrence lifecycle");
        require(handler.progress(1), "second occurrence lifecycle");
        require(handler.successfulConsumptions() == 2 && handler.successfulCompletions() == 2, "execution absent");
        handler.assertInvariants();
    }

    function testWitnessDifferentSourceCannotReplayConsumedMeaning() public {
        require(handler.createReplay(0) != 0 && handler.approve(2), "replay candidate absent");
        require(
            handler.requestAt(0).input.recognisedStateId != handler.requestAt(2).input.recognisedStateId,
            "not a distinct source"
        );
        require(handler.progress(0), "original occurrence lifecycle");
        require(!handler.consume(0) && !handler.complete(0), "same-request replay");
        require(!handler.executable(2) && !handler.consume(2), "cross-source meaning replay");
        require(handler.successfulConsumptions() == 1 && handler.successfulCompletions() == 1, "duplicate effect");
        handler.assertInvariants();
    }

    function testWitnessPermissionRestorationAndResidualCompletionAfterRevocation() public {
        handler.setPermission(0, false);
        require(!handler.consume(0) && !handler.executable(0), "revocation ineffective");
        handler.setPermission(0, true);
        require(handler.executable(0), "permission suspension became withdrawal");
        require(handler.file(0, false), "pending filing");
        require(handler.executable(0) && handler.consume(0), "filing suspended execution");
        handler.setPermission(0, false);
        handler.deactivateAllocator();
        require(handler.resolve(0, 0), "residual decision");
        require(handler.successfulResiduals() == 1, "residual route absent");
        require(handler.complete(0), "consumed completion lost authority independence");
        require(!handler.consume(0) && !handler.complete(0), "effect replay");
        require(handler.file(0, true) && handler.resolve(1, 1), "completed-effect concern");
        require(handler.successfulConsumptions() == 1 && handler.successfulCompletions() == 1, "execution absent");
        require(handler.successfulResolutions() == 2, "correction routes absent");
        handler.assertInvariants();
    }

    function testWitnessHistoricalWithdrawalAndFreshSuccessorDecision() public {
        uint256 originalPackage = handler.requestAt(0).packageId;
        handler.upgradeRules();
        handler.upgradeRules();
        require(handler.file(0, false) && handler.file(0, false), "historical filings");
        require(handler.resolve(0, 0), "historical withdrawal");
        handler.setPermission(0, false);
        handler.setPermission(0, true);
        require(!handler.executable(0) && !handler.consume(0), "withdrawal reversed");
        require(handler.resolve(1, 3), "retained withdrawal closure");
        require(handler.successor(0) != 0, "successor missing");
        require(!handler.executable(2) && !handler.consume(2), "successor inherited approval");
        require(handler.approve(2) && handler.consume(2) && handler.complete(2), "fresh successor lifecycle");
        require(handler.requestAt(0).packageId == originalPackage, "historical rule identity lost");
        require(handler.requestAt(2).supersedesRequestId == handler.requestAt(0).id, "ancestry lost");
        require(handler.historicalAdmissions() == 3 && handler.successfulWithdrawals() == 1, "historical routes absent");
        handler.assertInvariants();
    }

    function testWitnessFreshSubjectCannotReviveOriginalApproval() public {
        bytes32 originalAuthority = handler.requestAt(0).allocatorAuthorityId;
        handler.deactivateAllocator();
        require(!handler.consume(0), "inactive subject executed");
        handler.replaceAllocator();
        require(!handler.executable(0) && !handler.consume(0), "new subject inherited old approval");
        require(handler.create() != 0 && handler.approve(2), "fresh subject decision");
        require(handler.requestAt(2).allocatorAuthorityId != originalAuthority, "subject replacement absent");
        require(handler.consume(2) && handler.complete(2), "fresh subject lifecycle");
        require(handler.subjectDeactivations() == 1 && handler.subjectReplacements() == 1, "identity routes absent");
        handler.assertInvariants();
    }

    function testWitnessExpiryAndUnavailableEvidencePreserveConsumedCompletion() public {
        require(handler.file(0, false), "filing absent");
        handler.revokeFilingEvidence(0);
        require(handler.resolve(0, 2), "neutral unavailable closure");
        require(handler.consume(0), "neutral closure suspended request");
        handler.expire(0);
        require(!handler.executable(1) && !handler.consume(1), "expiry boundary ineffective");
        require(handler.complete(0), "expiry prevented consumed completion");
        require(
            handler.expiryAdvances() == 1 && handler.successfulUnavailableClosures() == 1,
            "closure/expiry routes absent"
        );
        handler.assertInvariants();
    }
}
