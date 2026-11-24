// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {IAVAApplicationModule} from "../src/interfaces/IAVAApplicationModule.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {IAVAExtensionPolicyModule} from "../src/extensions/shared/IAVAExtensionPolicyModule.sol";
import {IAVAChallengePolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {IAVACorrectionReview} from "../src/core/interfaces/IAVACorrectionReview.sol";
import {
    AVARequestAllocation,
    AVARequestCorrectionActions,
    AVARequestCompensation
} from "../src/extensions/requests/AVARequestAllocation.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";

contract RequestCorrectionApplication is IAVAApplicationModule, RuleModuleIdentity {
    bytes32 public immutable APP_ID;
    bytes32 public immutable RESPONSE;
    bytes32 private constant SOURCE_ROLE = keccak256("ava.test.request.role.source.v1");
    bytes32 private constant VERIFIER_ROLE = keccak256("ava.test.request.role.verifier.v1");
    bytes32 private constant ALLOCATOR_ROLE = keccak256("ava.test.request.role.allocator.v1");

    constructor(bytes32 app, bytes32 response) {
        APP_ID = app;
        RESPONSE = response;
    }

    function applicationId() external view returns (bytes32) {
        return APP_ID;
    }

    function validateGovernedObject(GovernedObjectContext calldata c) external view {
        require(c.appId == APP_ID);
    }

    function validateRecognisedStateFormation(RecognisedStateFormationContext calldata c) external view {
        require(c.appId == APP_ID);
    }

    function validateRecognisedStateTransition(RecognisedStateTransitionContext calldata c) external view {
        require(c.appId == APP_ID);
    }

    function validateEvidence(EvidenceContext calldata c) external view {
        require(c.appId == APP_ID && c.subjectId == c.authorityId);
    }

    function validateDownstreamRecord(DownstreamRecordContext calldata c) external view {
        require(c.appId == APP_ID && c.recordTypeKey == RESPONSE, "correction application scope");
        if (c.actionKey == AVACoreTypes.ACTION_RECORD_ALLOCATION) {
            require(c.roleKey == ALLOCATOR_ROLE, "allocator");
        } else if (c.actionKey == AVARequestCorrectionActions.FILE) {
            require(c.roleKey == SOURCE_ROLE, "challenger");
        } else {
            require(
                c.actionKey == AVARequestCorrectionActions.RESOLVE
                    || c.actionKey == AVARequestCorrectionActions.AUTHORISE_REMEDY,
                "correction action"
            );
            require(c.roleKey == VERIFIER_ROLE, "resolver");
        }
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(APP_ID, RESPONSE));
    }
}

contract CorrectionExecutor {
    function consume(AVARequestAllocation allocation, uint256 requestId, bytes32 response, bytes32 parameters)
        external
    {
        allocation.consume(requestId, response, parameters, msg.sender);
    }

    function complete(AVARequestAllocation allocation, uint256 requestId, bytes32 effect) external {
        allocation.complete(requestId, effect);
    }
}

contract CorrectionTransitionRequester is RuleModuleIdentity {
    function change(AVAGovernanceKernel kernel, AVAGovernanceKernel.SourceBoundTransitionInput calldata input)
        external
    {
        kernel.requestSourceBoundTransition(input);
    }
}

contract RejectCorrectionExtensionPolicy is IAVAExtensionPolicyModule, RuleModuleIdentity {
    bytes32 private immutable rejectedAction;

    constructor(bytes32 action) {
        rejectedAction = action;
    }

    function validateExtensionRecord(ExtensionPolicyContext calldata c) external view {
        require(c.actionKey != rejectedAction, "correction extension policy rejected");
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return rejectedAction;
    }
}

contract RejectCorrectionChallengePolicy is IAVAChallengePolicyModule, RuleModuleIdentity {
    bytes32 private immutable rejectedAction;

    constructor(bytes32 action) {
        rejectedAction = action;
    }

    function validateChallenge(ChallengeContext calldata c) external view {
        require(c.actionKey != rejectedAction, "correction challenge policy rejected");
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return rejectedAction;
    }
}

contract CorrectionToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint8 public mode;
    AVARequestAllocation private reentryTarget;
    uint256 private reentryChallenge;
    bool public reentryAttempted;
    bool public reentryRejected;

    function configureReentry(AVARequestAllocation target, uint256 challenge) external {
        reentryTarget = target;
        reentryChallenge = challenge;
        allowance[address(this)][address(target)] = 100;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function setMode(uint8 next) external {
        mode = next;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        if (address(reentryTarget) != address(0) && !reentryAttempted) {
            reentryAttempted = true;
            (bool ok,) =
                address(reentryTarget).call(abi.encodeCall(AVARequestAllocation.fundCompensation, (reentryChallenge)));
            reentryRejected = !ok;
            require(!ok, "reentrant funding succeeded");
        }
        if (mode == 1) return false;
        if (mode == 2) return true;
        allowance[from][msg.sender] -= amount;
        _move(from, to, amount);
        if (mode == 4) {
            assembly ("memory-safe") { return(0, 0) }
        }
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        if (mode == 1) return false;
        if (mode == 2) return true;
        _move(msg.sender, to, amount);
        if (mode == 4) {
            assembly ("memory-safe") { return(0, 0) }
        }
        return true;
    }

    function _move(address from, address to, uint256 amount) private {
        balanceOf[from] -= amount;
        balanceOf[to] += mode == 3 ? amount - 1 : amount;
    }
}

contract RequestCorrectionsTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("request.correction.app");
    bytes32 private constant RESPONSE = keccak256("request.correction.response");
    bytes32 private constant PARAMETERS = keccak256("request.correction.parameters");
    bytes32 private constant BURDEN = keccak256("request.correction.burden");
    bytes32 private constant REASON = keccak256("request.correction.issue");
    bytes32 private constant EFFECT = keccak256("request.correction.original.effect");
    CorrectionExecutor private executor;
    RequestCorrectionApplication private application;
    CorrectionTransitionRequester private transitionRequester;
    address private constant BENEFICIARY = address(0xB1);

    function setUp() public {
        application = new RequestCorrectionApplication(APP, RESPONSE);
        _setUpRequestAllocation(APP, application, keccak256("request.correction.object"));
        executor = new CorrectionExecutor();
        transitionRequester = new CorrectionTransitionRequester();
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(transitionRequester));
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVARequestCorrectionActions.FILE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.RESOLVE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REGISTER_EVIDENCE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RECORD_EVIDENCE_LIFECYCLE, true);
    }

    function testSubstantiveResolutionRequiresBoundedClaimWithoutOrphanFinding() public {
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        input.finding.claimHash = bytes32(0);
        _expectResolutionRevert(input);
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        uint256 caseId = requestAllocation.correctionReviewCaseIdByChallenge(challenge);
        require(corrections.findingIdByCase(caseId) == 0, "failed claim left causal finding");
        requestVm.expectRevert();
        corrections.getFinding(1);
        require(
            requestAllocation.lastResolutionIdByRequest(id) == 0
                && requestAllocation.getRequestChallenge(challenge).outcome
                    == AVARequestAllocation.ResolutionOutcome.None,
            "failed claim changed Allocation"
        );
        input.finding = _findingInput(true);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        require(corrections.findingIdByCase(caseId) == 1, "valid claim missing");
    }

    function testIndependentWithdrawalPreservesSourceAndRequiresFreshSuccessorApproval() public {
        uint256 id = _approved();
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(id);
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        require(
            requestAllocation.validateExecution(id, RESPONSE, PARAMETERS, address(executor)),
            "bare challenge suspended execution"
        );
        _resolve(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == challenge, "withdrawal missing");
        require(
            kernel.getRecognisedStateReference(original.input.recognisedStateId).lastTransitionId
                == original.recognisedStateTransitionId,
            "source corrected by allocation review"
        );
        requestVm.expectRevert();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        uint256 successor = _createRequest(original.input);
        AVARequestAllocation.RequestRecord memory next = requestAllocation.getRequest(successor);
        require(next.supersedesRequestId == id && next.allocator == address(0), "fresh decision missing");
        require(
            next.input.validUntil == original.input.validUntil && next.input.parametersHash == PARAMETERS,
            "commitment changed"
        );
        requestVm.expectRevert();
        executor.consume(requestAllocation, successor, RESPONSE, PARAMETERS);
        _approveRequest(successor);
        executor.consume(requestAllocation, successor, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, successor, EFFECT);
        require(
            !requestAllocation.getRequest(id).consumed && requestAllocation.getRequest(id).allocator == ALLOCATOR_ACTOR,
            "original facts changed"
        );
    }

    function testExecutionRacingPendingChallengeRequiresResidualAndStillAllowsCompletion() public {
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        AVARequestAllocation.ResolutionInput memory withdrawal =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(withdrawal);
        _resolve(challenge, AVARequestAllocation.ResolutionOutcome.Residual, 0);
        AVARequestAllocation.RequestChallenge memory receipt = requestAllocation.getRequestChallenge(challenge);
        require(
            !receipt.consumedAtFiling && receipt.consumedAtResolution && !receipt.completedAtResolution,
            "race not recorded"
        );
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == 0, "consumption withdrawn");
        executor.complete(requestAllocation, id, EFFECT);
        require(requestAllocation.getRequest(id).effectHash == EFFECT, "residual blocked completion");
        requestVm.expectRevert();
        executor.complete(requestAllocation, id, keccak256("different.effect"));
    }

    function testUnavailableFilingEvidenceClosesNeutrallyAndAllowsFreshEvidenceIssue() public {
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable, 0);
        input.decisionEvidenceId = 0;
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        uint256 filingEvidence = requestAllocation.getRequestChallenge(challenge).evidenceId;
        _revoke(filingEvidence, SOURCE_ACTOR, ROLE_SOURCE);
        input.finding = _findingInput(true);
        _expectResolutionRevert(input);
        input.finding = _findingInput(false);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        require(
            kernel.CORRECTIONS().findingIdByCase(requestAllocation.correctionReviewCaseIdByChallenge(challenge)) == 0,
            "neutral closure manufactured finding"
        );
        AVARequestAllocation.RequestChallenge memory receipt = requestAllocation.getRequestChallenge(challenge);
        require(
            receipt.outcome == AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable
                && receipt.decisionEvidenceId == 0,
            "unavailable decision missing"
        );
        require(receipt.evidenceId == filingEvidence && receipt.filingReasonHash == REASON, "filing receipt changed");
        require(
            requestAllocation.withdrawalResolutionIdByRequest(id) == 0 && !requestAllocation.getRequest(id).cancelled,
            "unavailability was adverse"
        );
        require(
            kernel.getRecognisedStateReference(requestAllocation.getRequest(id).input.recognisedStateId).status
                == AVACoreTypes.RecognisedStateStatus.Vested,
            "unavailable corrected source"
        );
        uint256 freshEvidence = _freshEvidence(SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        uint256 next = requestAllocation.fileRequestChallenge(
            id,
            AVARequestAllocation.ChallengeTarget.Allocation,
            freshEvidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            REASON
        );
        require(next != challenge, "challenger permanently excluded");
    }

    function testRejectedConcernKeepsExecutionAndLaterResolutionAppendsWithoutOverwrite() public {
        uint256 id = _approved();
        uint256 first = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        _resolve(first, AVARequestAllocation.ResolutionOutcome.Rejected, 0);
        AVARequestAllocation.RequestChallenge memory rejected = requestAllocation.getRequestChallenge(first);
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == 0, "rejection withdrew decision");
        require(
            requestAllocation.validateExecution(id, RESPONSE, PARAMETERS, address(executor)),
            "rejection blocked execution"
        );
        uint256 evidenceId = _freshEvidence(SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        uint256 second = requestAllocation.fileRequestChallenge(
            id,
            AVARequestAllocation.ChallengeTarget.Allocation,
            evidenceId,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            REASON
        );
        AVARequestAllocation.ResolutionInput memory stale =
            _resolutionInput(second, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(stale);
        require(
            requestAllocation.getRequestChallenge(second).outcome == AVARequestAllocation.ResolutionOutcome.None,
            "stale decision partly written"
        );
        _resolve(second, AVARequestAllocation.ResolutionOutcome.Withdrawn, first);
        require(
            requestAllocation.lastResolutionIdByRequest(id) == second
                && requestAllocation.getRequestChallenge(second).previousResolutionId == first,
            "resolution chain missing"
        );
        require(
            requestAllocation.getRequestChallenge(first).resolutionHash == rejected.resolutionHash,
            "old resolution overwritten"
        );
        stale.challengeId = first;
        stale.expectedPreviousResolutionId = second;
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(stale);
    }

    function testOneFindingSupportsResidualThenSeparatelyAuthorisedCompensationAndActualPayment() public {
        uint256 id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, id, EFFECT);
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(id);
        bytes32 requestHistory = keccak256(abi.encode(original));
        bytes32 sourceHistory =
            keccak256(abi.encode(kernel.getRecognisedStateReference(original.input.recognisedStateId)));
        uint256 first = _file(id, AVARequestAllocation.ChallengeTarget.Effect);
        _resolve(first, AVARequestAllocation.ResolutionOutcome.Residual, 0);
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        uint256 findingId = corrections.findingIdByCase(requestAllocation.correctionReviewCaseIdByChallenge(first));
        require(findingId != 0, "residual lacks finding");
        bytes32 findingHistory = keccak256(abi.encode(corrections.getFinding(findingId)));
        bytes32 firstHistory = keccak256(abi.encode(requestAllocation.getRequestChallenge(first)));
        uint256 second = _fileFreshEffect(id);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(second, AVARequestAllocation.ResolutionOutcome.Compensate, first);
        input.finding.existingFindingId = findingId;
        CorrectionToken asset = new CorrectionToken();
        input.remedy = AVARequestAllocation.RemedyTerms(address(asset), BENEFICIARY, 100);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, false);
        _expectResolutionRevert(input);
        uint256 secondCase = requestAllocation.correctionReviewCaseIdByChallenge(second);
        require(corrections.findingIdByCase(secondCase) == 0, "failed remedy bound finding");
        require(requestAllocation.getCompensation(second).terms.amount == 0, "finding granted remedy authority");
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, true);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        require(corrections.findingIdByCase(secondCase) == findingId, "reused claim formed new finding");
        require(
            keccak256(abi.encode(corrections.getFinding(findingId))) == findingHistory, "finding consumed or rewritten"
        );
        requestVm.expectRevert();
        corrections.getFinding(findingId + 1);
        require(
            keccak256(abi.encode(requestAllocation.getRequestChallenge(first))) == firstHistory,
            "first disposition changed"
        );
        require(
            keccak256(abi.encode(requestAllocation.getRequest(id))) == requestHistory,
            "Allocation review rewrote effect history"
        );
        require(
            keccak256(abi.encode(kernel.getRecognisedStateReference(original.input.recognisedStateId)))
                == sourceHistory,
            "Allocation review changed valid source"
        );
        // Authorised fixed terms remain executable even after the original source and finding evidence disappear.
        _revoke(original.evidenceReceiptId, SOURCE_ACTOR, ROLE_SOURCE);
        _revoke(corrections.getFinding(findingId).evidenceId, VERIFIER_ACTOR, ROLE_VERIFIER);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, false);
        asset.mint(address(this), 100);
        asset.approve(address(requestAllocation), 100);
        requestAllocation.fundCompensation(second);
        requestVm.prank(BENEFICIARY);
        requestAllocation.claimCompensation(second);
        require(
            asset.balanceOf(BENEFICIARY) == 100 && requestAllocation.getCompensation(second).paid, "fixed remedy unpaid"
        );
        require(
            keccak256(abi.encode(requestAllocation.getRequest(id))) == requestHistory, "payment erased original effect"
        );
        require(corrections.findingIdByCase(secondCase) == findingId, "payment required another finding");
        requestVm.prank(BENEFICIARY);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(second);
    }

    function testFindingReuseRejectsChangedClaimScopeBurdenTargetAndRevokedOriginalEvidence() public {
        uint256 id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, id, EFFECT);
        uint256 first = _file(id, AVARequestAllocation.ChallengeTarget.Effect);
        _resolve(first, AVARequestAllocation.ResolutionOutcome.Residual, 0);
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        uint256 findingId = corrections.findingIdByCase(requestAllocation.correctionReviewCaseIdByChallenge(first));
        uint256 second = _fileFreshEffect(id);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(second, AVARequestAllocation.ResolutionOutcome.Residual, first);
        input.finding.existingFindingId = findingId;
        input.finding.claimHash = keccak256("different accepted claim");
        _expectResolutionRevert(input);
        input.finding = _findingInput(true);
        input.finding.existingFindingId = findingId;
        input.finding.useScopeHash = keccak256("broader correction use");
        _expectResolutionRevert(input);
        input.finding = _findingInput(true);
        input.finding.existingFindingId = findingId;
        input.finding.burdenHash = keccak256("different evidential burden");
        _expectResolutionRevert(input);
        input.finding = _findingInput(true);
        input.finding.existingFindingId = findingId;
        bytes32 otherParameters = keccak256("different actual target");
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 state = _createRequestState(address(executor), RESPONSE, otherParameters, BURDEN, expiry);
        uint256 other = _createRequest(
            AVARequestAllocation.RequestInput(state, address(executor), RESPONSE, otherParameters, BURDEN, expiry)
        );
        _approveRequest(other);
        executor.consume(requestAllocation, other, RESPONSE, otherParameters);
        executor.complete(requestAllocation, other, EFFECT);
        uint256 otherChallenge = _file(other, AVARequestAllocation.ChallengeTarget.Effect);
        AVARequestAllocation.ResolutionInput memory foreign =
            _resolutionInput(otherChallenge, AVARequestAllocation.ResolutionOutcome.Residual, 0);
        foreign.finding.existingFindingId = findingId;
        _expectResolutionRevert(foreign);
        _revoke(corrections.getFinding(findingId).evidenceId, VERIFIER_ACTOR, ROLE_VERIFIER);
        _expectResolutionRevert(input);
        require(
            corrections.findingIdByCase(requestAllocation.correctionReviewCaseIdByChallenge(second)) == 0
                && corrections.findingIdByCase(requestAllocation.correctionReviewCaseIdByChallenge(otherChallenge))
                    == 0,
            "rejected reuse left causal link"
        );
        require(
            requestAllocation.lastResolutionIdByRequest(id) == first
                && requestAllocation.lastResolutionIdByRequest(other) == 0,
            "rejected reuse changed dispositions"
        );
        requestVm.expectRevert();
        corrections.getFinding(findingId + 1);
    }

    function testFindingReuseRequiresActiveOriginalBasisWithFreshReceivingResolver() public {
        uint256 id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, id, EFFECT);
        uint256 first = _file(id, AVARequestAllocation.ChallengeTarget.Effect);
        _resolve(first, AVARequestAllocation.ResolutionOutcome.Residual, 0);
        IAVACorrectionReview corrections = kernel.CORRECTIONS();
        uint256 findingId = corrections.findingIdByCase(requestAllocation.correctionReviewCaseIdByChallenge(first));
        bytes32 findingHistory = keccak256(abi.encode(corrections.getFinding(findingId)));
        bytes32 firstHistory = keccak256(abi.encode(requestAllocation.getRequestChallenge(first)));
        bytes32 requestHistory = keccak256(abi.encode(requestAllocation.getRequest(id)));
        uint256 second = _fileFreshEffect(id);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(second, AVARequestAllocation.ResolutionOutcome.Residual, first);
        address freshVerifier = address(0xC3);
        bytes32 freshAuthority = keccak256("correction.fresh.verifier");
        identityRegistry.assignSubject(freshVerifier, APP, ROLE_VERIFIER, freshAuthority, "test:fresh-verifier");
        input.authorityId = freshAuthority;
        requestVm.prank(freshVerifier);
        input.decisionEvidenceId = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_VERIFIER,
                subjectId: freshAuthority,
                commitment: keccak256("fresh.resolver.decision"),
                evidenceTypeHash: keccak256("correction.decision"),
                disclosurePolicyId: requestPolicyId,
                authorityId: freshAuthority,
                uri: "test:fresh-resolver-evidence"
            })
        );
        input.finding.existingFindingId = findingId;
        identityRegistry.deactivateSubject(_authority(ROLE_VERIFIER));
        require(
            !evidenceRegistry.isEvidenceAvailableForPackage(
                corrections.getFinding(findingId).evidenceId, requestPackageId
            ),
            "inactive original basis remains available"
        );
        require(
            evidenceRegistry.isEvidenceAvailableForPackage(input.decisionEvidenceId, requestPackageId),
            "fresh receiving evidence unavailable"
        );
        requestVm.prank(freshVerifier);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        uint256 secondCase = requestAllocation.correctionReviewCaseIdByChallenge(second);
        require(
            corrections.findingIdByCase(secondCase) == 0
                && requestAllocation.getRequestChallenge(second).outcome == AVARequestAllocation.ResolutionOutcome.None
                && requestAllocation.lastResolutionIdByRequest(id) == first,
            "unavailable finding reuse partly committed"
        );
        require(
            keccak256(abi.encode(corrections.getFinding(findingId))) == findingHistory
                && keccak256(abi.encode(requestAllocation.getRequestChallenge(first))) == firstHistory
                && keccak256(abi.encode(requestAllocation.getRequest(id))) == requestHistory,
            "refused reuse changed history"
        );
        input.finding.existingFindingId = 0;
        input.finding.supersedesFindingId = findingId;
        requestVm.prank(freshVerifier);
        requestAllocation.resolveRequestChallenge(input);
        uint256 freshFindingId = corrections.findingIdByCase(secondCase);
        require(
            freshFindingId == findingId + 1 && corrections.getFinding(freshFindingId).verifier == freshVerifier
                && corrections.getFinding(freshFindingId).evidenceId == input.decisionEvidenceId
                && corrections.getFinding(freshFindingId).supersedesFindingId == findingId
                && requestAllocation.lastResolutionIdByRequest(id) == second,
            "fresh finding and disposition unavailable"
        );
        require(
            keccak256(abi.encode(corrections.getFinding(findingId))) == findingHistory
                && keccak256(abi.encode(requestAllocation.getRequestChallenge(first))) == firstHistory
                && keccak256(abi.encode(requestAllocation.getRequest(id))) == requestHistory,
            "fresh finding rewrote history"
        );
    }

    function testCompensationNeedsFreshFundsAndPaysOnlyFixedRecipientOnce() public {
        CorrectionToken asset = new CorrectionToken();
        (uint256 id, uint256 challenge) = _compensate(asset);
        AVARequestAllocation.CompensationRecord memory receipt = requestAllocation.getCompensation(challenge);
        require(
            !receipt.funded && !receipt.paid && receipt.terms.amount == 100 && receipt.terms.recipient == BENEFICIARY,
            "authorization fabricated funding"
        );
        requestVm.prank(BENEFICIARY);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(challenge);
        asset.mint(address(this), 100);
        asset.approve(address(requestAllocation), 100);
        requestAllocation.fundCompensation(challenge);
        receipt = requestAllocation.getCompensation(challenge);
        require(receipt.funded && !receipt.paid && receipt.funder == address(this), "funding fabricated payment");
        require(asset.balanceOf(address(requestAllocation)) == 100, "fresh funds missing");
        requestVm.expectRevert();
        requestAllocation.fundCompensation(challenge);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(challenge);
        _revoke(requestAllocation.getRequest(id).evidenceReceiptId, SOURCE_ACTOR, ROLE_SOURCE);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, false);
        applicationRegistry.proposeApplicationAdmin(APP, address(0xAD1));
        requestVm.prank(address(0xAD1));
        applicationRegistry.acceptApplicationAdmin(APP);
        applicationRegistry.proposeAdmin(address(0xAD2));
        requestVm.prank(address(0xAD2));
        applicationRegistry.acceptAdmin();
        requestVm.warp(block.timestamp + 2 days);
        requestVm.prank(BENEFICIARY);
        requestAllocation.claimCompensation(challenge);
        receipt = requestAllocation.getCompensation(challenge);
        require(
            receipt.paid && receipt.paymentHash != bytes32(0) && receipt.paidAt > receipt.fundedAt,
            "payment receipt missing"
        );
        require(
            asset.balanceOf(BENEFICIARY) == 100 && asset.balanceOf(address(requestAllocation)) == 0,
            "fixed payment missing"
        );
        require(
            requestAllocation.getRequest(id).effectHash == EFFECT && requestAllocation.getRequest(id).completed,
            "compensation erased effect"
        );
        requestVm.prank(BENEFICIARY);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(challenge);
    }

    function testSecondPendingConcernCanCloseAgainstRetainedWithdrawal() public {
        uint256 id = _approved();
        uint256 first = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        uint256 evidence = _freshEvidence(SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        uint256 second = requestAllocation.fileRequestChallenge(
            id,
            AVARequestAllocation.ChallengeTarget.Allocation,
            evidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            keccak256("second.concern")
        );
        AVARequestAllocation.ResolutionInput memory close =
            _resolutionInput(second, AVARequestAllocation.ResolutionOutcome.AlreadyWithdrawn, 0);
        close.decisionEvidenceId = 0;
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(close);
        _resolve(first, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        close.expectedPreviousResolutionId = first;
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(close);
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == first, "withdrawal pointer overwritten");
        require(
            requestAllocation.lastResolutionIdByRequest(id) == second
                && requestAllocation.getRequestChallenge(second).previousResolutionId == first,
            "neutral chain missing"
        );
        require(
            requestAllocation.getRequestChallenge(first).outcome == AVARequestAllocation.ResolutionOutcome.Withdrawn,
            "first decision overwritten"
        );
        requestVm.expectRevert();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        uint256 successor = _createRequest(requestAllocation.getRequest(id).input);
        require(requestAllocation.getRequest(successor).supersedesRequestId == id, "successor history missing");
        requestVm.expectRevert();
        executor.consume(requestAllocation, successor, RESPONSE, PARAMETERS);
        _approveRequest(successor);
        executor.consume(requestAllocation, successor, RESPONSE, PARAMETERS);
    }

    function testFilingRequiresApprovedTargetAndOwnActiveEvidence() public {
        uint256 id = _unapproved();
        uint256 evidence = requestAllocation.getRequest(id).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Allocation, evidence, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
        _approveRequest(id);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Effect, evidence, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
        uint256 someoneElsesEvidence = _decisionEvidence();
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.fileRequestChallenge(
            id,
            AVARequestAllocation.ChallengeTarget.Allocation,
            someoneElsesEvidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            REASON
        );
        _revoke(evidence, SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Allocation, evidence, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
        require(requestAllocation.nextRequestChallengeId() == 1, "failed filing left receipt");
    }

    function testCorrectionRequiresCurrentAppAuthorityAndExcludesBothConflictedAccounts() public {
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        input.authorityId = _authority(ROLE_SOURCE);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        bytes32 challengerResolver = keccak256("challenger.verifier");
        identityRegistry.assignSubject(SOURCE_ACTOR, APP, ROLE_VERIFIER, challengerResolver, "test:conflicted");
        input.authorityId = challengerResolver;
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        bytes32 allocatorResolver = keccak256("allocator.verifier");
        identityRegistry.assignSubject(
            ALLOCATOR_ACTOR, APP, ROLE_VERIFIER, allocatorResolver, "test:allocator-conflicted"
        );
        input.authorityId = allocatorResolver;
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        input.authorityId = _authority(ROLE_VERIFIER);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.RESOLVE, false);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        require(requestAllocation.lastResolutionIdByRequest(id) == 0, "unauthorised decision written");
    }

    function testOtherAppAuthorityCannotFileOrResolve() public {
        uint256 id = _approved();
        uint256 evidence = requestAllocation.getRequest(id).evidenceReceiptId;
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        bytes32 otherApp = keccak256("correction.other.app");
        bytes32 otherSubject = keccak256("correction.other.subject");
        applicationRegistry.registerApplication(
            otherApp, keccak256("other.identity"), keccak256("other.authority"), address(this), "test:other"
        );
        identityRegistry.assignSubject(address(this), otherApp, ROLE_VERIFIER, otherSubject, "test:other");
        authorityMatrix.setPermission(otherApp, ROLE_VERIFIER, AVARequestCorrectionActions.RESOLVE, true);
        authorityMatrix.setPermission(otherApp, ROLE_VERIFIER, AVARequestCorrectionActions.FILE, true);
        requestVm.expectRevert();
        requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Allocation, evidence, ROLE_VERIFIER, otherSubject, REASON
        );
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        input.authorityId = otherSubject;
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
    }

    function testRuleUpgradeAllowsNewEvidenceToFileAndWithdrawHistoricalAllocation() public {
        uint256 id = _approved();
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(id);
        requestPackageId = _registerRequestPackage(application, 2);
        uint256 filing = _historicalEvidence(SOURCE_ACTOR, ROLE_SOURCE, original.packageId);
        requestVm.prank(SOURCE_ACTOR);
        uint256 challenge = requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Allocation, filing, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
        AVARequestAllocation.ResolutionInput memory input = AVARequestAllocation.ResolutionInput({
            challengeId: challenge,
            expectedPreviousResolutionId: 0,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            decisionEvidenceId: _historicalEvidence(VERIFIER_ACTOR, ROLE_VERIFIER, original.packageId),
            outcome: AVARequestAllocation.ResolutionOutcome.Withdrawn,
            reasonHash: REASON,
            remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
            finding: _findingInput(true)
        });
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        uint256 successor = _createRequest(original.input);
        require(requestAllocation.getRequest(successor).approvedAt == 0, "correction auto-approved successor");
        _approveRequest(successor);
        executor.consume(requestAllocation, successor, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, successor, EFFECT);
        require(requestAllocation.getRequest(successor).supersedesRequestId == id, "predecessor lost");
        require(requestAllocation.getRequest(id).packageId == original.packageId, "original package rewritten");
        require(!requestAllocation.getRequest(id).consumed, "withdrawn request consumed");
    }

    function testFuzzRuleUpgradeCorrectionRetainsExecutionAndHistory(
        uint8 extraUpgrades,
        bool consumeFirst,
        bool finishFirst
    ) public {
        uint256 id = _approved();
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(id);
        if (consumeFirst) {
            executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
            if (finishFirst) executor.complete(requestAllocation, id, EFFECT);
        }
        uint64 lastVersion = 2 + uint64(extraUpgrades % 3);
        for (uint64 version = 2; version <= lastVersion; ++version) {
            requestPackageId = _registerRequestPackage(application, version);
        }
        uint256 filing = _historicalEvidence(SOURCE_ACTOR, ROLE_SOURCE, original.packageId);
        requestVm.prank(SOURCE_ACTOR);
        uint256 challenge = requestAllocation.fileRequestChallenge(
            id,
            consumeFirst && finishFirst
                ? AVARequestAllocation.ChallengeTarget.Effect
                : AVARequestAllocation.ChallengeTarget.Allocation,
            filing,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            REASON
        );
        AVARequestAllocation.ResolutionInput memory input = AVARequestAllocation.ResolutionInput({
            challengeId: challenge,
            expectedPreviousResolutionId: 0,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            decisionEvidenceId: _historicalEvidence(VERIFIER_ACTOR, ROLE_VERIFIER, original.packageId),
            outcome: consumeFirst
                ? AVARequestAllocation.ResolutionOutcome.Residual
                : AVARequestAllocation.ResolutionOutcome.Withdrawn,
            reasonHash: REASON,
            remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
            finding: _findingInput(true)
        });
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        requestVm.expectRevert();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        if (consumeFirst && !finishFirst) executor.complete(requestAllocation, id, EFFECT);
        AVARequestAllocation.RequestRecord memory retained = requestAllocation.getRequest(id);
        require(
            retained.packageId == original.packageId && retained.approvedAt == original.approvedAt, "decision changed"
        );
        require(retained.recognisedStateTransitionId == original.recognisedStateTransitionId, "source changed");
        require(retained.consumed == consumeFirst && retained.completed == consumeFirst, "execution erased or invented");
        require(retained.effectHash == (consumeFirst ? EFFECT : bytes32(0)), "effect changed");
        require(requestAllocation.getRequestChallenge(challenge).evidenceId == filing, "filing lost");
    }

    function testNewPackageEvidenceCannotReplaceHistoricalDecisionScope() public {
        uint256 id = _approved();
        uint256 historicalPackage = requestPackageId;
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.ResolutionInput memory historicalDecision =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        requestPackageId = _registerRequestPackage(application, 2);
        uint256 fresh = _freshEvidence(SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Allocation, fresh, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(historicalDecision);
        require(requestAllocation.getRequest(id).packageId == historicalPackage, "historical package changed");
    }

    function testHistoricalCorrectionWorksAfterSourceCorrectionRevocationInactivityExpiryAndAllocatorRevocation()
        public
    {
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.RequestRecord memory beforeRecord = requestAllocation.getRequest(id);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        _correctSource(beforeRecord.input.recognisedStateId);
        _revoke(beforeRecord.evidenceReceiptId, SOURCE_ACTOR, ROLE_SOURCE);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, AVACoreTypes.ACTION_RECORD_ALLOCATION, false);
        requestVm.warp(beforeRecord.input.validUntil);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        AVARequestAllocation.RequestChallenge memory receipt = requestAllocation.getRequestChallenge(challenge);
        require(
            receipt.sourceStatusAtFiling == AVACoreTypes.RecognisedStateStatus.Vested
                && receipt.sourceStatusAtResolution == AVACoreTypes.RecognisedStateStatus.Voided,
            "source observations missing"
        );
        require(receipt.sourceTransitionIdAtFiling != receipt.sourceTransitionIdAtResolution, "source change missing");
        AVARequestAllocation.RequestRecord memory retained = requestAllocation.getRequest(id);
        require(
            retained.recognisedStateTransitionId == beforeRecord.recognisedStateTransitionId
                && retained.evidenceReceiptId == beforeRecord.evidenceReceiptId
                && retained.approvedAt == beforeRecord.approvedAt && retained.allocator == ALLOCATOR_ACTOR,
            "historical allocation changed"
        );
    }

    function testInactiveChallengerPermitsOnlyNeutralUnavailableWithoutFreshDecisionEvidence() public {
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        input.decisionEvidenceId = 0;
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        input.outcome = AVARequestAllocation.ResolutionOutcome.EvidenceUnavailable;
        input.finding = _findingInput(false);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == 0, "inactivity withdrew request");
    }

    function testRestorationPolicyRejectionRollsBackResolution() public {
        _withPolicy(
            AVACapabilityKeys.RESTORATION,
            address(new RejectCorrectionExtensionPolicy(AVARequestCorrectionActions.RESOLVE))
        );
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        require(
            requestAllocation.getRequestChallenge(challenge).outcome == AVARequestAllocation.ResolutionOutcome.None
                && requestAllocation.lastResolutionIdByRequest(id) == 0
                && requestAllocation.withdrawalResolutionIdByRequest(id) == 0,
            "policy rejection partly written"
        );
    }

    function testChallengePolicyRejectsResolutionWithoutPartialWrite() public {
        _withPolicy(
            AVACapabilityKeys.CHALLENGE_POLICY,
            address(new RejectCorrectionChallengePolicy(AVARequestCorrectionActions.RESOLVE))
        );
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        require(
            requestAllocation.getRequestChallenge(challenge).outcome == AVARequestAllocation.ResolutionOutcome.None,
            "router policy ignored"
        );
    }

    function testChallengePolicyCanRejectFilingBeforeReceiptIsWritten() public {
        _withPolicy(
            AVACapabilityKeys.CHALLENGE_POLICY,
            address(new RejectCorrectionChallengePolicy(AVARequestCorrectionActions.FILE))
        );
        uint256 id = _approved();
        uint256 evidence = requestAllocation.getRequest(id).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Allocation, evidence, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
        require(requestAllocation.nextRequestChallengeId() == 1, "policy rejected filing partly written");
    }

    function testRemedyPolicyRejectionRollsBackAuthorisationAndResolution() public {
        _withPolicy(
            AVACapabilityKeys.VALUE_EXECUTION,
            address(new RejectCorrectionExtensionPolicy(AVARequestCorrectionActions.AUTHORISE_REMEDY))
        );
        CorrectionToken asset = new CorrectionToken();
        uint256 id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, id, EFFECT);
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Effect);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Compensate, 0);
        input.remedy = AVARequestAllocation.RemedyTerms(address(asset), BENEFICIARY, 100);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        require(
            requestAllocation.getCompensation(challenge).terms.amount == 0
                && !requestAllocation.getCompensation(challenge).funded,
            "rejected remedy retained terms"
        );
        require(
            requestAllocation.lastResolutionIdByRequest(id) == 0
                && requestAllocation.getRequestChallenge(challenge).outcome
                    == AVARequestAllocation.ResolutionOutcome.None,
            "rejected remedy resolved concern"
        );
        require(requestAllocation.getRequest(id).effectHash == EFFECT, "rejection changed original effect");
    }

    function testCompensationRequiresSeparateCurrentRemedyPermission() public {
        uint256 id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, id, EFFECT);
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Effect);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Compensate, 0);
        input.remedy = AVARequestAllocation.RemedyTerms(address(new CorrectionToken()), BENEFICIARY, 100);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, false);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
        require(
            requestAllocation.getCompensation(challenge).terms.amount == 0
                && requestAllocation.lastResolutionIdByRequest(id) == 0,
            "resolve permission granted remedy"
        );
    }

    function testCompensationRequiresCompletedEffectAndExactDeployedNonzeroTerms() public {
        CorrectionToken asset = new CorrectionToken();
        uint256 id = _approved();
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Compensate, 0);
        input.remedy = AVARequestAllocation.RemedyTerms(address(asset), BENEFICIARY, 100);
        _expectResolutionRevert(input);
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        _expectResolutionRevert(input);
        executor.complete(requestAllocation, id, EFFECT);
        input.remedy.asset = address(0xD1);
        _expectResolutionRevert(input);
        input.remedy.asset = address(asset);
        input.remedy.recipient = address(0);
        _expectResolutionRevert(input);
        input.remedy.recipient = address(requestAllocation);
        _expectResolutionRevert(input);
        input.remedy.recipient = BENEFICIARY;
        input.remedy.amount = 0;
        _expectResolutionRevert(input);
        input.remedy.amount = 100;
        input.outcome = AVARequestAllocation.ResolutionOutcome.Residual;
        _expectResolutionRevert(input);
        input.outcome = AVARequestAllocation.ResolutionOutcome.Compensate;
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
        require(
            requestAllocation.getRequestChallenge(challenge).effectHashAtResolution == EFFECT
                && requestAllocation.getRequestChallenge(challenge).completedAtResolution,
            "original effect not retained"
        );
        requestVm.expectRevert();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        requestVm.expectRevert();
        executor.complete(requestAllocation, id, keccak256("replacement.effect"));
    }

    function testTransferFailuresFeesAndMissingTransfersRollbackAndOptionalBoolTransfersWork() public {
        CorrectionToken asset = new CorrectionToken();
        (, uint256 challenge) = _compensate(asset);
        asset.mint(address(this), 100);
        asset.approve(address(requestAllocation), 100);
        for (uint8 mode = 1; mode <= 3; ++mode) {
            asset.setMode(mode);
            requestVm.expectRevert();
            requestAllocation.fundCompensation(challenge);
            AVARequestAllocation.CompensationRecord memory receipt = requestAllocation.getCompensation(challenge);
            require(
                !receipt.funded && receipt.funder == address(0) && receipt.fundedAt == 0,
                "failed funding retained flags"
            );
            require(
                asset.balanceOf(address(this)) == 100 && asset.balanceOf(address(requestAllocation)) == 0
                    && asset.allowance(address(this), address(requestAllocation)) == 100,
                "failed funding did not roll back asset"
            );
        }
        asset.setMode(4);
        requestAllocation.fundCompensation(challenge);
        for (uint8 mode = 1; mode <= 3; ++mode) {
            asset.setMode(mode);
            requestVm.prank(BENEFICIARY);
            requestVm.expectRevert();
            requestAllocation.claimCompensation(challenge);
            AVARequestAllocation.CompensationRecord memory receipt = requestAllocation.getCompensation(challenge);
            require(
                receipt.funded && !receipt.paid && receipt.paidAt == 0 && receipt.paymentHash == bytes32(0),
                "failed claim retained payment flags"
            );
            require(
                asset.balanceOf(address(requestAllocation)) == 100 && asset.balanceOf(BENEFICIARY) == 0,
                "failed claim lost escrow"
            );
        }
        asset.setMode(4);
        requestVm.prank(BENEFICIARY);
        requestAllocation.claimCompensation(challenge);
        require(
            asset.balanceOf(BENEFICIARY) == 100 && requestAllocation.getCompensation(challenge).paid,
            "optional bool payment failed"
        );
    }

    function testManagementHandoverDoesNotPreventConsumedCompletion() public {
        uint256 id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        applicationRegistry.revokeApplicationAdmin(APP);
        applicationRegistry.proposeAdmin(address(0xAD3));
        requestVm.prank(address(0xAD3));
        applicationRegistry.acceptAdmin();
        executor.complete(requestAllocation, id, EFFECT);
        require(requestAllocation.getRequest(id).completed, "management loss erased executor continuation");
        require(requestAllocation.getRequest(id).effectHash == EFFECT, "effect receipt lost");
        requestVm.expectRevert();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
    }

    function testCompensationLibraryRejectsDirectCallsAndKeepsOwnerEscrow() public {
        CorrectionToken asset = new CorrectionToken();
        (, uint256 challenge) = _compensate(asset);
        address implementation = address(AVARequestCompensation);
        (bool called,) = implementation.call(
            abi.encodeWithSelector(AVARequestCompensation.fund.selector, challenge, true, uint256(0))
        );
        require(!called, "compensation library allowed direct storage mutation");
        asset.mint(address(this), 100);
        asset.approve(address(requestAllocation), 100);
        requestAllocation.fundCompensation(challenge);
        require(
            asset.balanceOf(address(requestAllocation)) == 100 && asset.balanceOf(implementation) == 0,
            "escrow left allocation owner"
        );
        require(requestAllocation.getCompensation(challenge).funder == address(this), "delegate sender changed");
        requestVm.prank(BENEFICIARY);
        requestAllocation.claimCompensation(challenge);
        require(
            asset.balanceOf(BENEFICIARY) == 100 && asset.balanceOf(implementation) == 0
                && requestAllocation.getCompensation(challenge).paid,
            "owner payment storage changed"
        );
    }

    function testTokenCallbackCannotReenterFundingOrReplaceRecordedFunder() public {
        CorrectionToken asset = new CorrectionToken();
        (, uint256 challenge) = _compensate(asset);
        asset.mint(address(this), 100);
        asset.mint(address(asset), 100);
        asset.approve(address(requestAllocation), 100);
        asset.configureReentry(requestAllocation, challenge);
        requestAllocation.fundCompensation(challenge);
        require(asset.reentryAttempted() && asset.reentryRejected(), "funding callback not blocked");
        require(
            requestAllocation.getCompensation(challenge).funder == address(this)
                && asset.balanceOf(address(requestAllocation)) == 100 && asset.balanceOf(address(asset)) == 100,
            "callback changed funded escrow"
        );
    }

    function testCoreReviewActuallyWithdrawsVetoedAllocationWithoutChangingSource() public {
        _withPolicy(
            AVACapabilityKeys.CHALLENGE_POLICY,
            address(new RejectCorrectionChallengePolicy(AVARequestCorrectionActions.RESOLVE))
        );
        uint256 id = _approved();
        AVARequestAllocation.RequestRecord memory original = requestAllocation.getRequest(id);
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Allocation);
        _expectResolutionRevert(_resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Withdrawn, 0));
        IAVACorrectionReview.ReviewInput memory input = _coreReview(challenge, IAVACorrectionReview.Outcome.Withdrawn);
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        requestVm.prank(VERIFIER_ACTOR);
        corrections.review(input);
        uint256 findingId = corrections.findingIdByCase(input.caseId);
        require(
            findingId == 1 && corrections.getFinding(findingId).independentReview, "Core finding provenance missing"
        );
        requestVm.expectRevert();
        corrections.getFinding(2);
        require(requestAllocation.withdrawalResolutionIdByRequest(id) == challenge, "Core review did not withdraw");
        require(
            kernel.getRecognisedStateReference(original.input.recognisedStateId).lastTransitionId
                == original.recognisedStateTransitionId,
            "Allocation review changed recognised state"
        );
        requestVm.expectRevert();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        uint256 successor = _createRequest(original.input);
        require(requestAllocation.getRequest(successor).allocator == address(0), "successor copied withdrawn approval");
    }

    function testCoreReviewCompensationNeedsSeparateAuthorityAndActualPayment() public {
        _withPolicy(
            AVACapabilityKeys.CHALLENGE_POLICY,
            address(new RejectCorrectionChallengePolicy(AVARequestCorrectionActions.RESOLVE))
        );
        uint256 id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, id, EFFECT);
        uint256 challenge = _file(id, AVARequestAllocation.ChallengeTarget.Effect);
        CorrectionToken asset = new CorrectionToken();
        IAVACorrectionReview.ReviewInput memory input = _coreReview(challenge, IAVACorrectionReview.Outcome.Compensate);
        input.asset = address(asset);
        input.recipient = BENEFICIARY;
        input.amount = 100;
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, false);
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        corrections.review(input);
        require(requestAllocation.getCompensation(challenge).terms.amount == 0, "rejected review partly committed");
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVARequestCorrectionActions.AUTHORISE_REMEDY, true);
        requestVm.prank(VERIFIER_ACTOR);
        corrections.review(input);
        require(!requestAllocation.getCompensation(challenge).paid, "review invented payment");
        asset.mint(address(this), 100);
        asset.approve(address(requestAllocation), 100);
        requestAllocation.fundCompensation(challenge);
        requestVm.prank(BENEFICIARY);
        requestAllocation.claimCompensation(challenge);
        require(
            asset.balanceOf(BENEFICIARY) == 100 && requestAllocation.getCompensation(challenge).paid,
            "authorised remedy not delivered"
        );
        require(
            requestAllocation.getRequest(id).completed && requestAllocation.getRequest(id).effectHash == EFFECT,
            "remedy erased original effect"
        );
        requestVm.prank(BENEFICIARY);
        requestVm.expectRevert();
        requestAllocation.claimCompensation(challenge);
    }

    function _coreReview(uint256 challenge, IAVACorrectionReview.Outcome outcome)
        private
        returns (IAVACorrectionReview.ReviewInput memory input)
    {
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_REVIEW_CORRECTION, true);
        IAVACorrectionReview corrections = IAVACorrectionReview(address(kernel.CORRECTIONS()));
        input.caseId = requestAllocation.correctionReviewCaseIdByChallenge(challenge);
        input.outcome = outcome;
        input.finding = _findingInput(
            outcome != IAVACorrectionReview.Outcome.EvidenceUnavailable
                && outcome != IAVACorrectionReview.Outcome.TargetChanged
        );
        input.roleKey = ROLE_VERIFIER;
        input.authorityId = _authority(ROLE_VERIFIER);
        input.reasonHash = REASON;
        AVAEvidenceRegistry.EvidenceRegistrationInput memory receipt = AVAEvidenceRegistry.EvidenceRegistrationInput(
            APP,
            REQUEST_WORKFLOW,
            requestPackageId,
            ROLE_VERIFIER,
            input.authorityId,
            keccak256(abi.encode("independent Core remedy evidence", challenge)),
            keccak256("Core review evidence"),
            requestPolicyId,
            input.authorityId,
            "test:core-review"
        );
        requestVm.prank(VERIFIER_ACTOR);
        input.evidenceId = evidenceRegistry.registerReviewEvidence(receipt, corrections, input.caseId);
    }

    function _expectResolutionRevert(AVARequestAllocation.ResolutionInput memory input) private {
        requestVm.prank(VERIFIER_ACTOR);
        requestVm.expectRevert();
        requestAllocation.resolveRequestChallenge(input);
    }

    function _compensate(CorrectionToken asset) private returns (uint256 id, uint256 challenge) {
        id = _approved();
        executor.consume(requestAllocation, id, RESPONSE, PARAMETERS);
        executor.complete(requestAllocation, id, EFFECT);
        challenge = _file(id, AVARequestAllocation.ChallengeTarget.Effect);
        AVARequestAllocation.ResolutionInput memory input =
            _resolutionInput(challenge, AVARequestAllocation.ResolutionOutcome.Compensate, 0);
        input.remedy = AVARequestAllocation.RemedyTerms(address(asset), BENEFICIARY, 100);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
    }

    function _approved() private returns (uint256 id) {
        id = _unapproved();
        _approveRequest(id);
    }

    function _unapproved() private returns (uint256 id) {
        uint64 expiry = uint64(block.timestamp + 1 days);
        uint256 state = _createRequestState(address(executor), RESPONSE, PARAMETERS, BURDEN, expiry);
        id = _createRequest(
            AVARequestAllocation.RequestInput(state, address(executor), RESPONSE, PARAMETERS, BURDEN, expiry)
        );
    }

    function _withPolicy(bytes32 capability, address policy) private {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _coreBindings(application);
        for (uint256 i; i < bindings.length; ++i) {
            if (bindings[i].capabilityKey == capability) bindings[i] = _coreBinding(capability, policy);
        }
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                2,
                keccak256("request.compatibility"),
                "test:correction-policy"
            ),
            requestPackageId,
            bindings
        );
    }

    function _correctSource(uint256 stateId) private {
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        AVAGovernanceKernel.RecognisedStateReference memory state = kernel.getRecognisedStateReference(stateId);
        transitionRequester.change(
            kernel,
            AVAGovernanceKernel.SourceBoundTransitionInput({
                recognisedStateId: stateId,
                expectedTransitionId: state.lastTransitionId,
                decisionPackageId: state.packageId,
                sourceRecordId: 1,
                decisionEvidenceReceiptId: state.evidenceReceiptId,
                disclosureTargetId: state.governedObjectId,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                actionKey: AVACoreTypes.ACTION_RESOLVE_CHALLENGE,
                decisionHash: keccak256("independent.source.correction"),
                toStatus: AVACoreTypes.RecognisedStateStatus.Voided,
                kind: AVACoreTypes.TransitionKind.ChallengeCorrection,
                reasonHash: keccak256("source.correction"),
                reasonURI: "test:source-correction"
            })
        );
    }

    function _file(uint256 id, AVARequestAllocation.ChallengeTarget target) private returns (uint256) {
        uint256 evidenceId = requestAllocation.getRequest(id).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        return
            requestAllocation.fileRequestChallenge(id, target, evidenceId, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON);
    }

    function _fileFreshEffect(uint256 id) private returns (uint256) {
        uint256 evidence = _freshEvidence(SOURCE_ACTOR, ROLE_SOURCE);
        requestVm.prank(SOURCE_ACTOR);
        return requestAllocation.fileRequestChallenge(
            id, AVARequestAllocation.ChallengeTarget.Effect, evidence, ROLE_SOURCE, _authority(ROLE_SOURCE), REASON
        );
    }

    function _historicalEvidence(address actor, bytes32 role, uint256 historicalPackage) private returns (uint256) {
        authorityMatrix.setPermission(APP, role, evidenceRegistry.ACTION_REGISTER_CORRECTION_EVIDENCE(), true);
        bytes32 commitment = keccak256(abi.encode("post.upgrade.evidence", evidenceRegistry.nextEvidenceId()));
        requestVm.prank(actor);
        return evidenceRegistry.registerCorrectionEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: historicalPackage,
                roleKey: role,
                subjectId: _authority(role),
                commitment: commitment,
                evidenceTypeHash: keccak256("correction.decision"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(role),
                uri: "test:post-upgrade-correction"
            }),
            requestPackageId,
            REASON
        );
    }

    function _decisionEvidence() private returns (uint256 id) {
        return _freshEvidence(VERIFIER_ACTOR, ROLE_VERIFIER);
    }

    function _freshEvidence(address actor, bytes32 role) private returns (uint256 id) {
        bytes32 commitment = keccak256(abi.encode("decision", evidenceRegistry.nextEvidenceId()));
        requestVm.prank(actor);
        id = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: role,
                subjectId: _authority(role),
                commitment: commitment,
                evidenceTypeHash: keccak256("correction.decision"),
                disclosurePolicyId: requestPolicyId,
                authorityId: _authority(role),
                uri: "test:correction-evidence"
            })
        );
    }

    function _revoke(uint256 id, address actor, bytes32 role) private {
        requestVm.prank(actor);
        evidenceRegistry.recordEvidenceLifecycle(
            id, role, _authority(role), AVACoreTypes.EvidenceLifecycleKind.Revoke, 0, keccak256("revoke"), "test:revoke"
        );
    }

    function _resolve(uint256 challenge, AVARequestAllocation.ResolutionOutcome outcome, uint256 previous) private {
        AVARequestAllocation.ResolutionInput memory input = _resolutionInput(challenge, outcome, previous);
        requestVm.prank(VERIFIER_ACTOR);
        requestAllocation.resolveRequestChallenge(input);
    }

    function _resolutionInput(uint256 challenge, AVARequestAllocation.ResolutionOutcome outcome, uint256 previous)
        private
        returns (AVARequestAllocation.ResolutionInput memory)
    {
        return AVARequestAllocation.ResolutionInput({
            challengeId: challenge,
            expectedPreviousResolutionId: previous,
            roleKey: ROLE_VERIFIER,
            authorityId: _authority(ROLE_VERIFIER),
            decisionEvidenceId: _decisionEvidence(),
            outcome: outcome,
            reasonHash: keccak256("independent.decision"),
            remedy: AVARequestAllocation.RemedyTerms(address(0), address(0), 0),
            finding: _findingInput(
                outcome == AVARequestAllocation.ResolutionOutcome.Rejected
                    || outcome == AVARequestAllocation.ResolutionOutcome.Withdrawn
                    || outcome == AVARequestAllocation.ResolutionOutcome.Residual
                    || outcome == AVARequestAllocation.ResolutionOutcome.Compensate
            )
        });
    }
}
