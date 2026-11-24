// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {AVAAuthorityMatrix} from "../../core/AVAAuthorityMatrix.sol";
import {AVAIdentityRegistry} from "../../core/AVAIdentityRegistry.sol";
import {AVACoreRulePackageRegistry} from "../../core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../../core/AVAEvidenceRegistry.sol";
import {IAVARequestPolicy} from "../../core/interfaces/IAVARequestPolicy.sol";
import {IAVACorrectionReview} from "../../core/interfaces/IAVACorrectionReview.sol";
import {AVARequestSupport, IAVARequestCorrectionTarget} from "./AVARequestSupport.sol";
import {AVAExecutionLifecycle} from "./AVAExecutionLifecycle.sol";
import {AVARequestSupportDeployment} from "./AVARequestSupportDeployment.sol";

library AVARequestCorrectionActions {
    bytes32 internal constant FILE = keccak256("ava.extension.request.challenge.file.v1");
    bytes32 internal constant RESOLVE = keccak256("ava.extension.request.challenge.resolve.v1");
    bytes32 internal constant AUTHORISE_REMEDY = keccak256("ava.extension.request.remedy.authorise.v1");
}

interface IAVACompensationAsset {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
}

/// @notice Atomic requests with either exact single-state support or explicitly scoped finite witnesses.
contract AVARequestAllocation {
    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;
    AVAAuthorityMatrix public immutable AUTHORITY_MATRIX;
    AVAIdentityRegistry public immutable IDENTITY_REGISTRY;
    AVACoreRulePackageRegistry public immutable RULE_PACKAGE_REGISTRY;
    AVAEvidenceRegistry public immutable EVIDENCE_REGISTRY;
    bytes32 public constant ACTION_CREATE_REQUEST = keccak256("ava.extension.request.create.v1");
    bytes32 public constant ACTION_FILE_REQUEST_CHALLENGE = AVARequestCorrectionActions.FILE;
    bytes32 public constant ACTION_RESOLVE_REQUEST_CHALLENGE = AVARequestCorrectionActions.RESOLVE;
    bytes32 public constant ACTION_AUTHORISE_REMEDY = AVARequestCorrectionActions.AUTHORISE_REMEDY;
    bytes32 public constant ACTION_AUTHORISE_RECOVERY = keccak256("ava.extension.request.recovery.authorise.v1");
    bytes32 private constant REQUEST_DOMAIN = keccak256("ava.request-allocation.commitment.v1");
    bytes32 private constant SCOPE_DOMAIN = keccak256("ava.recognition-scope.v1");
    uint256 public constant MAX_SUPPORT_WITNESSES = 16;
    uint256 public constant REQUEST_POLICY_INTERFACE_VERSION = 1;
    uint256 public constant EXECUTION_APPROVAL_INTERFACE_VERSION = 1;

    enum ChallengeTarget {
        Allocation,
        Effect
    }
    enum ResolutionOutcome {
        None,
        Rejected,
        Withdrawn,
        Residual,
        Compensate,
        EvidenceUnavailable,
        AlreadyWithdrawn,
        ReviewedResidual
    }

    struct RemedyTerms {
        address asset;
        address recipient;
        uint256 amount;
    }

    struct ResolutionInput {
        uint256 challengeId;
        uint256 expectedPreviousResolutionId;
        bytes32 roleKey;
        bytes32 authorityId;
        uint256 decisionEvidenceId;
        ResolutionOutcome outcome;
        bytes32 reasonHash;
        RemedyTerms remedy;
        IAVACorrectionReview.FindingInput finding;
    }

    struct RequestChallenge {
        uint256 id;
        uint256 requestId;
        ChallengeTarget target;
        bytes32 challengerSubjectId;
        uint256 evidenceId;
        uint256 decisionEvidenceId;
        ResolutionOutcome outcome;
        bytes32 reasonHash;
        bytes32 filingReasonHash;
        bytes32 resolutionHash;
        uint256 previousResolutionId;
        address filedBy;
        address resolvedBy;
        bytes32 resolverAuthorityId;
        uint64 filedAt;
        uint64 resolvedAt;
        bool consumedAtFiling;
        bool completedAtFiling;
        bytes32 effectHashAtFiling;
        uint256 sourceTransitionIdAtFiling;
        AVACoreTypes.RecognisedStateStatus sourceStatusAtFiling;
        bool consumedAtResolution;
        bool completedAtResolution;
        bytes32 effectHashAtResolution;
        uint256 sourceTransitionIdAtResolution;
        AVACoreTypes.RecognisedStateStatus sourceStatusAtResolution;
    }

    struct CompensationRecord {
        RemedyTerms terms;
        bool funded;
        bool paid;
        address funder;
        uint64 fundedAt;
        uint64 paidAt;
        bytes32 paymentHash;
    }

    struct RequestInput {
        uint256 recognisedStateId;
        address executor;
        bytes32 responseClass;
        bytes32 parametersHash;
        bytes32 burdenHash;
        uint64 validUntil;
    }

    struct RequestRecord {
        uint256 id;
        RequestInput input;
        uint256 recognisedStateTransitionId;
        uint256 supersedesRequestId;
        bytes32 appId;
        bytes32 workflowKey;
        uint256 packageId;
        bytes32 subjectId;
        uint256 evidenceReceiptId;
        address creator;
        bytes32 creatorRoleKey;
        bytes32 creatorAuthorityId;
        address allocator;
        bytes32 allocatorRoleKey;
        bytes32 allocatorAuthorityId;
        address triggeredBy;
        bool cancelled;
        bool consumed;
        bool completed;
        bytes32 effectHash;
        uint64 createdAt;
        uint64 approvedAt;
        uint64 consumedAt;
        uint64 completedAt;
    }

    mapping(uint256 => RequestRecord) private requests;
    /// @notice Pending concerns only; ordinary execution policy remains unchanged.
    mapping(uint256 => uint256) public openChallengeCountByRequest;
    /// @notice Latest request only; every predecessor remains readable by its own ID.
    mapping(uint256 => uint256) public requestIdByRecognisedState;
    mapping(uint256 => bool) public scopedSupportByRequest;
    mapping(uint256 => uint256) public decisionRequestIdByExecution;
    mapping(uint256 => bytes32) public supportWitnessHash;
    AVARequestSupport public immutable SUPPORT;
    AVAExecutionLifecycle public immutable EXECUTION;
    mapping(bytes32 => uint256) public supportedRequestIdByMeaning;
    mapping(bytes32 => uint256) public consumedRequestIdByMeaning;
    mapping(uint256 => uint256) public supersededByRequest;
    uint256 public nextRequestId = 1;
    mapping(uint256 => RequestChallenge) private requestChallenges;
    mapping(uint256 => uint256) public lastResolutionIdByRequest;
    mapping(uint256 => uint256) public withdrawalResolutionIdByRequest;
    mapping(uint256 => uint256) public correctionReviewCaseIdByChallenge;
    mapping(bytes32 => bool) private filedIssues;
    uint256 public nextRequestChallengeId = 1;
    mapping(uint256 => CompensationRecord) private compensations;
    uint256 private escrowEntered;

    event RequestCreated(
        uint256 indexed requestId, uint256 indexed recognisedStateId, bytes32 indexed appId, address creator
    );
    event RequestApproved(uint256 indexed requestId, address indexed allocator, bytes32 authorityId);
    event RequestSupportBound(uint256 indexed requestId, bytes32 witnessHash, bool exactCommitment);
    event RequestConsumed(uint256 indexed requestId, address indexed executor, address indexed triggeredBy);
    event RequestCompleted(uint256 indexed requestId, bytes32 effectHash);
    event RequestCancelled(uint256 indexed requestId, address indexed actor);
    event RequestChallengeFiled(
        uint256 indexed challengeId, uint256 indexed requestId, ChallengeTarget target, address challenger
    );
    event RequestChallengeResolved(
        uint256 indexed challengeId, uint256 indexed requestId, ResolutionOutcome outcome, bytes32 resolutionHash
    );
    event CompensationFunded(uint256 indexed challengeId, address indexed funder, address asset, uint256 amount);
    event CompensationPaid(uint256 indexed challengeId, address indexed recipient, bytes32 paymentHash);

    modifier nonReentrantEscrow() {
        if (escrowEntered != 0) revert AVACoreTypes.InvalidState(0);
        escrowEntered = 1;
        _;
        escrowEntered = 0;
    }

    constructor(AVAGovernanceKernel kernel) {
        if (address(kernel) == address(0) || address(kernel).code.length == 0) revert AVACoreTypes.EmptyValue();
        GOVERNANCE_KERNEL = kernel;
        AUTHORITY_MATRIX = kernel.AUTHORITY_MATRIX();
        IDENTITY_REGISTRY = kernel.IDENTITY_REGISTRY();
        RULE_PACKAGE_REGISTRY = kernel.RULE_PACKAGE_REGISTRY();
        EVIDENCE_REGISTRY = kernel.EVIDENCE_REGISTRY();
        EXECUTION = new AVAExecutionLifecycle();
        SUPPORT = AVARequestSupportDeployment.deploy(
            kernel,
            address(EXECUTION),
            AVARequestSupport.HostComponents({
                authority: AUTHORITY_MATRIX,
                identity: IDENTITY_REGISTRY,
                packages: RULE_PACKAGE_REGISTRY,
                evidence: EVIDENCE_REGISTRY,
                router: kernel.POLICY_ROUTER()
            })
        );
    }

    function commitmentFor(
        bytes32 appId,
        address executor,
        bytes32 responseClass,
        bytes32 parametersHash,
        bytes32 burdenHash,
        uint64 validUntil
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                REQUEST_DOMAIN,
                block.chainid,
                address(this),
                appId,
                executor,
                responseClass,
                parametersHash,
                burdenHash,
                validUntil
            )
        );
    }

    function createRequest(RequestInput calldata input, bytes32 roleKey, bytes32 authorityId)
        external
        returns (uint256 id)
    {
        id = _createRequest(input, roleKey, authorityId);
        _requireOriginalSource(requests[id]);
    }

    /// @notice One actor supplies independently authorised creation and Allocation roles; execution stays separate.
    function createAndApproveRequest(
        RequestInput calldata input,
        bytes32 creatorRole,
        bytes32 creatorAuthority,
        bytes32 allocatorRole,
        bytes32 allocatorAuthority
    ) external returns (uint256 id) {
        // validateDecision checks the newly bound support before Allocation in this same transaction.
        id = _createRequest(input, creatorRole, creatorAuthority);
        _approveFor(id, allocatorRole, allocatorAuthority, msg.sender);
    }

    /// @notice Supported and decision-bound requests may pin the same mode before their allocation.
    function declareSplitMode(uint256 requestId, bytes32 configurationHash) external {
        RequestRecord storage record = _request(requestId);
        _requireOpen(record);
        if (record.creator != msg.sender || record.allocator != address(0)) {
            revert AVACoreTypes.InvalidState(requestId);
        }
        AUTHORITY_MATRIX.requireAuthorisedSubject(
            msg.sender, record.appId, record.creatorRoleKey, ACTION_CREATE_REQUEST, record.creatorAuthorityId
        );
        EXECUTION.declareSplit(requestId, record.input.executor, record.input.parametersHash, configurationHash);
    }

    function _createRequest(RequestInput calldata input, bytes32 roleKey, bytes32 authorityId)
        private
        returns (uint256 id)
    {
        AVAGovernanceKernel.RecognisedStateReference memory source = _source(input);
        AUTHORITY_MATRIX.requireAuthorisedSubject(msg.sender, source.appId, roleKey, ACTION_CREATE_REQUEST, authorityId);
        uint256 previousId = requestIdByRecognisedState[input.recognisedStateId];
        if (previousId != 0) {
            RequestRecord storage previous = requests[previousId];
            // A fresh source occurrence needs a fresh decision, never a replay of an effect.
            // Older predecessors cannot consume after their pinned transition has changed.
            if (
                previous.consumed
                    || (previous.recognisedStateTransitionId == source.lastTransitionId
                        && withdrawalResolutionIdByRequest[previousId] == 0)
            ) {
                revert AVACoreTypes.InvalidState(input.recognisedStateId);
            }
        }
        id = _storeRequest(input, source, previousId, roleKey, authorityId);
        RequestRecord storage record = requests[id];
        requestIdByRecognisedState[input.recognisedStateId] = id;
        _bindSupport(record, new IAVARequestPolicy.WitnessInput[](0));
        emit RequestCreated(id, input.recognisedStateId, source.appId, msg.sender);
    }

    /// @notice Scope must already be committed in the governed object's metadata before recognition.
    function recognitionScopeHash(IAVARequestPolicy.RecognitionScope memory scope) public pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_DOMAIN, scope));
    }

    /// @notice Explicit witnesses are checked jointly by the package's request policy, never inferred by count.
    function createSupportedRequest(
        RequestInput calldata input,
        IAVARequestPolicy.WitnessInput[] calldata witness,
        bytes32 roleKey,
        bytes32 authorityId
    ) external returns (uint256 id) {
        return _createSupportedRequest(0, 0, input, witness, roleKey, authorityId);
    }

    struct ScopedRequestAuthorities {
        bytes32 creatorRole;
        bytes32 creatorAuthority;
        bytes32 allocatorRole;
        bytes32 allocatorAuthority;
    }

    /// @notice One actor supplies independently authorised creation and Allocation roles for scoped support.
    function createSupportedAndApproveRequest(
        RequestInput calldata input,
        IAVARequestPolicy.WitnessInput[] calldata witness,
        ScopedRequestAuthorities calldata authorities
    ) external returns (uint256 id) {
        id = _createSupportedRequest(0, 0, input, witness, authorities.creatorRole, authorities.creatorAuthority);
        _approveFor(id, authorities.allocatorRole, authorities.allocatorAuthority, msg.sender);
    }

    /// @notice Explicitly binds the pending decision request before the package validates its support.
    function createDecisionRequest(
        uint256 decisionRequestId,
        RequestInput calldata input,
        IAVARequestPolicy.WitnessInput[] calldata witness,
        bytes32 roleKey,
        bytes32 authorityId
    ) external returns (uint256 id) {
        if (decisionRequestId == 0) revert AVACoreTypes.EmptyValue();
        return _createSupportedRequest(decisionRequestId, 0, input, witness, roleKey, authorityId);
    }

    /// @notice A current receiving package explicitly judges retained historical support.
    function createDecisionRequestForPackage(
        uint256 decisionRequestId,
        uint256 receivingPackageId,
        RequestInput calldata input,
        IAVARequestPolicy.WitnessInput[] calldata witness,
        bytes32 roleKey,
        bytes32 authorityId
    ) external returns (uint256 id) {
        if (decisionRequestId == 0 || receivingPackageId == 0) revert AVACoreTypes.EmptyValue();
        return _createSupportedRequest(decisionRequestId, receivingPackageId, input, witness, roleKey, authorityId);
    }

    function _createSupportedRequest(
        uint256 decisionRequestId,
        uint256 receivingPackageId,
        RequestInput calldata input,
        IAVARequestPolicy.WitnessInput[] calldata witness,
        bytes32 roleKey,
        bytes32 authorityId
    ) private returns (uint256 id) {
        AVAGovernanceKernel.RecognisedStateReference memory source = _source(input);
        if (
            receivingPackageId != 0
                && RULE_PACKAGE_REGISTRY.getActivePackageId(source.appId, source.workflowKey) != receivingPackageId
        ) revert AVACoreTypes.InvalidState(receivingPackageId);
        AUTHORITY_MATRIX.requireAuthorisedSubject(msg.sender, source.appId, roleKey, ACTION_CREATE_REQUEST, authorityId);
        if (witness.length == 0 || witness.length > MAX_SUPPORT_WITNESSES) revert AVACoreTypes.EmptyValue();
        bytes32 meaning = _meaningKey(source.appId, input);
        if (consumedRequestIdByMeaning[meaning] != 0) {
            revert AVACoreTypes.InvalidState(consumedRequestIdByMeaning[meaning]);
        }
        uint256 previousId = supportedRequestIdByMeaning[meaning];
        if (previousId != 0) {
            RequestRecord storage previous = requests[previousId];
            bool terminal = previous.cancelled || block.timestamp >= previous.input.validUntil;
            if (
                previous.consumed
                    || (!terminal
                        && (previous.input.burdenHash != input.burdenHash
                            || previous.input.validUntil != input.validUntil
                            || (withdrawalResolutionIdByRequest[previousId] == 0
                                && !SUPPORT.occurrenceChanged(previousId))))
            ) revert AVACoreTypes.InvalidState(previousId);
        }
        id = _storeRequest(input, source, previousId, roleKey, authorityId);
        RequestRecord storage record = requests[id];
        if (receivingPackageId != 0) record.packageId = receivingPackageId;
        scopedSupportByRequest[id] = true;
        decisionRequestIdByExecution[id] = decisionRequestId;
        supportedRequestIdByMeaning[meaning] = id;
        if (previousId != 0) supersededByRequest[previousId] = id;
        _bindSupport(record, witness);
        _requireOriginalSource(record);
        emit RequestCreated(id, input.recognisedStateId, source.appId, msg.sender);
    }

    function _storeRequest(
        RequestInput calldata input,
        AVAGovernanceKernel.RecognisedStateReference memory source,
        uint256 previousId,
        bytes32 roleKey,
        bytes32 authorityId
    ) private returns (uint256 id) {
        id = nextRequestId++;
        RequestRecord storage record = requests[id];
        record.id = id;
        record.input = input;
        record.recognisedStateTransitionId = source.lastTransitionId;
        record.supersedesRequestId = previousId;
        record.appId = source.appId;
        record.workflowKey = source.workflowKey;
        record.packageId = source.packageId;
        record.subjectId = source.subjectId;
        record.evidenceReceiptId = source.evidenceReceiptId;
        record.creator = msg.sender;
        record.creatorRoleKey = roleKey;
        record.creatorAuthorityId = authorityId;
        record.createdAt = uint64(block.timestamp);
    }

    function getSupportWitness(uint256 requestId) external view returns (IAVARequestPolicy.WitnessInput[] memory) {
        _request(requestId);
        return SUPPORT.getWitness(requestId);
    }

    /// @notice Current support is actor-neutral; it does not approve or execute the request.
    function validateCurrentSupport(uint256 requestId) external view returns (bytes32) {
        _requireOriginalSource(_request(requestId));
        return supportWitnessHash[requestId];
    }

    function approve(uint256 requestId, bytes32 roleKey, bytes32 authorityId) external {
        _approveFor(requestId, roleKey, authorityId, msg.sender);
    }

    /// @notice The verified package's decision registry relays the actual canonical allocating actor.
    function approveFromDecision(uint256 requestId, bytes32 roleKey, bytes32 authorityId, address actor) external {
        SUPPORT.requireDecisionBridge(requestId, msg.sender);
        _approveFor(requestId, roleKey, authorityId, actor);
    }

    function _approveFor(uint256 requestId, bytes32 roleKey, bytes32 authorityId, address actor) private {
        RequestRecord storage record = _request(requestId);
        _requireOpen(record);
        if (record.allocator != address(0)) revert AVACoreTypes.InvalidState(requestId);
        _validateRequestDecision(record, roleKey, authorityId, actor);
        record.allocator = actor;
        record.allocatorRoleKey = roleKey;
        record.allocatorAuthorityId = authorityId;
        record.approvedAt = uint64(block.timestamp);
        emit RequestApproved(requestId, actor, authorityId);
    }

    function validateExecution(uint256 requestId, bytes32 responseClass, bytes32 parametersHash, address executor)
        public
        view
        returns (bool)
    {
        RequestRecord storage record = _request(requestId);
        _requireOpen(record);
        if (
            record.allocator == address(0) || record.input.executor != executor
                || record.input.responseClass != responseClass || record.input.parametersHash != parametersHash
        ) revert AVACoreTypes.InvalidState(requestId);
        SUPPORT.validateExecution(
            record.id,
            IAVARequestPolicy.DecisionContext(
                record.allocatorRoleKey, record.allocatorAuthorityId, record.allocator, uint64(block.timestamp)
            )
        );
        return true;
    }

    function consume(uint256 requestId, bytes32 responseClass, bytes32 parametersHash, address triggeredBy) external {
        if (EXECUTION.isSplit(requestId)) revert AVACoreTypes.InvalidState(requestId);
        validateExecution(requestId, responseClass, parametersHash, msg.sender);
        RequestRecord storage record = requests[requestId];
        _consume(record, triggeredBy);
    }

    function consumeSplit(uint256 requestId, bytes32 responseClass, bytes32 parametersHash, address triggeredBy)
        external
        returns (uint256 attemptId)
    {
        validateExecution(requestId, responseClass, parametersHash, msg.sender);
        _consume(requests[requestId], triggeredBy);
        return EXECUTION.begin(requestId, triggeredBy);
    }

    function _consume(RequestRecord storage record, address triggeredBy) private {
        uint256 requestId = record.id;
        consumedRequestIdByMeaning[_meaningKey(record.appId, record.input)] = requestId;
        record.consumed = true;
        record.triggeredBy = triggeredBy;
        record.consumedAt = uint64(block.timestamp);
        emit RequestConsumed(requestId, msg.sender, triggeredBy);
    }

    function complete(uint256 requestId, bytes32 effectHash) external {
        RequestRecord storage record = _request(requestId);
        if (
            EXECUTION.isSplit(requestId) || msg.sender != record.input.executor || !record.consumed || record.completed
                || effectHash == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(requestId);
        }
        _complete(record, effectHash);
    }

    /// @notice The adapter effect and this record's completion revert together on any failure.
    function completeAttempt(uint256 requestId, uint256 attemptId, bytes calldata parameters) external {
        RequestRecord storage record = _request(requestId);
        if (msg.sender != record.input.executor) revert AVACoreTypes.InvalidState(requestId);
        _requireConsumedExecution(record);
        bytes32 effectHash = EXECUTION.complete(requestId, attemptId, parameters);
        _complete(record, effectHash);
    }

    function reportAttempt(
        uint256 requestId,
        uint256 attemptId,
        AVAExecutionLifecycle.ReportKind kind,
        bytes32 receiptHash
    ) external returns (uint256) {
        _request(requestId);
        return EXECUTION.report(requestId, attemptId, kind, receiptHash, msg.sender);
    }

    function authoriseRecovery(AVAExecutionLifecycle.RecoveryInput calldata input) external returns (uint256) {
        RequestRecord storage record = _request(input.requestId);
        AVAGovernanceKernel.RecognisedStateReference memory source =
            GOVERNANCE_KERNEL.getRecognisedStateReference(record.input.recognisedStateId);
        bytes32 decisionHash = keccak256(
            abi.encode(
                ACTION_AUTHORISE_RECOVERY, block.chainid, address(this), input, _correctionContextHash(record, source)
            )
        );
        return EXECUTION.authorise(input, msg.sender, record.allocator, decisionHash);
    }

    function consumeRecovery(uint256 requestId, uint256 recoveryId, address triggeredBy) external returns (uint256) {
        RequestRecord storage record = _request(requestId);
        if (msg.sender != record.input.executor) revert AVACoreTypes.InvalidState(requestId);
        _requireConsumedExecution(record);
        return EXECUTION.recover(requestId, recoveryId, triggeredBy);
    }

    function _requireConsumedExecution(RequestRecord storage record) private view {
        if (
            !record.consumed || record.completed || record.cancelled || block.timestamp >= record.input.validUntil
                || withdrawalResolutionIdByRequest[record.id] != 0 || supersededByRequest[record.id] != 0
                || consumedRequestIdByMeaning[_meaningKey(record.appId, record.input)] != record.id
        ) revert AVACoreTypes.InvalidState(record.id);
        _validateRequestDecision(record, record.allocatorRoleKey, record.allocatorAuthorityId, record.allocator);
    }

    function _complete(RequestRecord storage record, bytes32 effectHash) private {
        record.completed = true;
        record.effectHash = effectHash;
        record.completedAt = uint64(block.timestamp);
        emit RequestCompleted(record.id, effectHash);
    }

    function cancel(uint256 requestId) external {
        RequestRecord storage record = _request(requestId);
        if (
            msg.sender != record.creator || record.allocator != address(0) || record.cancelled || record.consumed
                || record.completed
        ) revert AVACoreTypes.InvalidState(requestId);
        AUTHORITY_MATRIX.requireAuthorisedSubject(
            msg.sender, record.appId, record.creatorRoleKey, ACTION_CREATE_REQUEST, record.creatorAuthorityId
        );
        record.cancelled = true;
        emit RequestCancelled(requestId, msg.sender);
    }

    function getRequest(uint256 requestId) external view returns (RequestRecord memory) {
        return _request(requestId);
    }

    /// @notice Filing records a concern; it does not suspend an approved request.
    function fileRequestChallenge(
        uint256 requestId,
        ChallengeTarget target,
        uint256 evidenceId,
        bytes32 roleKey,
        bytes32 authorityId,
        bytes32 reasonHash
    ) external returns (uint256 id) {
        RequestRecord storage record = _request(requestId);
        if (record.allocator == address(0) || record.cancelled || reasonHash == bytes32(0)) {
            revert AVACoreTypes.InvalidState(requestId);
        }
        if (target == ChallengeTarget.Effect && !record.completed) revert AVACoreTypes.InvalidState(requestId);
        bytes32 evidenceSubject =
            EVIDENCE_REGISTRY.requireCorrectionSupport(evidenceId, record.packageId, record.appId, record.workflowKey);
        if (evidenceSubject != authorityId) revert AVACoreTypes.SubjectMismatch(authorityId, evidenceSubject);
        bytes32 issue = keccak256(abi.encode(requestId, target, authorityId, evidenceId, reasonHash));
        if (filedIssues[issue]) revert AVACoreTypes.InvalidState(requestId);
        AVAGovernanceKernel.RecognisedStateReference memory source =
            GOVERNANCE_KERNEL.getRecognisedStateReference(record.input.recognisedStateId);
        id = nextRequestChallengeId;
        bytes32 decisionHash = keccak256(
            abi.encode(
                AVARequestCorrectionActions.FILE,
                block.chainid,
                address(this),
                id,
                requestId,
                target,
                evidenceId,
                roleKey,
                authorityId,
                reasonHash,
                supportWitnessHash[record.id],
                record.recognisedStateTransitionId,
                source.lastTransitionId
            )
        );
        SUPPORT.validateCorrection(
            record.id,
            AVARequestSupport.CorrectionInput({
                actionKey: AVARequestCorrectionActions.FILE,
                roleKey: roleKey,
                authorityId: authorityId,
                evidenceId: evidenceId,
                decisionHash: decisionHash,
                challengeId: id,
                outcomeKey: bytes32(0),
                validateDisclosure: true,
                actor: msg.sender
            })
        );
        nextRequestChallengeId = id + 1;
        filedIssues[issue] = true;
        RequestChallenge storage challenge = requestChallenges[id];
        challenge.id = id;
        challenge.requestId = requestId;
        challenge.target = target;
        challenge.challengerSubjectId = authorityId;
        challenge.evidenceId = evidenceId;
        challenge.reasonHash = reasonHash;
        challenge.filingReasonHash = reasonHash;
        challenge.filedBy = msg.sender;
        challenge.filedAt = uint64(block.timestamp);
        challenge.consumedAtFiling = record.consumed;
        challenge.completedAtFiling = record.completed;
        challenge.effectHashAtFiling = record.effectHash;
        challenge.sourceTransitionIdAtFiling = source.lastTransitionId;
        challenge.sourceStatusAtFiling = source.status;
        uint256 reviewCaseId = GOVERNANCE_KERNEL.CORRECTIONS()
            .registerCase(
                IAVACorrectionReview.CaseInput({
                    kind: target == ChallengeTarget.Allocation
                        ? IAVACorrectionReview.TargetKind.Allocation
                        : IAVACorrectionReview.TargetKind.Effect,
                    appId: record.appId,
                    workflowKey: record.workflowKey,
                    packageId: record.packageId,
                    targetPackageId: record.packageId,
                    sourceStateId: record.input.recognisedStateId,
                    originCaseId: id,
                    targetId: requestId,
                    originalTargetVersion: lastResolutionIdByRequest[requestId],
                    filingEvidenceId: evidenceId,
                    challengerSubjectId: authorityId,
                    originalActor: record.allocator,
                    challenger: msg.sender,
                    affectedActor: record.input.executor
                })
            );
        correctionReviewCaseIdByChallenge[id] = reviewCaseId;
        ++openChallengeCountByRequest[requestId];
        emit RequestChallengeFiled(id, requestId, target, msg.sender);
    }

    function correctionTargetVersion(uint256 challengeId) external view returns (uint256) {
        RequestChallenge storage challenge = _challenge(challengeId);
        if (challenge.outcome != ResolutionOutcome.None) revert AVACoreTypes.InvalidState(challengeId);
        return lastResolutionIdByRequest[challenge.requestId];
    }

    function _correctionReviewTarget(uint256 challengeId)
        private
        view
        returns (IAVARequestCorrectionTarget.Target memory target)
    {
        RequestChallenge storage challenge = _challenge(challengeId);
        RequestRecord storage record = requests[challenge.requestId];
        return IAVARequestCorrectionTarget.Target(
            record.id,
            record.packageId,
            lastResolutionIdByRequest[record.id],
            withdrawalResolutionIdByRequest[record.id],
            challenge.evidenceId,
            challenge.challengerSubjectId,
            record.allocator,
            challenge.filedBy,
            uint8(challenge.target),
            uint8(challenge.outcome),
            record.consumed,
            record.completed,
            record.effectHash
        );
    }

    /// @notice An accepted Core review deliberately bypasses ordinary historical policy vetoes.
    function applyCorrectionReview(uint256 reviewId) external {
        IAVACorrectionReview corrections = GOVERNANCE_KERNEL.CORRECTIONS();
        if (msg.sender != address(corrections)) revert AVACoreTypes.InvalidState(reviewId);
        IAVACorrectionReview.ReviewTerms memory review = corrections.activeReviewTerms(reviewId);
        RequestChallenge storage challenge = _challenge(review.originCaseId);
        RequestRecord storage record = requests[challenge.requestId];
        ResolutionOutcome outcome =
            ResolutionOutcome(SUPPORT.validateCoreReviewTerms(review, _correctionReviewTarget(challenge.id)));
        if (outcome == ResolutionOutcome.Compensate) {
            compensations[challenge.id].terms = RemedyTerms(review.asset, review.recipient, review.amount);
        }
        AVAGovernanceKernel.RecognisedStateReference memory source =
            GOVERNANCE_KERNEL.getRecognisedStateReference(record.input.recognisedStateId);
        _writeResolution(
            challenge,
            record,
            source,
            ResolutionInput({
                challengeId: challenge.id,
                expectedPreviousResolutionId: review.expectedTargetVersion,
                roleKey: review.roleKey,
                authorityId: review.authorityId,
                decisionEvidenceId: review.evidenceId,
                outcome: outcome,
                reasonHash: review.reasonHash,
                remedy: RemedyTerms(review.asset, review.recipient, review.amount),
                finding: IAVACorrectionReview.FindingInput(0, 0, bytes32(0), bytes32(0), bytes32(0))
            }),
            review.reviewHash,
            review.actor
        );
    }

    function resolveRequestChallenge(ResolutionInput calldata input) external {
        RequestChallenge storage challenge = _challenge(input.challengeId);
        RequestRecord storage record = requests[challenge.requestId];
        AVAGovernanceKernel.RecognisedStateReference memory source =
            GOVERNANCE_KERNEL.getRecognisedStateReference(record.input.recognisedStateId);
        bytes32 decisionHash = keccak256(
            abi.encode(
                AVARequestCorrectionActions.RESOLVE,
                block.chainid,
                address(this),
                record.id,
                input,
                _correctionContextHash(record, source)
            )
        );
        SUPPORT.validateResolutionTerms(
            AVARequestSupport.ResolutionTerms({
                challengeId: challenge.id,
                expectedHead: input.expectedPreviousResolutionId,
                evidenceId: input.decisionEvidenceId,
                outcome: uint8(input.outcome),
                reasonHash: input.reasonHash,
                asset: input.remedy.asset,
                recipient: input.remedy.recipient,
                amount: input.remedy.amount,
                actor: msg.sender,
                roleKey: input.roleKey,
                authorityId: input.authorityId,
                decisionHash: decisionHash,
                contextHash: _correctionContextHash(record, source)
            }),
            _correctionReviewTarget(challenge.id)
        );
        GOVERNANCE_KERNEL.CORRECTIONS()
            .recordFinding(
                IAVACorrectionReview.FindingFormation({
                    caseId: correctionReviewCaseIdByChallenge[challenge.id],
                    targetVersion: input.expectedPreviousResolutionId,
                    evidenceId: input.decisionEvidenceId,
                    roleKey: input.roleKey,
                    authorityId: input.authorityId,
                    verifier: msg.sender,
                    substantive: input.outcome == ResolutionOutcome.Rejected
                        || input.outcome == ResolutionOutcome.Withdrawn || input.outcome == ResolutionOutcome.Residual
                        || input.outcome == ResolutionOutcome.Compensate,
                    finding: input.finding
                })
            );
        if (input.outcome == ResolutionOutcome.Compensate) compensations[challenge.id].terms = input.remedy;
        _writeResolution(challenge, record, source, input, decisionHash, msg.sender);
    }

    function _writeResolution(
        RequestChallenge storage challenge,
        RequestRecord storage record,
        AVAGovernanceKernel.RecognisedStateReference memory source,
        ResolutionInput memory input,
        bytes32 decisionHash,
        address actor
    ) private {
        if (challenge.outcome == ResolutionOutcome.None) --openChallengeCountByRequest[record.id];
        challenge.decisionEvidenceId = input.decisionEvidenceId;
        challenge.outcome = input.outcome;
        challenge.reasonHash = input.reasonHash;
        challenge.resolutionHash = decisionHash;
        challenge.previousResolutionId = input.expectedPreviousResolutionId;
        challenge.resolvedBy = actor;
        challenge.resolverAuthorityId = input.authorityId;
        challenge.resolvedAt = uint64(block.timestamp);
        challenge.consumedAtResolution = record.consumed;
        challenge.completedAtResolution = record.completed;
        challenge.effectHashAtResolution = record.effectHash;
        challenge.sourceTransitionIdAtResolution = source.lastTransitionId;
        challenge.sourceStatusAtResolution = source.status;
        lastResolutionIdByRequest[record.id] = challenge.id;
        if (input.outcome == ResolutionOutcome.Withdrawn) withdrawalResolutionIdByRequest[record.id] = challenge.id;
        emit RequestChallengeResolved(challenge.id, record.id, input.outcome, decisionHash);
    }

    function _correctionContextHash(
        RequestRecord storage record,
        AVAGovernanceKernel.RecognisedStateReference memory source
    ) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                record.id,
                supportWitnessHash[record.id],
                record.recognisedStateTransitionId,
                source.lastTransitionId,
                source.status,
                record.consumed,
                record.completed,
                record.effectHash
            )
        );
    }

    function getRequestChallenge(uint256 challengeId) external view returns (RequestChallenge memory) {
        return _challenge(challengeId);
    }

    function getCompensation(uint256 challengeId) external view returns (CompensationRecord memory) {
        _challenge(challengeId);
        return compensations[challengeId];
    }

    /// @notice Voluntary fresh funding; no application reserve or obligation is touched.
    /// @dev Supports standard, non-rebasing ERC20 assets with exact transfers and optional boolean returns.
    function fundCompensation(uint256 challengeId) external nonReentrantEscrow {
        RequestChallenge storage challenge = _challenge(challengeId);
        AVARequestCompensation.fund(
            challengeId, challenge.outcome == ResolutionOutcome.Compensate, compensations[challengeId]
        );
    }

    /// @notice Payment stays available under already authorised terms if source actors/evidence later disappear.
    function claimCompensation(uint256 challengeId) external nonReentrantEscrow {
        RequestChallenge storage challenge = _challenge(challengeId);
        AVARequestCompensation.claim(
            challengeId, challenge.requestId, requests[challenge.requestId].effectHash, compensations[challengeId]
        );
    }

    function _challenge(uint256 id) private view returns (RequestChallenge storage challenge) {
        challenge = requestChallenges[id];
        if (challenge.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function _request(uint256 requestId) private view returns (RequestRecord storage record) {
        record = requests[requestId];
        if (record.id == 0) revert AVACoreTypes.UnknownReference(requestId);
    }

    function _requireOpen(RequestRecord storage record) private view {
        if (
            record.cancelled || record.consumed || record.completed || withdrawalResolutionIdByRequest[record.id] != 0
                || supersededByRequest[record.id] != 0
                || consumedRequestIdByMeaning[_meaningKey(record.appId, record.input)] != 0
                || block.timestamp >= record.input.validUntil
        ) {
            revert AVACoreTypes.InvalidState(record.id);
        }
    }

    function _source(RequestInput memory input)
        private
        view
        returns (AVAGovernanceKernel.RecognisedStateReference memory source)
    {
        if (
            input.executor == address(0) || input.executor.code.length == 0 || input.responseClass == bytes32(0)
                || input.parametersHash == bytes32(0) || input.burdenHash == bytes32(0)
                || input.validUntil <= block.timestamp
        ) revert AVACoreTypes.EmptyValue();
        source = GOVERNANCE_KERNEL.getRecognisedStateReference(input.recognisedStateId);
        // Full primary and witness validation runs atomically at binding or combined Allocation, including
        // commitment, subject, evidence and historical package checks in the fixed helper.
    }

    function _requireOriginalSource(RequestRecord storage record) private view {
        SUPPORT.validateSupport(record.id);
    }

    function _meaningKey(bytes32 appId, RequestInput memory input) private view returns (bytes32) {
        // Repeated occurrences must have distinct parameter commitments. A new deadline or burden
        // cannot manufacture a second execution of the same substantive instruction.
        return keccak256(
            abi.encode(block.chainid, address(this), appId, input.executor, input.responseClass, input.parametersHash)
        );
    }

    function _requestContext(RequestRecord storage record)
        private
        view
        returns (IAVARequestPolicy.RequestContext memory)
    {
        RequestInput memory input = record.input;
        return IAVARequestPolicy.RequestContext({
            requestAllocation: address(this),
            requestId: record.id,
            appId: record.appId,
            workflowKey: record.workflowKey,
            packageId: record.packageId,
            primaryRecognisedStateId: input.recognisedStateId,
            executor: input.executor,
            responseClass: input.responseClass,
            parametersHash: input.parametersHash,
            burdenHash: input.burdenHash,
            validUntil: input.validUntil,
            commitment: commitmentFor(
                record.appId,
                input.executor,
                input.responseClass,
                input.parametersHash,
                input.burdenHash,
                input.validUntil
            ),
            exactCommitment: !scopedSupportByRequest[record.id]
        });
    }

    /// @dev Each entry point validates this binding before returning, via support or atomic Allocation.
    function _bindSupport(RequestRecord storage record, IAVARequestPolicy.WitnessInput[] memory input) private {
        supportWitnessHash[record.id] = SUPPORT.bind(_requestContext(record), record.recognisedStateTransitionId, input);
        emit RequestSupportBound(record.id, supportWitnessHash[record.id], !scopedSupportByRequest[record.id]);
    }

    function _validateRequestDecision(RequestRecord storage record, bytes32 roleKey, bytes32 authorityId, address actor)
        private
        view
    {
        SUPPORT.validateDecision(
            record.id, IAVARequestPolicy.DecisionContext(roleKey, authorityId, actor, uint64(block.timestamp))
        );
    }
}

/// @notice Fixed escrow implementation; delegatecall preserves the allocation's storage, sender and balances.
library AVARequestCompensation {
    event CompensationFunded(uint256 indexed challengeId, address indexed funder, address asset, uint256 amount);
    event CompensationPaid(uint256 indexed challengeId, address indexed recipient, bytes32 paymentHash);

    function fund(uint256 challengeId, bool authorised, AVARequestAllocation.CompensationRecord storage compensation)
        external
    {
        if (!authorised || compensation.funded) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        AVARequestAllocation.RemedyTerms memory terms = compensation.terms;
        uint256 beforeBalance = IAVACompensationAsset(terms.asset).balanceOf(address(this));
        _transferAsset(
            terms.asset, abi.encodeCall(IAVACompensationAsset.transferFrom, (msg.sender, address(this), terms.amount))
        );
        if (IAVACompensationAsset(terms.asset).balanceOf(address(this)) != beforeBalance + terms.amount) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        compensation.funded = true;
        compensation.funder = msg.sender;
        compensation.fundedAt = uint64(block.timestamp);
        emit CompensationFunded(challengeId, msg.sender, terms.asset, terms.amount);
    }

    function claim(
        uint256 challengeId,
        uint256 requestId,
        bytes32 effectHash,
        AVARequestAllocation.CompensationRecord storage compensation
    ) external {
        if (!compensation.funded || compensation.paid || msg.sender != compensation.terms.recipient) {
            revert AVACoreTypes.InvalidState(challengeId);
        }
        AVARequestAllocation.RemedyTerms memory terms = compensation.terms;
        uint256 recipientBefore = IAVACompensationAsset(terms.asset).balanceOf(terms.recipient);
        uint256 escrowBefore = IAVACompensationAsset(terms.asset).balanceOf(address(this));
        compensation.paid = true;
        compensation.paidAt = uint64(block.timestamp);
        compensation.paymentHash = keccak256(
            abi.encode(
                keccak256("ava.request-compensation.payment.v1"),
                block.chainid,
                address(this),
                challengeId,
                requestId,
                effectHash,
                terms,
                compensation.funder,
                terms.recipient,
                compensation.paidAt
            )
        );
        _transferAsset(terms.asset, abi.encodeCall(IAVACompensationAsset.transfer, (terms.recipient, terms.amount)));
        if (
            IAVACompensationAsset(terms.asset).balanceOf(terms.recipient) != recipientBefore + terms.amount
                || IAVACompensationAsset(terms.asset).balanceOf(address(this)) != escrowBefore - terms.amount
        ) revert AVACoreTypes.InvalidState(challengeId);
        emit CompensationPaid(challengeId, terms.recipient, compensation.paymentHash);
    }

    function _transferAsset(address asset, bytes memory data) private {
        if (asset.code.length == 0) revert AVACoreTypes.EmptyValue();
        (bool ok, bytes memory result) = asset.call(data);
        if (!ok || (result.length != 0 && (result.length != 32 || !abi.decode(result, (bool))))) {
            revert AVACoreTypes.InvalidState(0);
        }
    }
}
