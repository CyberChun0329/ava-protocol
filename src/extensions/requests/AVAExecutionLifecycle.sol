// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVARequestSupport} from "./AVARequestSupport.sol";

interface IAVAExecutionOwner {
    function SUPPORT() external view returns (address);
}

/// @notice A declared local adapter must confine its effect to this helper's fenced call.
interface IAVAFencedSplitExecutor {
    function fencedSplitInterfaceVersion() external view returns (uint256);
    function fencedExecutionConfigurationHash() external view returns (bytes32);
    function executeFencedEffect(uint256 requestId, uint256 attemptId, bytes calldata parameters)
        external
        returns (bytes32 effectHash);
}

/// @notice Append-only attempts for one request extension. Consumption is never undone.
/// @dev The request extension owns live support and policy checks; this fixed helper owns fencing.
contract AVAExecutionLifecycle {
    enum ReportKind {
        None,
        FailedNoEffect,
        PartialEffect,
        OutcomeUnknown,
        ContradictoryEffect
    }

    struct Declaration {
        address executor;
        bytes32 codeHash;
        bytes32 configurationHash;
        bytes32 parametersHash;
        uint256 latestAttemptId;
        uint256 liveAttemptId;
        uint256 latestReportId;
        uint256 latestRecoveryId;
        bool frozen;
        bool completed;
    }

    struct Attempt {
        uint256 id;
        uint256 requestId;
        uint256 previousAttemptId;
        uint256 recoveryId;
        address triggeredBy;
        uint64 startedAt;
        uint64 endedAt;
        bool retired;
        bool completed;
        bytes32 effectHash;
    }

    struct AttemptReport {
        uint256 id;
        uint256 requestId;
        uint256 attemptId;
        uint256 previousReportId;
        ReportKind kind;
        bytes32 receiptHash;
        address reporter;
        uint64 reportedAt;
    }

    struct RecoveryInput {
        uint256 requestId;
        uint256 expectedReportId;
        uint256 decisionEvidenceId;
        bytes32 roleKey;
        bytes32 authorityId;
        bytes32 reasonHash;
    }

    struct Recovery {
        uint256 id;
        RecoveryInput input;
        uint256 attemptId;
        uint256 previousRecoveryId;
        address actor;
        bytes32 decisionHash;
        uint64 authorisedAt;
        bool used;
    }

    address public immutable REQUEST_ALLOCATION;
    mapping(uint256 => Declaration) private declarations;
    mapping(uint256 => Attempt) private attempts;
    mapping(uint256 => AttemptReport) private reports;
    mapping(uint256 => Recovery) private recoveries;
    mapping(uint256 => uint256) private recoveryIdByReport;
    // Operations return IDs; the per-request heads and previous-record links retain the full history.
    uint256 private nextAttemptId = 1;
    uint256 private nextReportId = 1;
    uint256 private nextRecoveryId = 1;
    bool private executing;

    event SplitModeDeclared(
        uint256 indexed requestId, address indexed executor, bytes32 codeHash, bytes32 configurationHash
    );
    event AttemptStarted(uint256 indexed requestId, uint256 indexed attemptId, uint256 recoveryId);
    event AttemptReported(
        uint256 indexed requestId, uint256 indexed attemptId, uint256 indexed reportId, ReportKind kind
    );
    event RecoveryAuthorised(
        uint256 indexed requestId, uint256 indexed recoveryId, uint256 indexed reportId, address actor
    );
    event AttemptCompleted(uint256 indexed requestId, uint256 indexed attemptId, bytes32 effectHash);

    constructor() {
        REQUEST_ALLOCATION = msg.sender;
    }

    modifier onlyAllocation() {
        if (msg.sender != REQUEST_ALLOCATION || executing) revert AVACoreTypes.InvalidState(0);
        _;
    }

    function declareSplit(uint256 requestId, address executor, bytes32 parametersHash, bytes32 configurationHash)
        external
        onlyAllocation
    {
        if (declarations[requestId].executor != address(0) || configurationHash == bytes32(0)) {
            revert AVACoreTypes.InvalidState(requestId);
        }
        Declaration storage declaration = declarations[requestId];
        declaration.executor = executor;
        declaration.codeHash = executor.codehash;
        declaration.parametersHash = parametersHash;
        declaration.configurationHash = configurationHash;
        _requireIdentity(declaration, requestId);
        emit SplitModeDeclared(requestId, executor, declaration.codeHash, configurationHash);
    }

    function isSplit(uint256 requestId) external view returns (bool) {
        return declarations[requestId].executor != address(0);
    }

    function begin(uint256 requestId, address triggeredBy) external onlyAllocation returns (uint256) {
        Declaration storage declaration = _declaration(requestId);
        if (declaration.latestAttemptId != 0) revert AVACoreTypes.InvalidState(requestId);
        _requireIdentity(declaration, requestId);
        return _start(requestId, declaration, 0, triggeredBy);
    }

    /// @notice Reports remain writable after retirement or loss of live source/permission.
    /// A later uncertainty or contradiction permanently prevents further local effects.
    function report(uint256 requestId, uint256 attemptId, ReportKind kind, bytes32 receiptHash, address actor)
        external
        onlyAllocation
        returns (uint256 id)
    {
        Declaration storage declaration = _declaration(requestId);
        Attempt storage attempt = _attempt(attemptId);
        if (
            actor != declaration.executor || attempt.requestId != requestId || kind == ReportKind.None
                || receiptHash == bytes32(0)
        ) {
            revert AVACoreTypes.InvalidState(attemptId);
        }
        id = nextReportId++;
        AttemptReport storage entry = reports[id];
        entry.id = id;
        entry.requestId = requestId;
        entry.attemptId = attemptId;
        entry.previousReportId = declaration.latestReportId;
        entry.kind = kind;
        entry.receiptHash = receiptHash;
        entry.reporter = actor;
        entry.reportedAt = uint64(block.timestamp);
        declaration.latestReportId = id;
        if (!attempt.completed && !attempt.retired) {
            attempt.retired = true;
            attempt.endedAt = uint64(block.timestamp);
            if (declaration.liveAttemptId == attemptId) declaration.liveAttemptId = 0;
        }
        if (kind != ReportKind.FailedNoEffect || attempt.completed) {
            declaration.frozen = true;
            uint256 live = declaration.liveAttemptId;
            if (live != 0) {
                attempts[live].retired = true;
                attempts[live].endedAt = uint64(block.timestamp);
                declaration.liveAttemptId = 0;
            }
        }
        emit AttemptReported(requestId, attemptId, id, kind);
    }

    function authorise(RecoveryInput calldata input, address actor, address allocator, bytes32 decisionHash)
        external
        onlyAllocation
        returns (uint256 id)
    {
        Declaration storage declaration = _declaration(input.requestId);
        AttemptReport storage reportRecord = _report(input.expectedReportId);
        if (
            declaration.frozen || declaration.completed || declaration.liveAttemptId != 0
                || declaration.latestReportId != input.expectedReportId || reportRecord.requestId != input.requestId
                || reportRecord.attemptId != declaration.latestAttemptId
                || reportRecord.kind != ReportKind.FailedNoEffect || actor == allocator || actor == declaration.executor
                || actor == address(0) || input.decisionEvidenceId == 0 || input.reasonHash == bytes32(0)
                || recoveryIdByReport[input.expectedReportId] != 0
        ) revert AVACoreTypes.InvalidState(input.requestId);
        _validateRecovery(input, actor, decisionHash);
        id = nextRecoveryId++;
        Recovery storage entry = recoveries[id];
        entry.id = id;
        entry.input = input;
        entry.attemptId = reportRecord.attemptId;
        entry.previousRecoveryId = declaration.latestRecoveryId;
        entry.actor = actor;
        entry.decisionHash = decisionHash;
        entry.authorisedAt = uint64(block.timestamp);
        declaration.latestRecoveryId = id;
        recoveryIdByReport[input.expectedReportId] = id;
        emit RecoveryAuthorised(input.requestId, id, input.expectedReportId, actor);
    }

    function recover(uint256 requestId, uint256 recoveryId, address triggeredBy)
        external
        onlyAllocation
        returns (uint256)
    {
        Declaration storage declaration = _declaration(requestId);
        Recovery storage recovery = _recovery(recoveryId);
        if (
            declaration.frozen || declaration.completed || declaration.liveAttemptId != 0 || recovery.used
                || recovery.input.requestId != requestId || declaration.latestRecoveryId != recoveryId
                || declaration.latestReportId != recovery.input.expectedReportId
                || declaration.latestAttemptId != recovery.attemptId
        ) revert AVACoreTypes.InvalidState(recoveryId);
        _validateRecovery(recovery.input, recovery.actor, recovery.decisionHash);
        _requireIdentity(declaration, requestId);
        recovery.used = true;
        return _start(requestId, declaration, recoveryId, triggeredBy);
    }

    /// @notice Adapter effect and completion share this transaction; any later failure rolls both back.
    function complete(uint256 requestId, uint256 attemptId, bytes calldata parameters)
        external
        onlyAllocation
        returns (bytes32 effectHash)
    {
        Declaration storage declaration = _declaration(requestId);
        Attempt storage attempt = _attempt(attemptId);
        if (
            declaration.frozen || declaration.completed || declaration.liveAttemptId != attemptId
                || attempt.requestId != requestId || attempt.retired || attempt.completed
                || keccak256(parameters) != declaration.parametersHash
        ) revert AVACoreTypes.InvalidState(attemptId);
        if (attempt.recoveryId != 0) {
            Recovery storage recovery = recoveries[attempt.recoveryId];
            _validateRecovery(recovery.input, recovery.actor, recovery.decisionHash);
        }
        _requireIdentity(declaration, requestId);
        executing = true;
        effectHash = IAVAFencedSplitExecutor(declaration.executor).executeFencedEffect(requestId, attemptId, parameters);
        if (effectHash == bytes32(0)) revert AVACoreTypes.InvalidState(attemptId);
        _requireIdentity(declaration, requestId);
        executing = false;
        attempt.completed = true;
        attempt.effectHash = effectHash;
        attempt.endedAt = uint64(block.timestamp);
        declaration.completed = true;
        declaration.liveAttemptId = 0;
        emit AttemptCompleted(requestId, attemptId, effectHash);
    }

    function getDeclaration(uint256 requestId) external view returns (Declaration memory) {
        return _declaration(requestId);
    }

    function getAttempt(uint256 id) external view returns (Attempt memory) {
        return _attempt(id);
    }

    function getReport(uint256 id) external view returns (AttemptReport memory) {
        return _report(id);
    }

    function getRecovery(uint256 id) external view returns (Recovery memory) {
        return _recovery(id);
    }

    function _validateRecovery(RecoveryInput memory input, address actor, bytes32 decisionHash) private view {
        AVARequestSupport(IAVAExecutionOwner(REQUEST_ALLOCATION).SUPPORT())
            .validateRecovery(
                input.requestId,
                AVARequestSupport.CorrectionInput({
                    actionKey: keccak256("ava.extension.request.recovery.authorise.v1"),
                    roleKey: input.roleKey,
                    authorityId: input.authorityId,
                    evidenceId: input.decisionEvidenceId,
                    decisionHash: decisionHash,
                    challengeId: input.expectedReportId,
                    outcomeKey: bytes32(0),
                    validateDisclosure: false,
                    actor: actor
                })
            );
    }

    function _start(uint256 requestId, Declaration storage declaration, uint256 recoveryId, address triggeredBy)
        private
        returns (uint256 id)
    {
        id = nextAttemptId++;
        Attempt storage entry = attempts[id];
        entry.id = id;
        entry.requestId = requestId;
        entry.previousAttemptId = declaration.latestAttemptId;
        entry.recoveryId = recoveryId;
        entry.triggeredBy = triggeredBy;
        entry.startedAt = uint64(block.timestamp);
        declaration.latestAttemptId = id;
        declaration.liveAttemptId = id;
        emit AttemptStarted(requestId, id, recoveryId);
    }

    function _requireIdentity(Declaration storage declaration, uint256 id) private view {
        if (
            declaration.executor.code.length == 0 || declaration.executor.codehash != declaration.codeHash
                || IAVAFencedSplitExecutor(declaration.executor).fencedSplitInterfaceVersion() != 1
                || IAVAFencedSplitExecutor(declaration.executor).fencedExecutionConfigurationHash()
                    != declaration.configurationHash
        ) revert AVACoreTypes.InvalidState(id);
    }

    function _declaration(uint256 id) private view returns (Declaration storage value) {
        value = declarations[id];
        if (value.executor == address(0)) revert AVACoreTypes.UnknownReference(id);
    }

    function _attempt(uint256 id) private view returns (Attempt storage value) {
        value = attempts[id];
        if (value.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function _report(uint256 id) private view returns (AttemptReport storage value) {
        value = reports[id];
        if (value.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function _recovery(uint256 id) private view returns (Recovery storage value) {
        value = recoveries[id];
        if (value.id == 0) revert AVACoreTypes.UnknownReference(id);
    }
}
