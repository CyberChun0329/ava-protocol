// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../../core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../../core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../../core/AVACoreRulePackageRegistry.sol";
import {AVAGovernanceKernel} from "../../core/AVAGovernanceKernel.sol";
import {IAVAAuthorityPolicyModule} from "../../core/interfaces/IAVACoreRuleModules.sol";
import {IAVARuleGovernance} from "../../core/interfaces/IAVARuleGovernance.sol";
import {IAVARuleRevisionPolicy} from "../../core/interfaces/IAVARuleRevisionPolicy.sol";
import {RuleModuleIdentity} from "../../interfaces/IRuleModuleIdentity.sol";

/// @notice Recognised proposals support a separate revision decision; they never activate themselves.
/// @dev Enrollment accepts an institutional bootstrap. Neither enrollment nor this controller establishes its legitimacy.
contract AVARecognisedRuleGovernance is IAVARuleGovernance, RuleModuleIdentity {
    bytes32 public constant ACTION_PROPOSE_RULE_REVISION = keccak256("ava.extension.rule-governance.propose.v1");
    bytes32 public constant ACTION_REVISE_RULE = keccak256("ava.extension.rule-governance.revise.v1");
    bytes32 public constant RULE_REVISION_OBJECT = keccak256("ava.rule-revision.proposal.v1");
    bytes32 private constant CORRECTION_DOMAIN = keccak256("ava.rule-revision.corrective-proposal.v1");

    struct ProposalInput {
        uint256 sourceStateId;
        uint256 expectedSourceTransitionId;
        uint256 expectedTargetPackageId;
        uint256 correctionOfAppliedProposal;
    }

    struct ProposalRecord {
        uint256 id;
        bytes32 appId;
        bytes32 targetWorkflowKey;
        uint256 sourceStateId;
        uint256 sourceObjectId;
        uint256 sourceTransitionId;
        uint256 governancePackageId;
        uint256 expectedTargetPackageId;
        bytes32 sourceSubjectId;
        bytes32 revisionCommitment;
        bytes32 proposalCommitment;
        uint64 proposedVersion;
        bytes32 proposedAuthorityId;
        bytes32 proposedRoleKey;
        uint256 correctionOfAppliedProposal;
        address proposer;
        bytes32 proposerRoleKey;
        bytes32 proposerAuthorityId;
        address recognisedBy;
        address sourceDecisionActor;
        uint64 recognisedAt;
        uint64 submittedAt;
        uint256 ratificationId;
        uint256 activationId;
    }

    struct RatificationRecord {
        uint256 id;
        uint256 proposalId;
        uint256 sourceStateId;
        uint256 sourceTransitionId;
        uint256 governancePackageId;
        uint256 previousPackageId;
        bytes32 revisionCommitment;
        address actor;
        bytes32 actorRoleKey;
        bytes32 actorAuthorityId;
        uint64 ratifiedAt;
    }

    struct ActivationRecord {
        uint256 id;
        uint256 proposalId;
        uint256 ratificationId;
        bytes32 appId;
        bytes32 targetWorkflowKey;
        uint256 sourceStateId;
        uint256 sourceTransitionId;
        uint256 governancePackageId;
        uint256 previousPackageId;
        uint256 replacementPackageId;
        bytes32 revisionCommitment;
        uint256 correctionOfAppliedProposal;
        address actor;
        bytes32 actorAuthorityId;
        uint64 activatedAt;
    }

    AVAGovernanceKernel public immutable GOVERNANCE_KERNEL;
    address public immutable RULE_PACKAGE_REGISTRY;
    bytes32 public immutable GOVERNANCE_WORKFLOW_KEY;
    mapping(uint256 => ProposalRecord) private proposals;
    mapping(uint256 => RatificationRecord) private ratifications;
    mapping(uint256 => ActivationRecord) private activations;
    mapping(uint256 => uint256) public proposalIdBySourceState;
    uint256 public nextProposalId = 1;
    uint256 public nextRatificationId = 1;
    uint256 public nextActivationId = 1;
    bytes32 private executingCommitment;
    bool private entered;

    event RuleRevisionProposed(
        uint256 indexed proposalId, uint256 indexed sourceStateId, bytes32 indexed appId, bytes32 commitment
    );
    event RuleRevisionRatified(uint256 indexed ratificationId, uint256 indexed proposalId, address indexed actor);
    event RuleRevisionActivated(
        uint256 indexed activationId, uint256 indexed proposalId, uint256 indexed replacementPackageId
    );

    constructor(AVAGovernanceKernel kernel, bytes32 governanceWorkflowKey) {
        if (address(kernel).code.length == 0 || governanceWorkflowKey == bytes32(0)) revert AVACoreTypes.EmptyValue();
        GOVERNANCE_KERNEL = kernel;
        RULE_PACKAGE_REGISTRY = address(kernel.RULE_PACKAGE_REGISTRY());
        GOVERNANCE_WORKFLOW_KEY = governanceWorkflowKey;
    }

    modifier nonReentrant() {
        if (entered) revert AVACoreTypes.InvalidState(0);
        entered = true;
        _;
        entered = false;
    }

    /// @notice Ordinary objects commit directly to registry.revisionCommitment; corrective objects also commit to lineage.
    /// @dev Both the governed object's objectCommitment and metadataHash must equal this result.
    function proposalCommitmentFor(bytes32 revisionHash, uint256 correctionOfAppliedProposal)
        public
        view
        returns (bytes32)
    {
        if (correctionOfAppliedProposal == 0) return revisionHash;
        return keccak256(
            abi.encode(CORRECTION_DOMAIN, block.chainid, address(this), revisionHash, correctionOfAppliedProposal)
        );
    }

    function registerProposal(
        ProposalInput calldata input,
        AVACoreRulePackageRegistry.PackageRegistrationInput calldata proposed,
        AVACoreRulePackageRegistry.ModuleBinding[] calldata bindings,
        bytes32 proposerRoleKey,
        bytes32 proposerAuthorityId
    ) external nonReentrant returns (uint256 id) {
        AVACoreRulePackageRegistry registry = AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY);
        AVACoreTypes.RecognisedStateRecord memory source = GOVERNANCE_KERNEL.getRecognisedState(input.sourceStateId);
        _requireSource(source, input.expectedSourceTransitionId);
        _requireSealedPair(proposed.appId, proposed.workflowKey);
        _requireRevisionContinuation(proposed.workflowKey, bindings);
        if (
            source.appId != proposed.appId || source.workflowKey != GOVERNANCE_WORKFLOW_KEY
                || registry.getActivePackageId(source.appId, GOVERNANCE_WORKFLOW_KEY) != source.packageId
                || proposalIdBySourceState[source.id] != 0
        ) revert AVACoreTypes.InvalidState(source.id);
        AVACoreRulePackageRegistry.VerifiedPackageContext memory previous =
            registry.getVerifiedPackageContext(input.expectedTargetPackageId);
        if (
            registry.getActivePackageId(proposed.appId, proposed.workflowKey) != previous.packageId
                || previous.appId != proposed.appId || previous.workflowKey != proposed.workflowKey
                || proposed.version != previous.version + 1 || proposed.compatibilityKey != previous.compatibilityKey
        ) revert AVACoreTypes.InvalidState(previous.packageId);
        // Verify the current governing package and require a separate, declared revision capability now.
        registry.getModule(source.packageId, AVACapabilityKeys.RULE_REVISION);
        bytes32 revisionHash = registry.revisionCommitment(proposed, previous.packageId, bindings);
        bytes32 proposalHash = proposalCommitmentFor(revisionHash, input.correctionOfAppliedProposal);
        (AVAGovernanceKernel.GovernedObjectReference memory object, bytes32 objectCommitment, bytes32 metadataHash) =
            GOVERNANCE_KERNEL.getGovernedObjectCommitmentReference(source.governedObjectId);
        if (
            object.objectTypeKey != RULE_REVISION_OBJECT || objectCommitment != proposalHash
                || metadataHash != proposalHash || object.packageId != source.packageId
                || object.subjectId != source.subjectId
        ) revert AVACoreTypes.InvalidState(object.id);
        _requireProposer(source.subjectId, source.appId, msg.sender);
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(
                msg.sender, source.appId, proposerRoleKey, ACTION_PROPOSE_RULE_REVISION, proposerAuthorityId
            );
        if (input.correctionOfAppliedProposal != 0) {
            ProposalRecord storage predecessor = _proposal(input.correctionOfAppliedProposal);
            if (
                predecessor.activationId == 0 || predecessor.appId != proposed.appId
                    || predecessor.targetWorkflowKey != proposed.workflowKey || predecessor.sourceStateId == source.id
            ) revert AVACoreTypes.InvalidState(predecessor.id);
        }
        _validateAuthority(
            source,
            object.objectTypeKey,
            ACTION_PROPOSE_RULE_REVISION,
            proposerRoleKey,
            proposerAuthorityId,
            proposalHash,
            msg.sender
        );
        AVACoreTypes.RecognisedStateTransitionRecord memory sourceTransition =
            GOVERNANCE_KERNEL.getRecognisedStateTransition(source.lastTransitionId);
        id = nextProposalId++;
        proposals[id] = ProposalRecord({
            id: id,
            appId: source.appId,
            targetWorkflowKey: proposed.workflowKey,
            sourceStateId: source.id,
            sourceObjectId: object.id,
            sourceTransitionId: source.lastTransitionId,
            governancePackageId: source.packageId,
            expectedTargetPackageId: previous.packageId,
            sourceSubjectId: source.subjectId,
            revisionCommitment: revisionHash,
            proposalCommitment: proposalHash,
            proposedVersion: proposed.version,
            proposedAuthorityId: proposed.authorityId,
            proposedRoleKey: proposed.roleKey,
            correctionOfAppliedProposal: input.correctionOfAppliedProposal,
            proposer: msg.sender,
            proposerRoleKey: proposerRoleKey,
            proposerAuthorityId: proposerAuthorityId,
            recognisedBy: source.createdBy,
            sourceDecisionActor: sourceTransition.createdBy,
            recognisedAt: sourceTransition.createdAt,
            submittedAt: uint64(block.timestamp),
            ratificationId: 0,
            activationId: 0
        });
        proposalIdBySourceState[source.id] = id;
        emit RuleRevisionProposed(id, source.id, source.appId, proposalHash);
    }

    /// @notice Ratification uses the OLD current policy; activation and both receipts succeed or roll back together.
    function executeProposal(
        uint256 proposalId,
        AVACoreRulePackageRegistry.PackageRegistrationInput calldata proposed,
        AVACoreRulePackageRegistry.ModuleBinding[] calldata bindings,
        bytes32 reviserRoleKey,
        bytes32 reviserAuthorityId
    ) external nonReentrant returns (uint256 replacementPackageId) {
        ProposalRecord storage proposal = _proposal(proposalId);
        if (proposal.activationId != 0) revert AVACoreTypes.InvalidState(proposalId);
        AVACoreRulePackageRegistry registry = AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY);
        _requireSealedPair(proposal.appId, proposal.targetWorkflowKey);
        _requireRevisionContinuation(proposal.targetWorkflowKey, bindings);
        if (
            proposed.appId != proposal.appId || proposed.workflowKey != proposal.targetWorkflowKey
                || registry.getActivePackageId(proposal.appId, GOVERNANCE_WORKFLOW_KEY) != proposal.governancePackageId
                || registry.getActivePackageId(proposal.appId, proposal.targetWorkflowKey)
                    != proposal.expectedTargetPackageId
                || registry.revisionCommitment(proposed, proposal.expectedTargetPackageId, bindings)
                    != proposal.revisionCommitment
        ) revert AVACoreTypes.InvalidState(proposalId);
        AVACoreTypes.RecognisedStateRecord memory source = GOVERNANCE_KERNEL.getRecognisedState(proposal.sourceStateId);
        _requireSource(source, proposal.sourceTransitionId);
        _requireProposer(proposal.sourceSubjectId, proposal.appId, proposal.proposer);
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(
                proposal.proposer,
                proposal.appId,
                proposal.proposerRoleKey,
                ACTION_PROPOSE_RULE_REVISION,
                proposal.proposerAuthorityId
            );
        GOVERNANCE_KERNEL.AUTHORITY_MATRIX()
            .requireAuthorisedSubject(
                msg.sender, proposal.appId, reviserRoleKey, ACTION_REVISE_RULE, reviserAuthorityId
            );
        _validateAuthority(
            source,
            RULE_REVISION_OBJECT,
            ACTION_REVISE_RULE,
            reviserRoleKey,
            reviserAuthorityId,
            proposal.proposalCommitment,
            msg.sender
        );
        AVACoreRulePackageRegistry.VerifiedPackageContext memory governing =
            registry.getVerifiedPackageContext(proposal.governancePackageId);
        AVACoreRulePackageRegistry.VerifiedPackageContext memory previous =
            registry.getVerifiedPackageContext(proposal.expectedTargetPackageId);
        IAVARuleRevisionPolicy(registry.getModule(proposal.governancePackageId, AVACapabilityKeys.RULE_REVISION))
            .validateRuleRevision(
                _revisionContext(
                    proposal, governing.authorityId, previous.authorityId, reviserRoleKey, reviserAuthorityId
                )
            );
        uint256 ratificationId = nextRatificationId++;
        ratifications[ratificationId] = RatificationRecord({
            id: ratificationId,
            proposalId: proposalId,
            sourceStateId: proposal.sourceStateId,
            sourceTransitionId: proposal.sourceTransitionId,
            governancePackageId: proposal.governancePackageId,
            previousPackageId: proposal.expectedTargetPackageId,
            revisionCommitment: proposal.revisionCommitment,
            actor: msg.sender,
            actorRoleKey: reviserRoleKey,
            actorAuthorityId: reviserAuthorityId,
            ratifiedAt: uint64(block.timestamp)
        });
        proposal.ratificationId = ratificationId;
        executingCommitment = proposal.revisionCommitment;
        replacementPackageId = registry.supersedeRulePackage(proposed, proposal.expectedTargetPackageId, bindings);
        GOVERNANCE_KERNEL.inheritGovernedPackageBindings(proposal.expectedTargetPackageId, replacementPackageId);
        executingCommitment = bytes32(0);
        uint256 activationId = nextActivationId++;
        activations[activationId] = ActivationRecord({
            id: activationId,
            proposalId: proposalId,
            ratificationId: ratificationId,
            appId: proposal.appId,
            targetWorkflowKey: proposal.targetWorkflowKey,
            sourceStateId: proposal.sourceStateId,
            sourceTransitionId: proposal.sourceTransitionId,
            governancePackageId: proposal.governancePackageId,
            previousPackageId: proposal.expectedTargetPackageId,
            replacementPackageId: replacementPackageId,
            revisionCommitment: proposal.revisionCommitment,
            correctionOfAppliedProposal: proposal.correctionOfAppliedProposal,
            actor: msg.sender,
            actorAuthorityId: reviserAuthorityId,
            activatedAt: uint64(block.timestamp)
        });
        proposal.activationId = activationId;
        emit RuleRevisionRatified(ratificationId, proposalId, msg.sender);
        emit RuleRevisionActivated(activationId, proposalId, replacementPackageId);
    }

    /// @notice Both the governing bootstrap and enrolled target must retain a source-correction route.
    function validateGovernanceEnrollment(bytes32 appId, bytes32 workflowKey, uint256 packageId) external view {
        if (msg.sender != RULE_PACKAGE_REGISTRY) revert AVACoreTypes.InvalidState(packageId);
        AVACoreRulePackageRegistry registry = AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY);
        if (registry.getActivePackageId(appId, workflowKey) != packageId) revert AVACoreTypes.InvalidState(packageId);
        _requireGoverningBindings(appId);
        _requireCorrectionBindings(packageId);
        if (
            workflowKey != GOVERNANCE_WORKFLOW_KEY
                && registry.governanceController(appId, GOVERNANCE_WORKFLOW_KEY) != address(this)
        ) revert AVACoreTypes.InvalidState(packageId);
    }

    function _requireRevisionContinuation(
        bytes32 workflowKey,
        AVACoreRulePackageRegistry.ModuleBinding[] calldata bindings
    ) private view {
        if (workflowKey != GOVERNANCE_WORKFLOW_KEY) return;
        for (uint256 i; i < bindings.length; ++i) {
            if (
                bindings[i].capabilityKey == AVACapabilityKeys.RULE_REVISION
                    && address(bindings[i].module) != address(0)
            ) return;
        }
        revert AVACoreTypes.InvalidState(0);
    }

    function _requireGoverningBindings(bytes32 appId) private view {
        AVACoreRulePackageRegistry registry = AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY);
        uint256 packageId = registry.getActivePackageId(appId, GOVERNANCE_WORKFLOW_KEY);
        registry.getModule(packageId, AVACapabilityKeys.RULE_REVISION);
        _requireCorrectionBindings(packageId);
    }

    function _requireCorrectionBindings(uint256 packageId) private view {
        address requester = GOVERNANCE_KERNEL.sourceBoundTransitionRequesterByPackage(packageId);
        if (requester == address(0) || requester != address(GOVERNANCE_KERNEL.transitionGuardByPackage(packageId))) {
            revert AVACoreTypes.InvalidState(packageId);
        }
        GOVERNANCE_KERNEL.requireStablePackageBindings(packageId);
    }

    function validateRuleRevision(bytes32 commitment) external view {
        if (
            msg.sender != RULE_PACKAGE_REGISTRY || !entered || commitment == bytes32(0)
                || commitment != executingCommitment
        ) {
            revert AVACoreTypes.NotAuthorised(msg.sender, ACTION_REVISE_RULE);
        }
    }

    function getProposal(uint256 id) external view returns (ProposalRecord memory) {
        return _proposal(id);
    }

    function getRatification(uint256 id) external view returns (RatificationRecord memory) {
        if (ratifications[id].id == 0) revert AVACoreTypes.UnknownReference(id);
        return ratifications[id];
    }

    function getActivation(uint256 id) external view returns (ActivationRecord memory) {
        if (activations[id].id == 0) revert AVACoreTypes.UnknownReference(id);
        return activations[id];
    }

    function _requireSource(AVACoreTypes.RecognisedStateRecord memory source, uint256 transitionId) private view {
        if (
            transitionId == 0 || source.lastTransitionId != transitionId
                || source.stage != AVACoreTypes.Stage.Verification
                || (source.status != AVACoreTypes.RecognisedStateStatus.Vested
                    && source.status != AVACoreTypes.RecognisedStateStatus.Restored)
        ) revert AVACoreTypes.InvalidState(source.id);
        GOVERNANCE_KERNEL.DEPENDENCIES().requireCurrent(source.governedObjectId);
        AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY).getVerifiedPackageContext(source.packageId);
        GOVERNANCE_KERNEL.IDENTITY_REGISTRY().requireActiveSubjectReference(source.subjectId, source.appId);
        GOVERNANCE_KERNEL.EVIDENCE_REGISTRY()
            .requireUsableEvidenceReferenceForPackage(source.evidenceReceiptId, source.packageId);
        GOVERNANCE_KERNEL.DISCLOSURE_REGISTRY().requireActivePolicyReference(source.disclosurePolicyId, source.appId);
    }

    function _requireProposer(bytes32 subjectId, bytes32 appId, address proposer) private view {
        AVACoreTypes.SubjectRecord memory subject =
            GOVERNANCE_KERNEL.IDENTITY_REGISTRY().requireActiveSubject(subjectId, appId);
        if (
            subject.account != proposer
                || GOVERNANCE_KERNEL.IDENTITY_REGISTRY().subjectOf(proposer, appId, subject.roleKey) != subjectId
        ) {
            revert AVACoreTypes.SubjectMismatch(subjectId, bytes32(uint256(uint160(proposer))));
        }
    }

    function _requireSealedPair(bytes32 appId, bytes32 targetWorkflowKey) private view {
        _requireGoverningBindings(appId);
        AVACoreRulePackageRegistry registry = AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY);
        bool distinctWorkflow = targetWorkflowKey != GOVERNANCE_WORKFLOW_KEY;
        // A workflow changing its own rules already passed the same binding checks above.
        if (distinctWorkflow) _requireCorrectionBindings(registry.getActivePackageId(appId, targetWorkflowKey));
        if (
            registry.governanceController(appId, targetWorkflowKey) != address(this)
                || (distinctWorkflow && registry.governanceController(appId, GOVERNANCE_WORKFLOW_KEY) != address(this))
        ) revert AVACoreTypes.InvalidState(0);
    }

    function _validateAuthority(
        AVACoreTypes.RecognisedStateRecord memory source,
        bytes32 objectTypeKey,
        bytes32 actionKey,
        bytes32 roleKey,
        bytes32 authorityId,
        bytes32 decisionHash,
        address actor
    ) private view {
        IAVAAuthorityPolicyModule(
                AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY)
                    .getModule(source.packageId, AVACapabilityKeys.AUTHORITY_POLICY)
            )
            .validateAuthority(
                IAVAAuthorityPolicyModule.AuthorityContext({
                    appId: source.appId,
                    workflowKey: source.workflowKey,
                    packageId: source.packageId,
                    actionKey: actionKey,
                    roleKey: roleKey,
                    stage: AVACoreTypes.Stage.Verification,
                    objectTypeKey: objectTypeKey,
                    targetId: source.governedObjectId,
                    targetSubjectId: source.subjectId,
                    authorityId: authorityId,
                    decisionHash: decisionHash,
                    actor: actor
                })
            );
    }

    function _revisionContext(
        ProposalRecord storage p,
        bytes32 governanceAuthority,
        bytes32 targetAuthority,
        bytes32 roleKey,
        bytes32 authorityId
    ) private view returns (IAVARuleRevisionPolicy.RuleRevisionContext memory) {
        return IAVARuleRevisionPolicy.RuleRevisionContext({
            appId: p.appId,
            governingWorkflowKey: GOVERNANCE_WORKFLOW_KEY,
            targetWorkflowKey: p.targetWorkflowKey,
            governancePackageId: p.governancePackageId,
            targetPackageId: p.expectedTargetPackageId,
            oldGovernanceAuthorityId: governanceAuthority,
            oldTargetAuthorityId: targetAuthority,
            proposalId: p.id,
            sourceStateId: p.sourceStateId,
            sourceObjectId: p.sourceObjectId,
            sourceTransitionId: p.sourceTransitionId,
            sourceSubjectId: p.sourceSubjectId,
            revisionCommitment: p.revisionCommitment,
            proposalCommitment: p.proposalCommitment,
            proposedVersion: p.proposedVersion,
            proposedAuthorityId: p.proposedAuthorityId,
            proposedRoleKey: p.proposedRoleKey,
            correctionOfAppliedProposal: p.correctionOfAppliedProposal,
            proposer: p.proposer,
            proposerAuthorityId: p.proposerAuthorityId,
            recognisedBy: p.recognisedBy,
            sourceDecisionActor: p.sourceDecisionActor,
            actor: msg.sender,
            actorRoleKey: roleKey,
            actorAuthorityId: authorityId,
            recognisedAt: p.recognisedAt,
            submittedAt: p.submittedAt,
            evaluatedAt: uint64(block.timestamp)
        });
    }

    function _proposal(uint256 id) private view returns (ProposalRecord storage proposal) {
        proposal = proposals[id];
        if (proposal.id == 0) revert AVACoreTypes.UnknownReference(id);
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(address(GOVERNANCE_KERNEL), RULE_PACKAGE_REGISTRY, GOVERNANCE_WORKFLOW_KEY));
    }
}
