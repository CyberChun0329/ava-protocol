// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVARuleGovernance} from "../src/core/interfaces/IAVARuleGovernance.sol";
import {IAVAPostTransitionHook} from "../src/core/interfaces/IAVAPostTransitionHook.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {AVARecognisedRuleGovernance} from "../src/extensions/governance/AVARecognisedRuleGovernance.sol";
import {AVALocalRuleRevisionPolicy} from "../src/extensions/governance/AVALocalRuleRevisionPolicy.sol";
import {AVAChallengeExtension} from "../src/extensions/challenge/AVAChallengeExtension.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

/// @notice Used only with vm.etch to check the registry's sealed controller identity.
contract DriftRuleGovernor is IAVARuleGovernance, RuleModuleIdentity {
    address public immutable RULE_PACKAGE_REGISTRY;

    constructor(address registry) {
        RULE_PACKAGE_REGISTRY = registry;
    }
    function validateRuleRevision(bytes32) external pure {}
    function validateGovernanceEnrollment(bytes32, bytes32, uint256) external pure {}

    function forceSupersede(
        AVACoreRulePackageRegistry.PackageRegistrationInput calldata input,
        uint256 previousId,
        AVACoreRulePackageRegistry.ModuleBinding[] calldata bindings
    ) external {
        AVACoreRulePackageRegistry(RULE_PACKAGE_REGISTRY).supersedeRulePackage(input, previousId, bindings);
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return bytes32(uint256(uint160(RULE_PACKAGE_REGISTRY)));
    }
}

contract RuleGovernanceTransitionHook is IAVAPostTransitionHook, RuleModuleIdentity {
    uint256 public calls;

    function onRecognisedStateTransition(TransitionContext calldata) external {
        ++calls;
    }
}

/// @notice Real Core, recognised states, package registry and public challenge lifecycle; no storage overwrites.
contract RuleGovernanceTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("rule.governance.app");
    bytes32 private constant BUSINESS = keccak256("rule.governance.business");
    bytes32 private constant CHALLENGER_SUBJECT = keccak256("rule.governance.challenger");
    address private constant CHALLENGER = address(0xD1);
    address private constant BACKUP_REVISER = address(0xD2);
    bytes32 private constant BACKUP_SUBJECT = keccak256("rule.governance.backup-reviser");
    uint64 private constant DELAY = 5;
    AVARecognisedRuleGovernance private governor;
    AVAChallengeExtension private challenges;
    RuleGovernanceTransitionHook private transitionHook;
    uint256 private businessPackageId;

    function setUp() public {
        _setUpRequestAllocation(
            APP, new M14PermissiveApplicationModule(APP), keccak256("ava.rule-revision.proposal.v1")
        );
        identityRegistry.assignSubject(BACKUP_REVISER, APP, ROLE_ALLOCATOR, BACKUP_SUBJECT, "test:backup");
        AVALocalRuleRevisionPolicy revisionPolicy = _policy(DELAY, true, true, _bootstrapElectorate());
        AVACoreRulePackageRegistry.ModuleBinding[] memory governanceBindings =
            _withRevision(_bindingsFor(requestPackageId), address(revisionPolicy));
        requestPackageId = packageRegistry.supersedeRulePackage(
            _nextInput(REQUEST_WORKFLOW, requestPackageId, "test:governance-bootstrap"),
            requestPackageId,
            governanceBindings
        );
        businessPackageId = packageRegistry.registerRulePackage(
            _corePackageInput(
                APP,
                BUSINESS,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                1,
                keccak256("business.compatibility"),
                "test:business-bootstrap"
            ),
            _coreBindings(new M14PermissiveApplicationModule(APP))
        );
        governor = new AVARecognisedRuleGovernance(kernel, REQUEST_WORKFLOW);
        challenges =
            new AVAChallengeExtension(kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry);
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
        kernel.bindSourceBoundTransitionRequester(businessPackageId, address(challenges));
        kernel.bindTransitionGuard(businessPackageId, address(challenges));
        transitionHook = new RuleGovernanceTransitionHook();
        kernel.bindPostTransitionHook(requestPackageId, address(transitionHook));
        packageRegistry.sealGovernance(APP, REQUEST_WORKFLOW, requestPackageId, governor);
        packageRegistry.sealGovernance(APP, BUSINESS, businessPackageId, governor);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, governor.ACTION_PROPOSE_RULE_REVISION(), true);
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, governor.ACTION_REVISE_RULE(), true);
        identityRegistry.assignSubject(CHALLENGER, APP, ROLE_SOURCE, CHALLENGER_SUBJECT, "test:challenger");
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FORM_RECOGNISED_STATE, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FILE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_SCREEN_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_RESOLVE_CHALLENGE, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_APPLY_RESTORATION, true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, AVACoreTypes.ACTION_CLOSE_CHALLENGE, true);
    }

    function testRecognisedProposalRatifiesAndActivatesExactSealedTargetOnce() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:business-v2");
        AVARecognisedRuleGovernance.ProposalRecord memory proposal = governor.getProposal(id);
        require(proposal.ratificationId == 0 && proposal.activationId == 0, "recognition activated rules");
        require(packageRegistry.getActivePackageId(APP, BUSINESS) == businessPackageId, "proposal moved pointer");
        bytes32 controllerIdentity = governor.moduleIdentityHash();
        uint256 replacement = _execute(id, next, bindings);
        proposal = governor.getProposal(id);
        AVARecognisedRuleGovernance.RatificationRecord memory ratification =
            governor.getRatification(proposal.ratificationId);
        AVARecognisedRuleGovernance.ActivationRecord memory activation = governor.getActivation(proposal.activationId);
        require(
            ratification.proposalId == id && activation.ratificationId == ratification.id, "decision/effect conflated"
        );
        require(
            activation.previousPackageId == businessPackageId && activation.replacementPackageId == replacement,
            "wrong effect"
        );
        require(
            activation.sourceTransitionId == proposal.sourceTransitionId && activation.actor == ALLOCATOR_ACTOR,
            "receipt provenance"
        );
        require(packageRegistry.getActivePackageId(APP, BUSINESS) == replacement, "activation missing");
        require(packageRegistry.getRulePackageById(businessPackageId).version == 1, "old package rewritten");
        require(governor.moduleIdentityHash() == controllerIdentity, "records drift controller identity");
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testSelfGovernanceUsesOldPolicyAndRetainsRecognisedSource() public {
        uint256 old = requestPackageId;
        address nextPolicy = address(_policy(0, false, false, _bootstrapElectorate()));
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _withRevision(_bindingsFor(old), nextPolicy);
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(REQUEST_WORKFLOW, old, "test:governance-next");
        uint256 id = _recogniseAndRegister(next, bindings, old, 0);
        uint256 replacement = _execute(id, next, bindings);
        require(packageRegistry.getActivePackageId(APP, REQUEST_WORKFLOW) == replacement, "self governance failed");
        require(
            packageRegistry.getModule(replacement, AVACapabilityKeys.RULE_REVISION) == nextPolicy, "new policy missing"
        );
        require(
            kernel.getRecognisedStateReference(governor.getProposal(id).sourceStateId).packageId == old,
            "source history relabelled"
        );
        require(
            governor.getActivation(governor.getProposal(id).activationId).governancePackageId == old,
            "new policy self authorised"
        );
    }

    function testRootAndRegistrarCannotExecuteOrSupersedeAfterSeal() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:root-denied");
        requestVm.expectRevert();
        packageRegistry.supersedeRulePackage(next, businessPackageId, bindings);
        _expectExecutionFailure(id, next, bindings, address(this), ROLE_PACKAGE, _authority(ROLE_PACKAGE));
        require(governor.getProposal(id).ratificationId == 0, "failed decision recorded");
    }

    function testSealedControllerCannotBeReplaced() public {
        AVARecognisedRuleGovernance replacement = new AVARecognisedRuleGovernance(kernel, REQUEST_WORKFLOW);
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, BUSINESS, businessPackageId, replacement);
        require(packageRegistry.governanceController(APP, BUSINESS) == address(governor), "seal replaced");
    }

    function testBusinessSealRejectsDifferentControllerThenAllowsGovernedRevision() public {
        bytes32 workflow = keccak256("rule.governance.controller-mismatch");
        uint256 packageId = _registerUnsealedBusiness(workflow);
        kernel.bindSourceBoundTransitionRequester(packageId, address(challenges));
        kernel.bindTransitionGuard(packageId, address(challenges));
        AVARecognisedRuleGovernance other = new AVARecognisedRuleGovernance(kernel, REQUEST_WORKFLOW);
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, other);
        AVACoreRulePackageRegistry.GovernanceBinding memory binding =
            packageRegistry.getGovernanceBinding(APP, workflow);
        require(
            binding.controller == address(0) && binding.identityHash == bytes32(0) && binding.bootstrapPackageId == 0,
            "failed seal persisted"
        );
        require(packageRegistry.getActivePackageId(APP, workflow) == packageId, "bootstrap changed");
        packageRegistry.sealGovernance(APP, workflow, packageId, governor);
        require(packageRegistry.governanceController(APP, workflow) == address(governor), "correct seal failed");

        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(workflow, packageId, "test:enrolled-v2");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(packageId);
        uint256 proposalId = _recogniseAndRegister(next, bindings, packageId, 0);
        uint256 replacement = _execute(proposalId, next, bindings);
        AVARecognisedRuleGovernance.ProposalRecord memory proposal = governor.getProposal(proposalId);
        require(governor.getRatification(proposal.ratificationId).proposalId == proposalId, "ratification missing");
        require(governor.getActivation(proposal.activationId).replacementPackageId == replacement, "activation missing");
        require(packageRegistry.getActivePackageId(APP, workflow) == replacement, "new package missing");
        require(packageRegistry.getRulePackageById(packageId).version == 1, "original package changed");
    }

    function testBusinessSealWaitsForGoverningBootstrapWithoutStrandingTarget() public {
        bytes32 governingWorkflow = keccak256("rule.governance.new-bootstrap");
        AVALocalRuleRevisionPolicy policy = new AVALocalRuleRevisionPolicy(
            identityRegistry, APP, governingWorkflow, DELAY, true, true, _bootstrapElectorate()
        );
        uint256 governingPackage = packageRegistry.registerRulePackage(
            _corePackageInput(
                APP,
                governingWorkflow,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                1,
                keccak256("new.governance.compatibility"),
                "test:new-governance"
            ),
            _withRevision(_bindingsFor(requestPackageId), address(policy))
        );
        kernel.bindSourceBoundTransitionRequester(governingPackage, address(challenges));
        kernel.bindTransitionGuard(governingPackage, address(challenges));
        AVARecognisedRuleGovernance controller = new AVARecognisedRuleGovernance(kernel, governingWorkflow);
        bytes32 workflow = keccak256("rule.governance.awaiting-bootstrap");
        uint256 packageId = _registerUnsealedBusiness(workflow);
        kernel.bindSourceBoundTransitionRequester(packageId, address(challenges));
        kernel.bindTransitionGuard(packageId, address(challenges));

        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, controller);
        require(packageRegistry.governanceController(APP, workflow) == address(0), "premature seal persisted");
        require(packageRegistry.getActivePackageId(APP, workflow) == packageId, "target changed");
        packageRegistry.sealGovernance(APP, governingWorkflow, governingPackage, controller);
        packageRegistry.sealGovernance(APP, workflow, packageId, controller);
        require(packageRegistry.governanceController(APP, governingWorkflow) == address(controller), "bootstrap failed");
        require(packageRegistry.governanceController(APP, workflow) == address(controller), "target stranded");
    }

    function testCallbackCannotBeCalledOutsideAtomicAuthorisedExecution() public {
        requestVm.expectRevert();
        governor.validateRuleRevision(keccak256("forged"));
        requestVm.prank(address(packageRegistry));
        requestVm.expectRevert();
        governor.validateRuleRevision(keccak256("forged"));
    }

    function testParallelProposalWithStaleTargetPredecessorCannotActivate() public {
        (
            uint256 first,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:first");
        (
            uint256 second,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory stale,
            AVACoreRulePackageRegistry.ModuleBinding[] memory staleBindings
        ) = _businessProposal("test:parallel");
        uint256 replacement = _execute(first, next, bindings);
        _expectExecutionFailure(
            second, stale, staleBindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)
        );
        require(packageRegistry.getActivePackageId(APP, BUSINESS) == replacement, "stale overwrite");
    }

    function testGovernanceReplacementStalesUnexecutedProposal() public {
        (
            uint256 staleId,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory stale,
            AVACoreRulePackageRegistry.ModuleBinding[] memory staleBindings
        ) = _businessProposal("test:before-governance-revision");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(requestPackageId);
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(REQUEST_WORKFLOW, requestPackageId, "test:next-governance");
        uint256 id = _recogniseAndRegister(next, bindings, requestPackageId, 0);
        _execute(id, next, bindings);
        _expectExecutionFailure(
            staleId, stale, staleBindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR)
        );
        require(governor.getProposal(staleId).activationId == 0, "stale source applied");
    }

    function testProvisionalSourceIsNotAnEligibleProposal() public {
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:provisional");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        bytes32 commitment = packageRegistry.revisionCommitment(next, businessPackageId, bindings);
        uint256 state = _customSource(
            commitment,
            commitment,
            governor.RULE_REVISION_OBJECT(),
            REQUEST_WORKFLOW,
            requestPackageId,
            AVACoreTypes.Stage.Verification,
            false
        );
        _expectRegistrationFailure(state, next, bindings);
    }

    function testWrongStageCannotUseVestedStateAsProposal() public {
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:attribution");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        bytes32 commitment = packageRegistry.revisionCommitment(next, businessPackageId, bindings);
        uint256 state = _customSource(
            commitment,
            commitment,
            governor.RULE_REVISION_OBJECT(),
            REQUEST_WORKFLOW,
            requestPackageId,
            AVACoreTypes.Stage.Attribution,
            true
        );
        _expectRegistrationFailure(state, next, bindings);
    }

    function testWrongObjectTypeRejected() public {
        _invalidSourceObject(0);
    }

    function testWrongObjectCommitmentRejected() public {
        _invalidSourceObject(1);
    }

    function testWrongMetadataHashRejected() public {
        _invalidSourceObject(2);
    }

    function testWrongGovernanceWorkflowRejected() public {
        _invalidSourceObject(3);
    }

    function testBorrowedVestedProposalCannotBeRegisteredByAnotherSubject() public {
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:borrowed");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        uint256 state = _createStateForCommitment(packageRegistry.revisionCommitment(next, businessPackageId, bindings));
        AVARecognisedRuleGovernance.ProposalInput memory input = _proposalInput(state, businessPackageId, 0);
        requestVm.prank(CHALLENGER);
        requestVm.expectRevert();
        governor.registerProposal(input, next, bindings, ROLE_SOURCE, CHALLENGER_SUBJECT);
    }

    function testSourceSubjectReplacementCannotResurrectProposal() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:subject-replaced");
        identityRegistry.deactivateSubject(_authority(ROLE_SOURCE));
        identityRegistry.assignSubject(
            SOURCE_ACTOR, APP, ROLE_SOURCE, keccak256("replacement.subject"), "test:replacement"
        );
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testRevisionPermissionRevocationBlocksActivation() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:revision-revoked");
        authorityMatrix.setPermission(APP, ROLE_ALLOCATOR, governor.ACTION_REVISE_RULE(), false);
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testProposePermissionRevocationBlocksActivation() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:proposal-revoked");
        authorityMatrix.setPermission(APP, ROLE_SOURCE, governor.ACTION_PROPOSE_RULE_REVISION(), false);
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testInactiveReviserAndWrongCanonicalAuthorityRejected() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:reviser-identity");
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_VERIFIER));
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testOldPolicyDelayCannotBeSkipped() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:delay");
        requestVm.prank(ALLOCATOR_ACTOR);
        requestVm.expectRevert();
        governor.executeProposal(id, next, bindings, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        require(governor.getProposal(id).ratificationId == 0, "early ratification retained");
        _execute(id, next, bindings);
    }

    function testProposedPermissivePolicyCannotAuthoriseItself() public {
        address permissive = address(_policy(0, false, false, _bootstrapElectorate()));
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _withRevision(_bindingsFor(requestPackageId), permissive);
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(REQUEST_WORKFLOW, requestPackageId, "test:permissive");
        uint256 id = _recogniseAndRegister(next, bindings, requestPackageId, 0);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, governor.ACTION_REVISE_RULE(), true);
        authorityMatrix.setPermission(APP, ROLE_VERIFIER, governor.ACTION_REVISE_RULE(), true);
        _expectExecutionFailure(id, next, bindings, SOURCE_ACTOR, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _expectExecutionFailure(id, next, bindings, VERIFIER_ACTOR, ROLE_VERIFIER, _authority(ROLE_VERIFIER));
        _execute(id, next, bindings);
    }

    function testGrantFirstCannotAddExistingRegistrarToSealedElectorate() public {
        authorityMatrix.setPermission(APP, ROLE_PACKAGE, governor.ACTION_REVISE_RULE(), true);
        require(
            authorityMatrix.isAuthorised(address(this), APP, ROLE_PACKAGE, governor.ACTION_REVISE_RULE()),
            "grant missing"
        );
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:grant-first");
        _expectExecutionFailure(id, next, bindings, address(this), ROLE_PACKAGE, _authority(ROLE_PACKAGE));
        require(governor.getProposal(id).activationId == 0, "registrar enlarged electorate");
    }

    function testFreshSubjectAndExtraRoleCannotJoinSealedElectorate() public {
        bytes32 extraRole = keccak256("root.fresh.reviser.role");
        bytes32 freshSubject = keccak256("root.fresh.reviser.subject");
        identityRegistry.assignSubject(address(this), APP, extraRole, freshSubject, "test:fresh-root");
        authorityMatrix.setPermission(APP, extraRole, governor.ACTION_REVISE_RULE(), true);
        require(
            authorityMatrix.isAuthorised(address(this), APP, extraRole, governor.ACTION_REVISE_RULE()),
            "fresh grant missing"
        );
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:extra-role");
        _expectExecutionFailure(id, next, bindings, address(this), extraRole, freshSubject);
    }

    function testFreshCanonicalSubjectAtSameAddressIsOutsideOldElectorate() public {
        bytes32 replacementSubject = keccak256("allocator.replacement.subject");
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, replacementSubject, "test:replacement");
        require(
            authorityMatrix.isAuthorised(ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, governor.ACTION_REVISE_RULE()),
            "current authority missing"
        );
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:replaced-reviser-subject");
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, replacementSubject);
    }

    function testSurvivingDeclaredReviserCanGovernElectorateRotationAndRecovery() public {
        bytes32 replacementSubject = keccak256("allocator.governed.replacement");
        identityRegistry.deactivateSubject(_authority(ROLE_ALLOCATOR));
        identityRegistry.assignSubject(ALLOCATOR_ACTOR, APP, ROLE_ALLOCATOR, replacementSubject, "test:replacement");
        bytes32[] memory electorate = new bytes32[](2);
        electorate[0] = replacementSubject;
        electorate[1] = BACKUP_SUBJECT;
        AVALocalRuleRevisionPolicy replacementPolicy = _policy(DELAY, true, true, electorate);
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _withRevision(_bindingsFor(requestPackageId), address(replacementPolicy));
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(REQUEST_WORKFLOW, requestPackageId, "test:governed-electorate-rotation");
        uint256 rotation = _recogniseAndRegister(next, bindings, requestPackageId, 0);
        _expectExecutionFailure(rotation, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, replacementSubject);
        requestPackageId = _executeAs(rotation, next, bindings, BACKUP_REVISER, ROLE_ALLOCATOR, BACKUP_SUBJECT);
        require(replacementPolicy.isAllowedSubject(replacementSubject), "new electorate missing");
        require(!replacementPolicy.isAllowedSubject(_authority(ROLE_ALLOCATOR)), "old identity silently retained");
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory businessNext,
            AVACoreRulePackageRegistry.ModuleBinding[] memory businessBindings
        ) = _businessProposal("test:recovered-v2");
        uint256 applied =
            _executeAs(id, businessNext, businessBindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, replacementSubject);
        require(packageRegistry.getActivePackageId(APP, BUSINESS) == applied, "new electorate cannot act");
    }

    function testLocalElectorateConstructorRejectsEmptyDuplicateInactiveMissingAndOversizedRosters() public {
        bytes32[] memory roster = new bytes32[](0);
        requestVm.expectRevert();
        new AVALocalRuleRevisionPolicy(identityRegistry, APP, REQUEST_WORKFLOW, DELAY, true, true, roster);
        roster = new bytes32[](2);
        roster[0] = BACKUP_SUBJECT;
        roster[1] = BACKUP_SUBJECT;
        requestVm.expectRevert();
        new AVALocalRuleRevisionPolicy(identityRegistry, APP, REQUEST_WORKFLOW, DELAY, true, true, roster);
        roster = new bytes32[](1);
        roster[0] = keccak256("missing.subject");
        requestVm.expectRevert();
        new AVALocalRuleRevisionPolicy(identityRegistry, APP, REQUEST_WORKFLOW, DELAY, true, true, roster);
        roster[0] = BACKUP_SUBJECT;
        identityRegistry.deactivateSubject(BACKUP_SUBJECT);
        requestVm.expectRevert();
        new AVALocalRuleRevisionPolicy(identityRegistry, APP, REQUEST_WORKFLOW, DELAY, true, true, roster);
        roster = new bytes32[](33);
        requestVm.expectRevert();
        new AVALocalRuleRevisionPolicy(identityRegistry, APP, REQUEST_WORKFLOW, DELAY, true, true, roster);
    }

    function testSelfUpgradeInheritsCorrectionBindingsBeforeFirstNewStateAndSupportsFreshCorrectiveVersion() public {
        uint256 originalGovernancePackage = requestPackageId;
        AVACoreRulePackageRegistry.ModuleBinding[] memory governanceBindings = _bindingsFor(requestPackageId);
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(REQUEST_WORKFLOW, requestPackageId, "test:upgrade-with-correction");
        uint256 upgrade = _recogniseAndRegister(next, governanceBindings, requestPackageId, 0);
        requestPackageId = _execute(upgrade, next, governanceBindings);
        require(!kernel.recognisedStateUseStartedByPackage(requestPackageId), "new package already used");
        require(
            kernel.sourceBoundTransitionRequesterByPackage(requestPackageId) == address(challenges),
            "requester not inherited"
        );
        require(
            address(kernel.transitionGuardByPackage(requestPackageId)) == address(challenges), "guard not inherited"
        );
        require(
            address(kernel.postTransitionHookByPackage(requestPackageId)) == address(transitionHook),
            "hook not inherited"
        );
        require(
            kernel.transitionGuardIdentityByPackage(requestPackageId)
                == kernel.transitionGuardIdentityByPackage(originalGovernancePackage),
            "guard identity changed"
        );
        uint256 firstNewStateId = kernel.nextRecognisedStateId();
        (
            uint256 applied,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory businessNext,
            AVACoreRulePackageRegistry.ModuleBinding[] memory businessBindings
        ) = _businessProposal("test:first-new-package-source");
        uint256 source = governor.getProposal(applied).sourceStateId;
        require(
            source == firstNewStateId && kernel.getRecognisedStateReference(source).packageId == requestPackageId,
            "not first new-package state"
        );
        uint256 appliedPackage = _execute(applied, businessNext, businessBindings);
        _correctSource(source);
        AVAChallengeExtension.ChallengeRecord memory challenge =
            challenges.getChallenge(challenges.nextChallengeId() - 1);
        require(
            challenge.status == AVAChallengeExtension.ChallengeStatus.Resolved
                && challenge.outcome == AVAChallengeExtension.ChallengeOutcome.Upheld,
            "public correction missing"
        );
        require(
            challenge.packageId == requestPackageId && challenge.targetPackageId == requestPackageId,
            "new source history wrong"
        );
        businessNext = _nextInput(BUSINESS, appliedPackage, "test:new-package-corrective-v3");
        uint256 correction = _recogniseAndRegister(businessNext, businessBindings, appliedPackage, applied);
        uint256 corrected = _execute(correction, businessNext, businessBindings);
        require(packageRegistry.getRulePackageById(corrected).version == 3, "fresh correction failed");
        require(
            governor.getActivation(governor.getProposal(applied).activationId).replacementPackageId == appliedPackage,
            "old effect rewritten"
        );
        require(transitionHook.calls() > 0, "inherited post hook unused");
    }

    function testSelfGovernanceCannotOmitRevisionCapabilityAndLeavesPointerAndReceiptsUnchanged() public {
        AVACoreRulePackageRegistry.ModuleBinding[] memory complete = _bindingsFor(requestPackageId);
        AVACoreRulePackageRegistry.ModuleBinding[] memory missing =
            new AVACoreRulePackageRegistry.ModuleBinding[](complete.length - 1);
        for (uint256 i; i < missing.length; ++i) {
            missing[i] = complete[i];
        }
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(REQUEST_WORKFLOW, requestPackageId, "test:missing-revision");
        uint256 state = _createStateForCommitment(packageRegistry.revisionCommitment(next, requestPackageId, missing));
        AVARecognisedRuleGovernance.ProposalInput memory input = _proposalInput(state, requestPackageId, 0);
        uint256 nextProposalId = governor.nextProposalId();
        uint256 nextRatificationId = governor.nextRatificationId();
        uint256 nextActivationId = governor.nextActivationId();
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        governor.registerProposal(input, next, missing, ROLE_SOURCE, _authority(ROLE_SOURCE));
        require(
            packageRegistry.getActivePackageId(APP, REQUEST_WORKFLOW) == requestPackageId, "missing policy activated"
        );
        require(
            governor.nextProposalId() == nextProposalId && governor.nextRatificationId() == nextRatificationId
                && governor.nextActivationId() == nextActivationId,
            "failed proposal left receipts"
        );
        next.uri = "test:complete-revision";
        uint256 id = _recogniseAndRegister(next, complete, requestPackageId, 0);
        _expectExecutionFailure(id, next, missing, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        require(
            governor.getProposal(id).ratificationId == 0 && governor.getProposal(id).activationId == 0,
            "failed execution left receipts"
        );
    }

    function testRootCannotChangeSealedKernelWiringBeforeFirstState() public {
        require(!kernel.recognisedStateUseStartedByPackage(businessPackageId), "business already used");
        requestVm.expectRevert();
        kernel.bindSourceBoundTransitionRequester(businessPackageId, address(challenges));
        requestVm.expectRevert();
        kernel.bindTransitionGuard(businessPackageId, address(challenges));
        requestVm.expectRevert();
        kernel.bindPostTransitionHook(businessPackageId, address(transitionHook));
        require(
            kernel.sourceBoundTransitionRequesterByPackage(businessPackageId) == address(challenges),
            "root rewired requester"
        );
        require(
            address(kernel.transitionGuardByPackage(businessPackageId)) == address(challenges), "root rewired guard"
        );
        require(address(kernel.postTransitionHookByPackage(businessPackageId)) == address(0), "root rewired hook");
    }

    function testBusinessSealRequiresCorrectionRequesterAndMatchingGuardAtomically() public {
        bytes32 workflow = keccak256("rule.governance.unwired-business");
        uint256 packageId = _registerUnsealedBusiness(workflow);
        uint256 nextPackageId = packageRegistry.nextPackageId();
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, governor);
        require(packageRegistry.governanceController(APP, workflow) == address(0), "unbound business sealed");
        kernel.bindSourceBoundTransitionRequester(packageId, address(challenges));
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, governor);
        require(packageRegistry.governanceController(APP, workflow) == address(0), "partial business sealed");
        require(
            packageRegistry.getActivePackageId(APP, workflow) == packageId
                && packageRegistry.nextPackageId() == nextPackageId,
            "failed seal changed packages"
        );
        require(
            kernel.sourceBoundTransitionRequesterByPackage(packageId) == address(challenges)
                && address(kernel.transitionGuardByPackage(packageId)) == address(0),
            "failed seal changed bindings"
        );
        kernel.bindTransitionGuard(packageId, address(challenges));
        packageRegistry.sealGovernance(APP, workflow, packageId, governor);
        require(packageRegistry.governanceController(APP, workflow) == address(governor), "complete business rejected");
        requestVm.expectRevert();
        kernel.bindPostTransitionHook(packageId, address(transitionHook));
    }

    function testBusinessSealRejectsMismatchedCorrectionRequesterAndGuard() public {
        bytes32 workflow = keccak256("rule.governance.mismatched-business");
        uint256 packageId = _registerUnsealedBusiness(workflow);
        AVAChallengeExtension other =
            new AVAChallengeExtension(kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry);
        kernel.bindSourceBoundTransitionRequester(packageId, address(challenges));
        kernel.bindTransitionGuard(packageId, address(other));
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, governor);
        require(packageRegistry.governanceController(APP, workflow) == address(0), "mismatched business sealed");
    }

    function testBusinessSealRejectsCorrectionBindingIdentityDrift() public {
        bytes32 workflow = keccak256("rule.governance.drifted-business");
        uint256 packageId = _registerUnsealedBusiness(workflow);
        AVAChallengeExtension other =
            new AVAChallengeExtension(kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry);
        kernel.bindSourceBoundTransitionRequester(packageId, address(other));
        kernel.bindTransitionGuard(packageId, address(other));
        requestVm.etch(address(other), hex"60006000f3");
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, governor);
        require(packageRegistry.governanceController(APP, workflow) == address(0), "drifted business sealed");
    }

    function testBusinessUpgradeFirstStateSupportsPublicChallengeAndCorrectionWithInheritedBindings() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:business-correctable-v2");
        uint256 replacement = _execute(id, next, bindings);
        require(!kernel.recognisedStateUseStartedByPackage(replacement), "replacement already used");
        require(kernel.governedBindingsInheritedFrom(replacement) == businessPackageId, "wrong binding predecessor");
        require(
            kernel.sourceBoundTransitionRequesterByPackage(replacement) == address(challenges)
                && address(kernel.transitionGuardByPackage(replacement)) == address(challenges),
            "business correction bindings missing"
        );
        require(
            kernel.sourceBoundTransitionRequesterIdentityByPackage(replacement)
                    == kernel.sourceBoundTransitionRequesterIdentityByPackage(businessPackageId)
                && kernel.transitionGuardIdentityByPackage(replacement)
                    == kernel.transitionGuardIdentityByPackage(businessPackageId),
            "business binding identities changed"
        );
        uint256 firstStateId = kernel.nextRecognisedStateId();
        uint256 state = _customSource(
            keccak256("business.object"),
            keccak256("business.metadata"),
            keccak256("business.object.type"),
            BUSINESS,
            replacement,
            AVACoreTypes.Stage.Verification,
            true
        );
        require(state == firstStateId, "not first business state");
        _correctSource(state);
        AVAChallengeExtension.ChallengeRecord memory challenge =
            challenges.getChallenge(challenges.nextChallengeId() - 1);
        require(
            challenge.status == AVAChallengeExtension.ChallengeStatus.Resolved
                && challenge.outcome == AVAChallengeExtension.ChallengeOutcome.Upheld,
            "business public correction failed"
        );
        require(
            challenge.workflowKey == BUSINESS && challenge.packageId == replacement
                && challenge.targetPackageId == replacement && challenge.challengedRecognisedStateId == state,
            "wrong business challenge provenance"
        );
        require(
            kernel.getRecognisedStateReference(state).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "business state not corrected"
        );
    }

    function testBootstrapSealRequiresCorrectionRequesterAndGuard() public {
        bytes32 workflow = keccak256("rule.governance.unwired-bootstrap");
        AVALocalRuleRevisionPolicy policy =
            new AVALocalRuleRevisionPolicy(identityRegistry, APP, workflow, DELAY, true, true, _bootstrapElectorate());
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _withRevision(_bindingsFor(requestPackageId), address(policy));
        uint256 packageId = packageRegistry.registerRulePackage(
            _corePackageInput(
                APP,
                workflow,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                1,
                keccak256("unwired.compatibility"),
                "test:unwired"
            ),
            bindings
        );
        AVARecognisedRuleGovernance controller = new AVARecognisedRuleGovernance(kernel, workflow);
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, controller);
        require(packageRegistry.governanceController(APP, workflow) == address(0), "unwired bootstrap sealed");
        kernel.bindSourceBoundTransitionRequester(packageId, address(challenges));
        requestVm.expectRevert();
        packageRegistry.sealGovernance(APP, workflow, packageId, controller);
        kernel.bindTransitionGuard(packageId, address(challenges));
        packageRegistry.sealGovernance(APP, workflow, packageId, controller);
        require(
            packageRegistry.governanceController(APP, workflow) == address(controller), "complete bootstrap rejected"
        );
    }

    function testHookIdentityDriftMakesSelfUpgradeAtomicFailure() public {
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(requestPackageId);
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(REQUEST_WORKFLOW, requestPackageId, "test:drifted-old-hook");
        uint256 id = _recogniseAndRegister(next, bindings, requestPackageId, 0);
        uint256 nextPackageId = packageRegistry.nextPackageId();
        requestVm.etch(address(transitionHook), hex"60006000f3");
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        require(
            packageRegistry.getActivePackageId(APP, REQUEST_WORKFLOW) == requestPackageId
                && packageRegistry.nextPackageId() == nextPackageId,
            "pointer or package escaped rollback"
        );
        require(
            governor.getProposal(id).ratificationId == 0 && governor.getProposal(id).activationId == 0,
            "failed inheritance left receipts"
        );
    }

    function testExactCommitmentRejectsURIAuthRoleVersionCompatibilityAndBindingTampering() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:exact");
        next.uri = "test:tampered";
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        next.uri = "test:exact";
        next.authorityId = _authority(ROLE_VERIFIER);
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        next.authorityId = _authority(ROLE_PACKAGE);
        next.roleKey = ROLE_VERIFIER;
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        next.roleKey = ROLE_PACKAGE;
        next.version = 3;
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        next.version = 2;
        next.compatibilityKey = keccak256("tampered.compatibility");
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        next.compatibilityKey = keccak256("business.compatibility");
        AVACoreRulePackageRegistry.ModuleBinding memory saved = bindings[1];
        bindings[1] = bindings[2];
        bindings[2] = saved;
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
        saved = bindings[1];
        bindings[1] = bindings[2];
        bindings[2] = saved;
        _execute(id, next, bindings);
    }

    function testProposedModuleIdentityDriftRejectsActivation() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:module-drift");
        requestVm.etch(address(bindings[0].module), hex"60006000f3");
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testSealedControllerIdentityDriftCannotBypassRegistry() public {
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:controller-drift");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        DriftRuleGovernor drift = new DriftRuleGovernor(address(packageRegistry));
        requestVm.etch(address(governor), address(drift).code);
        requestVm.expectRevert();
        DriftRuleGovernor(address(governor)).forceSupersede(next, businessPackageId, bindings);
        require(packageRegistry.getActivePackageId(APP, BUSINESS) == businessPackageId, "drift bypassed seal");
    }

    function testRevokedSourceEvidenceBlocksActivation() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:evidence-revoked");
        uint256 evidence = kernel.getRecognisedStateReference(governor.getProposal(id).sourceStateId).evidenceReceiptId;
        requestVm.prank(SOURCE_ACTOR);
        evidenceRegistry.recordEvidenceLifecycle(
            evidence,
            ROLE_SOURCE,
            _authority(ROLE_SOURCE),
            AVACoreTypes.EvidenceLifecycleKind.Revoke,
            0,
            keccak256("revoke"),
            "test:revoke"
        );
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testCorrectedDeclaredDependencyBlocksProposalRegistration() public {
        uint256 ancestor = _createStateForCommitment(keccak256("test:registration-ancestor"));
        AVACoreTypes.SourceOccurrence[] memory dependencies = new AVACoreTypes.SourceOccurrence[](1);
        dependencies[0] =
            AVACoreTypes.SourceOccurrence(ancestor, kernel.getRecognisedStateReference(ancestor).lastTransitionId);
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:dependent-registration");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        bytes32 commitment = packageRegistry.revisionCommitment(next, businessPackageId, bindings);
        uint256 state = _customSource(
            commitment,
            commitment,
            governor.RULE_REVISION_OBJECT(),
            REQUEST_WORKFLOW,
            requestPackageId,
            AVACoreTypes.Stage.Verification,
            true,
            dependencies
        );
        uint256 object = kernel.getRecognisedStateReference(state).governedObjectId;
        require(kernel.DEPENDENCIES().dependenciesCurrent(object), "dependency not initially current");
        AVARecognisedRuleGovernance.ProposalInput memory input = _proposalInput(state, businessPackageId, 0);
        _correctSource(ancestor);
        require(!kernel.DEPENDENCIES().dependenciesCurrent(object), "corrected dependency still current");
        require(
            kernel.getRecognisedStateReference(state).status == AVACoreTypes.RecognisedStateStatus.Vested,
            "dependent recognition mutated"
        );
        uint256 nextProposal = governor.nextProposalId();
        requestVm.prank(SOURCE_ACTOR);
        (bool registered, bytes memory reason) = address(governor)
            .call(
                abi.encodeCall(governor.registerProposal, (input, next, bindings, ROLE_SOURCE, _authority(ROLE_SOURCE)))
            );
        require(!registered, "corrected declared dependency registered");
        require(
            keccak256(reason) == keccak256(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, object)),
            "wrong dependency rejection"
        );
        require(governor.nextProposalId() == nextProposal, "failed registration consumed id");
        require(governor.proposalIdBySourceState(state) == 0, "ineligible proposal recorded");
    }

    function testCorrectedDeclaredDependencyAfterRegistrationBlocksExecution() public {
        uint256 ancestor = _createStateForCommitment(keccak256("test:execution-ancestor"));
        AVACoreTypes.SourceOccurrence[] memory dependencies = new AVACoreTypes.SourceOccurrence[](1);
        dependencies[0] =
            AVACoreTypes.SourceOccurrence(ancestor, kernel.getRecognisedStateReference(ancestor).lastTransitionId);
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:dependent-execution");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        bytes32 commitment = packageRegistry.revisionCommitment(next, businessPackageId, bindings);
        uint256 state = _customSource(
            commitment,
            commitment,
            governor.RULE_REVISION_OBJECT(),
            REQUEST_WORKFLOW,
            requestPackageId,
            AVACoreTypes.Stage.Verification,
            true,
            dependencies
        );
        AVARecognisedRuleGovernance.ProposalInput memory input = _proposalInput(state, businessPackageId, 0);
        requestVm.prank(SOURCE_ACTOR);
        uint256 id = governor.registerProposal(input, next, bindings, ROLE_SOURCE, _authority(ROLE_SOURCE));
        _correctSource(ancestor);
        uint256 object = kernel.getRecognisedStateReference(state).governedObjectId;
        require(
            kernel.getRecognisedStateReference(state).status == AVACoreTypes.RecognisedStateStatus.Vested,
            "dependent recognition mutated"
        );
        _waitDelay(id);
        uint256 nextPackage = packageRegistry.nextPackageId();
        requestVm.prank(ALLOCATOR_ACTOR);
        (bool executed, bytes memory reason) = address(governor)
            .call(
                abi.encodeCall(
                    governor.executeProposal, (id, next, bindings, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR))
                )
            );
        require(!executed, "corrected declared dependency activated rules");
        require(
            keccak256(reason) == keccak256(abi.encodeWithSelector(AVACoreTypes.InvalidState.selector, object)),
            "wrong dependency rejection"
        );
        AVARecognisedRuleGovernance.ProposalRecord memory proposal = governor.getProposal(id);
        require(proposal.ratificationId == 0 && proposal.activationId == 0, "failed execution left receipts");
        require(
            proposal.sourceStateId == state && proposal.sourceTransitionId == input.expectedSourceTransitionId,
            "proposal occurrence rewritten"
        );
        require(
            packageRegistry.getActivePackageId(APP, BUSINESS) == businessPackageId
                && packageRegistry.nextPackageId() == nextPackage,
            "failed execution changed packages"
        );
        AVACoreTypes.SourceOccurrence[] memory retained = kernel.DEPENDENCIES().getDependencies(object);
        require(
            retained.length == 1 && retained[0].recognisedStateId == dependencies[0].recognisedStateId
                && retained[0].transitionId == dependencies[0].transitionId,
            "declared occurrence changed"
        );
    }

    function testSourceCorrectionBeforeExecutionBlocksOldProposal() public {
        (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:source-corrected");
        uint256 state = governor.getProposal(id).sourceStateId;
        _correctSource(state);
        require(
            kernel.getRecognisedStateReference(state).status == AVACoreTypes.RecognisedStateStatus.Voided,
            "source not corrected"
        );
        _expectExecutionFailure(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function testAppliedHistorySurvivesSourceCorrectionAndFreshLinkedCorrectiveVersion() public {
        (
            uint256 first,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        ) = _businessProposal("test:applied-v2");
        uint256 appliedPackage = _execute(first, next, bindings);
        AVARecognisedRuleGovernance.ProposalRecord memory original = governor.getProposal(first);
        AVARecognisedRuleGovernance.ActivationRecord memory receipt = governor.getActivation(original.activationId);
        _correctSource(original.sourceStateId);
        require(packageRegistry.getActivePackageId(APP, BUSINESS) == appliedPackage, "source correction rewound effect");
        require(
            governor.getActivation(original.activationId).replacementPackageId == receipt.replacementPackageId,
            "receipt rewritten"
        );
        require(
            kernel.getRecognisedStateReference(original.sourceStateId).packageId == original.governancePackageId,
            "historical source package lost"
        );
        next = _nextInput(BUSINESS, appliedPackage, "test:corrective-v3");
        uint256 corrective = _recogniseAndRegister(next, bindings, appliedPackage, first);
        uint256 replacement = _execute(corrective, next, bindings);
        AVARecognisedRuleGovernance.ActivationRecord memory correction =
            governor.getActivation(governor.getProposal(corrective).activationId);
        require(correction.correctionOfAppliedProposal == first, "correction lineage missing");
        require(
            correction.previousPackageId == appliedPackage && replacement != appliedPackage, "correction was rewind"
        );
        require(
            packageRegistry.getRulePackageById(replacement).version == 3
                && packageRegistry.getRulePackageById(appliedPackage).version == 2,
            "history replaced"
        );
    }

    function testAcceptedUnresolvedSourceChallengeRetainsOriginalPackageHistory() public {
        (uint256 id,,) = _businessProposal("test:unresolved-source");
        AVARecognisedRuleGovernance.ProposalRecord memory proposal = governor.getProposal(id);
        uint256 challenge = _fileSourceChallenge(proposal.sourceStateId);
        requestVm.prank(VERIFIER_ACTOR);
        challenges.screenChallenge(challenge, ROLE_VERIFIER, _authority(ROLE_VERIFIER));
        AVAChallengeExtension.ChallengeRecord memory record = challenges.getChallenge(challenge);
        require(record.status == AVAChallengeExtension.ChallengeStatus.AdmissibilityScreening, "not accepted");
        require(
            record.targetPackageId == proposal.governancePackageId && record.packageId == requestPackageId,
            "package history lost"
        );
        require(
            record.outcome == AVAChallengeExtension.ChallengeOutcome.None
                && record.targetTransitionIdAtFiling == proposal.sourceTransitionId,
            "invented resolution"
        );
    }

    function testCorrectionLinkMustNameAnAppliedProposalAndBeCommitted() public {
        (uint256 first,,) = _businessProposal("test:unapplied");
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:invalid-correction");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        bytes32 revision = packageRegistry.revisionCommitment(next, businessPackageId, bindings);
        uint256 state = _createStateForCommitment(governor.proposalCommitmentFor(revision, first));
        AVARecognisedRuleGovernance.ProposalInput memory input = _proposalInput(state, businessPackageId, first);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        governor.registerProposal(input, next, bindings, ROLE_SOURCE, _authority(ROLE_SOURCE));
        input.correctionOfAppliedProposal = 0;
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        governor.registerProposal(input, next, bindings, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _businessProposal(string memory uri)
        private
        returns (
            uint256 id,
            AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
            AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
        )
    {
        next = _nextInput(BUSINESS, businessPackageId, uri);
        bindings = _bindingsFor(businessPackageId);
        id = _recogniseAndRegister(next, bindings, businessPackageId, 0);
    }

    function _registerUnsealedBusiness(bytes32 workflow) private returns (uint256) {
        return packageRegistry.registerRulePackage(
            _corePackageInput(
                APP,
                workflow,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                1,
                keccak256("business.compatibility"),
                "test:business"
            ),
            _bindingsFor(businessPackageId)
        );
    }

    function _recogniseAndRegister(
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings,
        uint256 previous,
        uint256 correction
    ) private returns (uint256) {
        bytes32 revision = packageRegistry.revisionCommitment(next, previous, bindings);
        uint256 state = _createStateForCommitment(governor.proposalCommitmentFor(revision, correction));
        AVARecognisedRuleGovernance.ProposalInput memory input = _proposalInput(state, previous, correction);
        requestVm.prank(SOURCE_ACTOR);
        return governor.registerProposal(input, next, bindings, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _proposalInput(uint256 state, uint256 previous, uint256 correction)
        private
        view
        returns (AVARecognisedRuleGovernance.ProposalInput memory)
    {
        return AVARecognisedRuleGovernance.ProposalInput(
            state, kernel.getRecognisedStateReference(state).lastTransitionId, previous, correction
        );
    }

    function _execute(
        uint256 id,
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
    ) private returns (uint256) {
        return _executeAs(id, next, bindings, ALLOCATOR_ACTOR, ROLE_ALLOCATOR, _authority(ROLE_ALLOCATOR));
    }

    function _executeAs(
        uint256 id,
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings,
        address actor,
        bytes32 role,
        bytes32 authority
    ) private returns (uint256) {
        _waitDelay(id);
        requestVm.prank(actor);
        return governor.executeProposal(id, next, bindings, role, authority);
    }

    function _policy(uint64 delay, bool independentProposer, bool independentRecogniser, bytes32[] memory electorate)
        private
        returns (AVALocalRuleRevisionPolicy)
    {
        return new AVALocalRuleRevisionPolicy(
            identityRegistry, APP, REQUEST_WORKFLOW, delay, independentProposer, independentRecogniser, electorate
        );
    }

    function _bootstrapElectorate() private view returns (bytes32[] memory electorate) {
        electorate = new bytes32[](4);
        electorate[0] = _authority(ROLE_ALLOCATOR);
        electorate[1] = BACKUP_SUBJECT;
        electorate[2] = _authority(ROLE_SOURCE);
        electorate[3] = _authority(ROLE_VERIFIER);
    }

    function _expectExecutionFailure(
        uint256 id,
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings,
        address actor,
        bytes32 role,
        bytes32 authority
    ) private {
        _waitDelay(id);
        requestVm.prank(actor);
        requestVm.expectRevert();
        governor.executeProposal(id, next, bindings, role, authority);
    }

    function _waitDelay(uint256 id) private {
        uint256 ready = uint256(governor.getProposal(id).submittedAt) + DELAY;
        if (block.timestamp < ready) requestVm.warp(ready);
    }

    function _nextInput(bytes32 workflow, uint256 previous, string memory uri)
        private
        view
        returns (AVACoreRulePackageRegistry.PackageRegistrationInput memory)
    {
        AVACoreRulePackageRegistry.RulePackage memory old = packageRegistry.getRulePackageById(previous);
        return _corePackageInput(
            APP, workflow, ROLE_PACKAGE, _authority(ROLE_PACKAGE), old.version + 1, old.compatibilityKey, uri
        );
    }

    function _bindingsFor(uint256 packageId)
        private
        view
        returns (AVACoreRulePackageRegistry.ModuleBinding[] memory result)
    {
        bytes32[] memory keys = packageRegistry.getCapabilityKeys(packageId);
        result = new AVACoreRulePackageRegistry.ModuleBinding[](keys.length);
        for (uint256 i; i < keys.length; ++i) {
            result[i] = _coreBinding(keys[i], packageRegistry.getModule(packageId, keys[i]));
        }
    }

    function _withRevision(AVACoreRulePackageRegistry.ModuleBinding[] memory original, address policy)
        private
        pure
        returns (AVACoreRulePackageRegistry.ModuleBinding[] memory result)
    {
        bool exists = original[original.length - 1].capabilityKey == AVACapabilityKeys.RULE_REVISION;
        result = new AVACoreRulePackageRegistry.ModuleBinding[](original.length + (exists ? 0 : 1));
        for (uint256 i; i < original.length; ++i) {
            result[i] = original[i];
        }
        result[result.length - 1] = _coreBinding(AVACapabilityKeys.RULE_REVISION, policy);
    }

    function _expectRegistrationFailure(
        uint256 state,
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next,
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings
    ) private {
        AVARecognisedRuleGovernance.ProposalInput memory input = _proposalInput(state, businessPackageId, 0);
        requestVm.prank(SOURCE_ACTOR);
        requestVm.expectRevert();
        governor.registerProposal(input, next, bindings, ROLE_SOURCE, _authority(ROLE_SOURCE));
    }

    function _invalidSourceObject(uint256 kind) private {
        AVACoreRulePackageRegistry.PackageRegistrationInput memory next =
            _nextInput(BUSINESS, businessPackageId, "test:invalid-object");
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings = _bindingsFor(businessPackageId);
        bytes32 commitment = packageRegistry.revisionCommitment(next, businessPackageId, bindings);
        uint256 state = _customSource(
            kind == 1 ? keccak256("wrong.commitment") : commitment,
            kind == 2 ? keccak256("wrong.metadata") : commitment,
            kind == 0 ? keccak256("wrong.type") : governor.RULE_REVISION_OBJECT(),
            kind == 3 ? BUSINESS : REQUEST_WORKFLOW,
            kind == 3 ? businessPackageId : requestPackageId,
            AVACoreTypes.Stage.Verification,
            true
        );
        _expectRegistrationFailure(state, next, bindings);
    }

    function _customSource(
        bytes32 commitment,
        bytes32 metadata,
        bytes32 objectType,
        bytes32 workflow,
        uint256 packageId,
        AVACoreTypes.Stage stage,
        bool vest
    ) private returns (uint256 state) {
        return _customSource(
            commitment, metadata, objectType, workflow, packageId, stage, vest, new AVACoreTypes.SourceOccurrence[](0)
        );
    }

    function _customSource(
        bytes32 commitment,
        bytes32 metadata,
        bytes32 objectType,
        bytes32 workflow,
        uint256 packageId,
        AVACoreTypes.Stage stage,
        bool vest,
        AVACoreTypes.SourceOccurrence[] memory dependencies
    ) private returns (uint256 state) {
        uint256 evidence = _sourceEvidence(SOURCE_ACTOR, _authority(ROLE_SOURCE), commitment, workflow, packageId);
        AVAGovernanceKernel.GovernedObjectInput memory objectInput = AVAGovernanceKernel.GovernedObjectInput({
            appId: APP,
            workflowKey: workflow,
            packageId: packageId,
            roleKey: ROLE_SOURCE,
            objectTypeKey: objectType,
            objectCommitment: commitment,
            parentObjectId: 0,
            subjectId: _authority(ROLE_SOURCE),
            evidenceReceiptId: evidence,
            disclosurePolicyId: requestPolicyId,
            metadataHash: metadata,
            authorityId: _authority(ROLE_SOURCE),
            uri: "test:custom-source"
        });
        requestVm.prank(SOURCE_ACTOR);
        uint256 object = dependencies.length == 0
            ? kernel.registerGovernedObject(objectInput)
            : kernel.registerGovernedObjectWithDependencies(objectInput, dependencies);
        requestVm.prank(VERIFIER_ACTOR);
        state = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: object,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                stage: stage,
                status: AVACoreTypes.RecognisedStateStatus.Provisional,
                reasonHash: commitment,
                reasonURI: "test:recognise"
            })
        );
        if (vest) {
            requestVm.prank(VERIFIER_ACTOR);
            kernel.vestRecognisedState(_transitionInput(state, AVACoreTypes.RecognisedStateStatus.Vested));
        }
    }

    function _sourceEvidence(address actor, bytes32 subject, bytes32 seed, bytes32 workflow, uint256 packageId)
        private
        returns (uint256)
    {
        requestVm.prank(actor);
        return evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: workflow,
                packageId: packageId,
                roleKey: ROLE_SOURCE,
                subjectId: subject,
                commitment: keccak256(abi.encode("evidence", seed)),
                evidenceTypeHash: keccak256("rule.governance.support"),
                disclosurePolicyId: requestPolicyId,
                authorityId: subject,
                uri: "test:evidence"
            })
        );
    }

    function _fileSourceChallenge(uint256 target) private returns (uint256 id) {
        bytes32 seed = keccak256(abi.encode("source.challenge", target));
        bytes32 workflow = kernel.getRecognisedStateReference(target).workflowKey;
        uint256 packageId = packageRegistry.getActivePackageId(APP, workflow);
        uint256 evidence = _sourceEvidence(CHALLENGER, CHALLENGER_SUBJECT, seed, workflow, packageId);
        requestVm.startPrank(CHALLENGER);
        uint256 object = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: APP,
                workflowKey: workflow,
                packageId: packageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: keccak256("rule.governance.challenge"),
                objectCommitment: seed,
                parentObjectId: kernel.getRecognisedStateReference(target).governedObjectId,
                subjectId: CHALLENGER_SUBJECT,
                evidenceReceiptId: evidence,
                disclosurePolicyId: requestPolicyId,
                metadataHash: seed,
                authorityId: CHALLENGER_SUBJECT,
                uri: "test:challenge"
            })
        );
        uint256 state = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: object,
                roleKey: ROLE_SOURCE,
                authorityId: CHALLENGER_SUBJECT,
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Registered,
                reasonHash: seed,
                reasonURI: "test:challenge"
            })
        );
        id = challenges.fileChallenge(
            AVAChallengeExtension.ChallengeFilingInput({
                appId: APP,
                workflowKey: workflow,
                packageId: packageId,
                challengeRecognisedStateId: state,
                challengedRecognisedStateId: target,
                roleKey: ROLE_SOURCE,
                reasonHash: seed,
                reasonURI: "test:challenge"
            })
        );
        requestVm.stopPrank();
    }

    function _correctSource(uint256 target) private {
        uint256 id = _fileSourceChallenge(target);
        requestVm.startPrank(VERIFIER_ACTOR);
        challenges.screenChallenge(id, ROLE_VERIFIER, _authority(ROLE_VERIFIER));
        challenges.resolveChallenge(
            AVAChallengeExtension.ChallengeResolutionInput({
                challengeId: id,
                roleKey: ROLE_VERIFIER,
                authorityId: _authority(ROLE_VERIFIER),
                outcome: AVAChallengeExtension.ChallengeOutcome.Upheld,
                correctionStatus: AVACoreTypes.RecognisedStateStatus.Voided,
                reasonHash: keccak256("source.corrected"),
                reasonURI: "test:correction",
                finding: _findingInput(true)
            })
        );
        requestVm.stopPrank();
    }
}
