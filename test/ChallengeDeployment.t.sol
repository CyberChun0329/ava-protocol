// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.26;

import {AVAChallengeExtension} from "../src/extensions/challenge/AVAChallengeExtension.sol";
import {AVAChallengePolicyValidation} from "../src/extensions/challenge/AVAChallengePolicyValidation.sol";
import {AVACoreTypes} from "../src/core/AVACoreTypes.sol";
import {AVACoreRulePackageRegistry} from "../src/core/AVACoreRulePackageRegistry.sol";
import {AVACapabilityKeys} from "../src/core/AVACapabilityKeys.sol";
import {AVAEvidenceRegistry} from "../src/core/AVAEvidenceRegistry.sol";
import {AVAGovernanceKernel} from "../src/core/AVAGovernanceKernel.sol";
import {IAVAChallengePolicyModule} from "../src/core/interfaces/IAVACoreRuleModules.sol";
import {RuleModuleIdentity} from "../src/interfaces/IRuleModuleIdentity.sol";
import {RequestAllocationFixture} from "./helpers/RequestAllocationFixture.sol";
import {M14PermissiveApplicationModule} from "./helpers/M14ApplicationFixture.sol";

/// @dev A filing policy may depend on the Router caller and every supplied challenge field.
contract ExactFilingContextPolicy is IAVAChallengePolicyModule, RuleModuleIdentity {
    address private immutable ROUTER;
    bytes32 private immutable CONTEXT_HASH;

    constructor(address router, ChallengeContext memory expected) {
        ROUTER = router;
        CONTEXT_HASH = keccak256(abi.encode(expected));
    }

    function validateChallenge(ChallengeContext calldata context) external view {
        require(msg.sender == ROUTER, "filing policy caller changed");
        require(keccak256(abi.encode(context)) == CONTEXT_HASH, "filing context changed");
    }

    function _moduleConfigurationHash() internal view override returns (bytes32) {
        return keccak256(abi.encode(ROUTER, CONTEXT_HASH));
    }
}

contract ChallengeDeploymentTest is RequestAllocationFixture {
    bytes32 private constant APP = keccak256("challenge.deployment.app");
    bytes32 private constant CHALLENGER_SUBJECT = keccak256("challenge.deployment.challenger");
    address private constant CHALLENGER = address(0xC3);
    AVAChallengeExtension private challenges;

    function setUp() public {
        _setUpRequestAllocation(APP, new M14PermissiveApplicationModule(APP), keccak256("challenge.deployment.object"));
        challenges =
            new AVAChallengeExtension(kernel, authorityMatrix, identityRegistry, packageRegistry, evidenceRegistry);
    }

    function testChallengeRuntimeLeavesAtLeastOneKiBOfHeadroom() public view {
        require(address(challenges).code.length <= 24_576 - 1_024, "challenge runtime lacks 1 KiB headroom");
    }

    function testFilingRetainsCurrentAndHistoricalContextWithOriginalActor() public {
        (uint256 targetId, uint256 challengeStateId, uint256 targetPackage) = _prepareFiling(false);
        requestVm.prank(CHALLENGER);
        uint256 id = challenges.fileChallenge(_filingInput(targetId, challengeStateId));
        AVAChallengeExtension.ChallengeRecord memory record = challenges.getChallenge(id);
        require(record.packageId == requestPackageId && record.targetPackageId == targetPackage, "packages collapsed");
        require(record.filedBy == CHALLENGER && record.challengerSubjectId == CHALLENGER_SUBJECT, "actor lost");
        require(
            kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Vested,
            "filing changed target"
        );
    }

    function testHistoricalFilingPolicyCannotBeSkipped() public {
        (uint256 targetId, uint256 challengeStateId,) = _prepareFiling(true);
        uint256 nextChallengeId = challenges.nextChallengeId();
        requestVm.prank(CHALLENGER);
        requestVm.expectRevert();
        challenges.fileChallenge(_filingInput(targetId, challengeStateId));
        require(challenges.nextChallengeId() == nextChallengeId, "rejected filing was recorded");
        require(
            kernel.getRecognisedStateReference(challengeStateId).status
                == AVACoreTypes.RecognisedStateStatus.Registered,
            "rejected filing transitioned concern"
        );
    }

    function testMissingFilingValidationLibraryRejectsBeforeRecordingChallenge() public {
        (uint256 targetId, uint256 challengeStateId,) = _prepareFiling(false);
        uint256 nextChallengeId = challenges.nextChallengeId();
        requestVm.etch(address(AVAChallengePolicyValidation), hex"");
        requestVm.prank(CHALLENGER);
        requestVm.expectRevert();
        challenges.fileChallenge(_filingInput(targetId, challengeStateId));
        require(challenges.nextChallengeId() == nextChallengeId, "missing validator recorded filing");
        require(
            kernel.getRecognisedStateReference(challengeStateId).status
                == AVACoreTypes.RecognisedStateStatus.Registered,
            "missing validator transitioned concern"
        );
        require(kernel.getRecognisedStateReference(targetId).status == AVACoreTypes.RecognisedStateStatus.Vested);
    }

    function _prepareFiling(bool rejectHistorical)
        private
        returns (uint256 targetId, uint256 challengeStateId, uint256 targetPackage)
    {
        identityRegistry.assignSubject(CHALLENGER, APP, ROLE_SOURCE, CHALLENGER_SUBJECT, "test:challenger");
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FORM_RECOGNISED_STATE, true);
        authorityMatrix.setPermission(APP, ROLE_SOURCE, AVACoreTypes.ACTION_FILE_CHALLENGE, true);
        targetId = kernel.nextRecognisedStateId();
        _registerFilingPackage(2, targetId, rejectHistorical ? address(0xBAD) : CHALLENGER);
        targetPackage = requestPackageId;
        require(_createStateForCommitment(keccak256("historical target")) == targetId, "wrong target identity");
        _registerFilingPackage(3, targetId, CHALLENGER);
        requestVm.startPrank(CHALLENGER);
        uint256 evidenceId = evidenceRegistry.registerEvidence(
            AVAEvidenceRegistry.EvidenceRegistrationInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                subjectId: CHALLENGER_SUBJECT,
                commitment: keccak256("filing evidence"),
                evidenceTypeHash: keccak256("filing support"),
                disclosurePolicyId: requestPolicyId,
                authorityId: CHALLENGER_SUBJECT,
                uri: "test:evidence"
            })
        );
        uint256 objectId = kernel.registerGovernedObject(
            AVAGovernanceKernel.GovernedObjectInput({
                appId: APP,
                workflowKey: REQUEST_WORKFLOW,
                packageId: requestPackageId,
                roleKey: ROLE_SOURCE,
                objectTypeKey: keccak256("filing concern"),
                objectCommitment: keccak256("filing concern commitment"),
                parentObjectId: kernel.getRecognisedStateReference(targetId).governedObjectId,
                subjectId: CHALLENGER_SUBJECT,
                evidenceReceiptId: evidenceId,
                disclosurePolicyId: requestPolicyId,
                metadataHash: keccak256("filing metadata"),
                authorityId: CHALLENGER_SUBJECT,
                uri: "test:concern"
            })
        );
        challengeStateId = kernel.formRecognisedState(
            AVAGovernanceKernel.RecognisedStateFormationInput({
                governedObjectId: objectId,
                roleKey: ROLE_SOURCE,
                authorityId: CHALLENGER_SUBJECT,
                stage: AVACoreTypes.Stage.Verification,
                status: AVACoreTypes.RecognisedStateStatus.Registered,
                reasonHash: keccak256("filing formation"),
                reasonURI: "test:concern-state"
            })
        );
        requestVm.stopPrank();
    }

    function _registerFilingPackage(uint64 version, uint256 targetId, address expectedActor) private {
        IAVAChallengePolicyModule.ChallengeContext memory expected = IAVAChallengePolicyModule.ChallengeContext({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: packageRegistry.nextPackageId(),
            actionKey: AVACoreTypes.ACTION_FILE_CHALLENGE,
            roleKey: ROLE_SOURCE,
            challengeId: 0,
            recognisedStateId: targetId,
            actorSubjectId: CHALLENGER_SUBJECT,
            targetSubjectId: _authority(ROLE_SOURCE),
            outcomeKey: bytes32(0),
            targetStatus: AVACoreTypes.RecognisedStateStatus.Vested,
            authorityId: CHALLENGER_SUBJECT,
            actor: expectedActor
        });
        AVACoreRulePackageRegistry.ModuleBinding[] memory bindings =
            _coreBindings(new M14PermissiveApplicationModule(APP));
        bindings[6] = _coreBinding(
            AVACapabilityKeys.CHALLENGE_POLICY,
            address(new ExactFilingContextPolicy(address(kernel.POLICY_ROUTER()), expected))
        );
        requestPackageId = packageRegistry.supersedeRulePackage(
            _corePackageInput(
                APP,
                REQUEST_WORKFLOW,
                ROLE_PACKAGE,
                _authority(ROLE_PACKAGE),
                version,
                keccak256("request.compatibility"),
                "test:filing-context"
            ),
            requestPackageId,
            bindings
        );
        kernel.bindSourceBoundTransitionRequester(requestPackageId, address(challenges));
        kernel.bindTransitionGuard(requestPackageId, address(challenges));
    }

    function _filingInput(uint256 targetId, uint256 challengeStateId)
        private
        view
        returns (AVAChallengeExtension.ChallengeFilingInput memory)
    {
        return AVAChallengeExtension.ChallengeFilingInput({
            appId: APP,
            workflowKey: REQUEST_WORKFLOW,
            packageId: requestPackageId,
            challengeRecognisedStateId: challengeStateId,
            challengedRecognisedStateId: targetId,
            roleKey: ROLE_SOURCE,
            reasonHash: keccak256("filing reason"),
            reasonURI: "test:filing"
        });
    }
}
