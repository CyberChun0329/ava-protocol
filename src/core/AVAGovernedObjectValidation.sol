// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {AVACoreTypes} from "./AVACoreTypes.sol";
import {IAVAApplicationModule} from "../interfaces/IAVAApplicationModule.sol";
import {
    IAVAAttributionModule,
    IAVAFieldPolicyModule,
    IAVAAntiAbusePolicyModule
} from "./interfaces/IAVACoreRuleModules.sol";

/// @notice Fixed linked object-policy validation; delegation retains the Kernel caller and context.
/// @dev No storage, authority, module selection or replaceable binding is introduced here.
library AVAGovernedObjectValidation {
    function validate(
        IAVAApplicationModule application,
        IAVAAttributionModule attribution,
        IAVAFieldPolicyModule fieldPolicy,
        IAVAAntiAbusePolicyModule antiAbuse,
        IAVAApplicationModule.GovernedObjectContext memory context
    ) external view {
        application.validateGovernedObject(context);
        attribution.validateAttribution(context);
        if (address(fieldPolicy) != address(0)) {
            fieldPolicy.validateFieldPolicy(
                IAVAFieldPolicyModule.FieldPolicyContext({
                    appId: context.appId,
                    workflowKey: context.workflowKey,
                    packageId: context.packageId,
                    actionKey: AVACoreTypes.ACTION_REGISTER_GOVERNED_OBJECT,
                    roleKey: context.roleKey,
                    stage: AVACoreTypes.Stage.Attribution,
                    targetId: uint256(context.objectCommitment),
                    objectTypeKey: context.objectTypeKey,
                    subjectId: context.subjectId,
                    evidenceId: context.evidenceReceiptId,
                    authorityId: context.authorityId,
                    actor: context.actor
                })
            );
        }
        if (address(antiAbuse) != address(0)) {
            antiAbuse.validateAntiAbuse(
                IAVAAntiAbusePolicyModule.AntiAbuseContext({
                    appId: context.appId,
                    workflowKey: context.workflowKey,
                    packageId: context.packageId,
                    actionKey: AVACoreTypes.ACTION_REGISTER_GOVERNED_OBJECT,
                    roleKey: context.roleKey,
                    targetId: uint256(context.objectCommitment),
                    targetTypeKey: context.objectTypeKey,
                    actorSubjectId: context.authorityId,
                    targetSubjectId: context.subjectId,
                    authorityId: context.authorityId,
                    actor: context.actor
                })
            );
        }
    }
}
