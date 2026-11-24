# Governance records and entry points

Applications define their own rules, actors, permissions and effects. AVA records the actions performed under the installed rules; installing an application does not establish that its rules faithfully represent an institution or guarantee access to a remedy.

| Question | Record | Meaning |
| --- | --- | --- |
| Which conclusion was recognised? | `AVAGovernanceKernel` object, state and transition records | The object, evidence, authority and rule package used for the occurrence. Later use checks current eligibility. |
| Which option did an authorised actor choose? | `AVADecisionRegistry` | A choice against the declared request, options and support. Allocation is a separate approval. |
| What action was authorised and what effect was recorded? | `AVARequestAllocation` and `AVAExecutionLifecycle` | Separate approval, consumption and completion records. Attempts and reports alone do not establish an effect. |
| What did a later review determine? | `AVACorrectionRegistry` and the bound origin | The case, finite finding and disposition; the origin applies the authorised consequence. Earlier records remain readable. |

The Kernel has separate entry points for generic transitions, vesting, transitions requested by a bound origin and independent repair. Combined formation still records a Generic step from Provisional to Challengeable. Vesting has its own authority requirement.

## Decisions and execution

A decision policy declares a finite catalogue and the relevant support pool. The registry filters the catalogue under the selected rule and current actor permission. The rule author must supply the complete relevant options, witness resolution and domain constraints; the protocol cannot establish that an application omitted no institutional rule. A decision is separate from Allocation, and neither by itself establishes that an effect occurred.

For split execution, attempts and reports are retained. Independent recovery is bounded by the installed rules and evidence. Partial, unknown or contradictory reports freeze retries; external operations and partial effects require their own recovery rules.

## Correction and history

Authorised correction records a finite finding and disposition with its basis and scope. A screened allegation is not a merits finding. Neutral outcomes do not assert an adverse conclusion. A correction can change current applicability through an explicit transition, while preserving original recognition and effect history. Compensation or other remedy requires its own authorisation and completion; a correction does not erase a realised effect.

Challenge access before admission, handling after admission and fulfilment of an authorised remedy are distinct questions. Installation checks and a successful tested case do not establish all three for every actor or circumstance.
