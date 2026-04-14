# Security Group Native Workflow — Design Spec

**Date:** 2026-04-14
**Author:** Rohid Dev · github.com/rohiddev
**Replaces:** `plugin/` custom React plugin
**Status:** Approved for implementation

---

## Goal

Replace the custom React plugin (`harness-idp-public-cloud-security-groups/plugin/`) with a fully native Harness IDP workflow. Developers can add, modify, and remove security group rules for their application's security groups — all from the IDP self-service portal — with no custom code.

**Design principle:** Only members of the application's SYSID-reviewer group may submit changes. Every change raises a ServiceNow RITM and is applied only after two-tier approval (Security Team + SYSID Reviewer).

---

## What Changes vs the Custom Plugin

| Capability | Custom Plugin | Native Workflow |
|---|---|---|
| Interactive rule table | ✅ React component | ❌ Not available natively |
| Real-time rule search/filter | ✅ | ❌ |
| Inline rule editing | ✅ | ❌ |
| CSV export | ✅ | ❌ |
| SYSID-reviewer access gate | ❌ Not enforced | ✅ Form + pipeline + approval |
| ServiceNow RITM | ✅ (submitted to pipeline) | ✅ Pipeline creates it directly |
| Two-tier approval | ❌ | ✅ Security Team + SYSID Reviewer |
| Audit trail | Limited | ✅ Every execution is a permanent record |
| 30-min rebuild cycle | ✅ Required for any change | ❌ No rebuild — YAML only |
| EU cluster support | ❌ Feature flag required | ✅ Native — no flags |

**The interactive table is intentionally dropped.** Users see current rule IDs in a read-only ContextViewer display and specify changes explicitly. This is more auditable and fits standard bank change management practice.

---

## Architecture

```
Harness IDP Workflow (3-page form)
    │
    │  Page 1: SYSID → Account → Region → Security Group
    │           SYSID-reviewer access gate (submit blocked if no access)
    │  Page 2: View current rules + Rules to Remove + Rules to Add
    │  Page 3: Change Description + Justification + Change Window
    │
    ↓  trigger:harness-custom-pipeline
Security Group Change Pipeline
    │
    ├─ Step 1a: Build + validate payload (ShellScript)
    ├─ Step 1b: Validate SYSID reviewer access — Layer 2 (Http)
    ├─ Step 1c: Validate security group belongs to SYSID (Http)
    ├─ Step 2:  Raise ServiceNow RITM (Http → ServiceNow API)
    ├─ Step 3:  HarnessApproval — Security Team (technical review)
    ├─ Step 4:  HarnessApproval — SYSID Reviewer (business confirm)
    ├─ Step 5:  Apply rule removals (Http → Hoover cloud API) [conditional]
    ├─ Step 6:  Apply rule additions (Http → Hoover cloud API) [conditional]
    └─ Step 7:  Update RITM to Implemented (Http → ServiceNow API)
    │
    ├─ Stage 2: Notify Requestor on Success
    └─ Stage 3: Notify Admin on Failure
```

---

## Access Control — 3-Layer Pattern

### Layer 1 — Form gate (primary control)

- `accessCheck` field: `SelectFieldFromApi` → `/sysid/{id}/reviewer-check?owner={email}`
- Returns `[{accessStatus:"yes"}]` if user is a reviewer, `[]` if not
- Field is `required` — empty = submit button disabled automatically
- `accessGuidance` ContextViewer always shows the specific reviewer group name
- When denied: user sees group name + link to Manage AD Group Users workflow

### Layer 2 — Pipeline validation (defence in depth)

- Step 1b re-validates membership server-side via Hoover API
- Catches any bypass of the form (direct API calls, re-runs)
- Assertion: `accessStatus == "yes"` — pipeline aborts if denied

### Layer 3 — HarnessApproval, SYSID Reviewer (4-eyes)

- Step 4: second member of `dso-sysid-{id}-reviewer` must confirm
- `disallowPipelineExecutor: true` — submitter cannot approve their own change
- Creates a peer-review gate for every security group change

---

## Workflow Form

### Page 1 — Application and Security Group

**Required:** `applicationId`, `accessCheck`, `account`, `region`, `securityGroupId`

| Field | Type | API path | Notes |
|---|---|---|---|
| `token` | HarnessAuthToken | — | Hidden, passed to pipeline |
| `applicationId` | SelectFieldFromApi | `/sysids` | All SYSIDs |
| `sysidDetails` | SelectFieldFromApi (hidden) | `/sysid/{id}/details` | Stores `sysidName`, `sysidTier`, `reviewerGroup` in formContext |
| `sysidDisplay` | ContextViewer | — | Shows `sysidName — Tier: sysidTier` |
| `accessCheck` | SelectFieldFromApi (required) | `/sysid/{id}/reviewer-check` | `appendUser: owner: query`. Empty = submit blocked |
| `accessGuidance` | ContextViewer | — | Always shows group name + Manage AD Group Users link |
| `account` | SelectFieldFromApi | `/sysid/{id}/accounts` | Scoped to SYSID |
| `region` | SelectFieldFromApi | `/accounts/{accountId}/regions` | Scoped to account |
| `securityGroupId` | SelectFieldFromApi | `/sysid/{id}/security-groups?account=&region=` | Stores `sgName`, `sgDescription` in formContext |
| `securityGroupDisplay` | ContextViewer | — | Shows `sgName — sgDescription` |

---

### Page 2 — Rule Changes

| Field | Type | Notes |
|---|---|---|
| `currentRulesLoad` | SelectFieldFromApi (hidden) | `/security-groups/{sgId}/rules` — stores `ruleCount`, `rulesSummary` in formContext |
| `currentRulesHeader` | ContextViewer | `N rules currently active on sgName` |
| `rulesSummaryDisplay` | ContextViewer | Full formatted rule list — user reads Rule IDs from here |
| `rulesToRemove` | `type: array, items: string` | One Rule ID per entry (e.g. `sgr-001`). Leave empty to add only. |
| `rulesToAdd` | `type: array, items: object` | One object per new rule. Leave empty to remove only. |

**rulesToAdd item schema:**

| Sub-field | Type | Values |
|---|---|---|
| `direction` | enum | `Inbound`, `Outbound` |
| `protocol` | enum | `TCP`, `UDP`, `ICMP`, `All` |
| `portRange` | string | `443`, `8080-8090`, `All` |
| `source` | string | CIDR, security group ID, or prefix list ID |
| `description` | string | Free text — appears on the RITM |

**Modify a rule** = add its ID to `rulesToRemove` + define the replacement in `rulesToAdd`. No separate "modify" operation needed.

---

### Page 3 — Change Context

**Required:** `changeDescription`, `businessJustification`, `changeWindow`

| Field | Type | Notes |
|---|---|---|
| `changeDescription` | textarea | What the changes enable — appears on RITM |
| `businessJustification` | textarea | Why the change is needed |
| `changeWindow` | enum | `Next Maintenance Window`, `Emergency`, `Scheduled Date` |
| `scheduledDate` | string | Shown only when `changeWindow = Scheduled Date` via `dependencies/oneOf` |
| `requestorDisplay` | ContextViewer | `Submitting as: {{formContext.owner}}` — read-only |

---

## Pipeline

**Identifier:** `security_group_change_pipeline`
**Stages:** 3 (Change Execution, Notify Success, Notify Failure)

### Stage 1 — Security Group Change

#### Step Group: Validate

| Step | Type | Detail |
|---|---|---|
| Step 1a | ShellScript | Build payload JSON. Validate at least one of `rulesToAdd` or `rulesToRemove` is non-empty. Derive `reviewerGroupName = dso-{sysId}-reviewer`. Export `PAYLOAD`. |
| Step 1b | Http | `GET /sysid/{sysId}/reviewer-check?owner=<+pipeline.triggeredBy.email>`. Assertion: `<+httpResponseCode> >= 200 && <+json.select("code", httpResponseBody)> == "000"` |
| Step 1c | Http | `GET /sysid/{sysId}/security-groups?account=&region=`. Validate `securityGroupId` is in response. Assertion: same dual pattern. |

#### Step 2 — Raise RITM

| Step | Type | Detail |
|---|---|---|
| Step 2 | Http | `POST /servicenow/api/ritm`. Body: full change details. Output: `RITM_NUMBER`, `RITM_URL`. Assertion: `httpResponseCode == 201`. |

#### Step Group: Approvals

| Step | Type | Detail |
|---|---|---|
| Step 3 | HarnessApproval | User group: `security_reviewers`. Timeout: `2d`. Approver inputs: `technicalReviewNotes` (required, free text), `riskRating` (selectOneFrom: Low, Medium, High). Message includes RITM number + rule delta summary. |
| Step 4 | HarnessApproval | User group: `<+pipeline.variables.reviewerGroupName>`. `disallowPipelineExecutor: true`. Timeout: `2d`. Approver inputs: `businessConfirmation` (required). Message includes RITM number + requestor name. |

#### Step Group: Apply Changes

| Step | Type | Detail |
|---|---|---|
| Step 5 | Http | `POST /security-groups/{sgId}/rules/remove`. Body: `{ruleIds: [...]}`. `when: condition: <+pipeline.variables.rulesToRemove> != "[]"` |
| Step 6 | Http | `POST /security-groups/{sgId}/rules/add`. Body: `{rules: [...]}`. `when: condition: <+pipeline.variables.rulesToAdd> != "[]"` |
| Step 7 | Http | `PATCH /servicenow/api/ritm/{ritmNumber}`. Body: `{state:"Implemented", closeNotes:"Applied by Harness pipeline <+pipeline.executionId>"}` |

### Stages 2 & 3 — Notifications

Use `idp_notify_success_stage` and `idp_notify_failure_stage` templates.
`when: pipelineStatus: Success / Failure`. `failureStrategies: Ignore` on both.

### Pipeline Variables

| Variable | Source | Description |
|---|---|---|
| `sysId` | Workflow | Application SYSID |
| `accountId` | Workflow | Cloud account |
| `region` | Workflow | Cloud region |
| `securityGroupId` | Workflow | Security group ID e.g. `sg-0a1b2c3d` |
| `rulesToAdd` | Workflow | JSON array string of new rule objects |
| `rulesToRemove` | Workflow | JSON array string of rule IDs to remove |
| `changeDescription` | Workflow | RITM description |
| `businessJustification` | Workflow | RITM justification |
| `changeWindow` | Workflow | Maintenance window type |
| `scheduledDate` | Workflow | Optional — populated when changeWindow = Scheduled Date |
| `token` | Workflow | Harness auth token |
| `reviewerGroupName` | Step 1a | Derived: `dso-{sysId}-reviewer` |
| `requestorEmail` | Pipeline runtime | `<+pipeline.triggeredBy.email>` — no need to pass explicitly |

---

## Mock API — 8 Endpoints

**Base path:** `/hoover-service/security-groups/mock-api`
**Port:** `:8084` (separate from public cloud onboarding mock on `:8083`)
**Language:** Go + Gin (same pattern as existing mock APIs)

| # | Method | Path | Purpose |
|---|---|---|---|
| 1 | GET | `/sysids` | List all SYSIDs for the SYSID picker |
| 2 | GET | `/sysid/:sysidId/details` | SYSID metadata: name, tier, reviewerGroup |
| 3 | GET | `/sysid/:sysidId/reviewer-check` | Access check: `?owner=email`. Returns `[{accessStatus:"yes"}]` or `[]` |
| 4 | GET | `/sysid/:sysidId/accounts` | Cloud accounts scoped to this SYSID |
| 5 | GET | `/accounts/:accountId/regions` | Regions available for this account |
| 6 | GET | `/sysid/:sysidId/security-groups` | `?account=&region=` — security groups for this SYSID + account + region |
| 7 | GET | `/security-groups/:sgId/rules` | Current rules for a security group (formatted for ContextViewer display) |
| 8 | POST | `/security-groups/:sgId/change-request` | Accept full change payload. Return RITM number + URL. |

**Endpoint 7 response shape** (single-item array for SelectFieldFromApi setContextData):
```json
[{
  "value": "loaded",
  "label": "4 rules active",
  "ruleCount": "4 rules active",
  "rulesSummary": "sgr-001 | Inbound  | TCP | 443       | 0.0.0.0/0        | HTTPS from internet\nsgr-002 | Inbound  | TCP | 80        | 0.0.0.0/0        | HTTP redirect\nsgr-003 | Inbound  | TCP | 22        | 10.100.0.0/16    | SSH from VPN\nsgr-004 | Outbound | All | All      | 0.0.0.0/0        | All outbound"
}]
```

**Access control logic in Endpoint 3:**
Hardcode 3 test emails that return `yes`. All others return `[]`.
Derive group name: `dso-{sysidId | lowercase}-reviewer`.

---

## Files to Create

```
harness-idp-public-cloud-security-groups/
├── security-group-native-workflow/
│   ├── workflow.yaml          # Full native workflow (3 pages)
│   ├── catalog-info.yaml      # Registers workflow in IDP catalog
│   └── mock-api/
│       └── main.go            # Go + Gin mock API server (port :8084)
└── docs/
    └── specs/
        └── 2026-04-14-security-group-native-workflow-design.md  ← this file
```

The existing `plugin/` and `scaffold/` directories are **not modified** — they remain as the v1 reference until the native workflow is validated in production.

---

## Out of Scope

- Interactive rule table with real-time filtering — not possible natively; intentionally dropped
- CSV export — not possible natively; intentionally dropped
- Azure support — mock API covers AWS only; Azure can be added as a second pass
- Direct cloud API calls (AWS SDK) — mock API simulates Hoover as the intermediary; real Hoover endpoints are the integration target

---

## Constraints and Rules

- All step names: letters, digits, underscores, spaces only — no hyphens or parentheses
- All secrets via Vault — `<+secrets.getValue("...")>`
- `delegateSelectors: act-delegate-k8s-ephub-p2r1` on every ShellScript step
- Http step assertion: `<+httpResponseCode> >= 200 && <+json.select("code", httpResponseBody)> == "000"`
- Notification stages: `failureStrategies: Ignore` — email failure must not mask pipeline outcome
- `pipelineStatus: Success / Failure` — NOT `Succeeded` / `Failed` (invalid enum)
- `onRetryFailure: type: Abort` — NOT `MarkAsFailure` (invalid enum)
- No `dependsOn` on notification stages — `pipelineStatus` drives scheduling
