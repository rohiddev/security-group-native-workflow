# Security Group Native Workflow

Harness IDP 2.0 native workflow to add and remove security group rules for an application.
Replaces the custom React plugin with a policy-driven, fully auditable self-service form.

---

## Current Status

**Phase 1 — Proof of concept. Validating workflow rendering in Harness IDP before production.**

This version is used to confirm:
- Form renders correctly across all 3 pages
- SelectFieldFromApi dropdowns cascade correctly (SYSID → account → region → security group)
- ContextViewer fields display rule data
- Reviewer access gate blocks non-reviewers on Page 1
- rulesToAdd (array of objects) and rulesToRemove (array of strings) render with add/remove buttons
- Pipeline trigger passes all parameters correctly

Do not promote to production until the pre-production checklist below is complete.

---

## Pre-Production Checklist

The following must be completed before this workflow goes live:

- [ ] **1. Rule policy guardrails**
  Add a pipeline validation step that rejects dangerous rules before they reach approval.
  Examples to block automatically:
  - Port 22 (SSH) open to `0.0.0.0/0`
  - Port 3389 (RDP) open to `0.0.0.0/0`
  - Any inbound `All traffic` from `0.0.0.0/0`
  Fail the pipeline with a clear rejection message and update the RITM to Rejected.

- [ ] **2. Duplicate rule detection**
  Before applying additions, check whether the rule already exists on the security group.
  Return a warning (not a failure) if a duplicate is found — let the approver decide.

- [ ] **3. Blast radius limit**
  Enforce a maximum of 5 rule changes per submission (removes + adds combined).
  Reject at the pipeline validation step if the limit is exceeded.
  Prevents accidental or malicious bulk changes in a single RITM.

- [ ] **4. Emergency change follow-up**
  Emergency changes must be reviewed within 72 hours and ratified.
  Add a follow-up Jira ticket or ServiceNow task created automatically when changeWindow = Emergency.

- [ ] **5. Automated rollback on failure**
  If rule additions (Step 6) are applied but the pipeline subsequently fails,
  trigger a rollback step to remove the rules that were added in that execution.
  Requires storing the pre-change rule state in the pipeline for comparison.

---

## Architecture

```
Harness IDP Workflow (3-page form)
    Page 1: SYSID -> access gate -> account -> region -> security group
    Page 2: View current rules + rules to remove + rules to add
    Page 3: Change description + justification + change window

    trigger:harness-custom-pipeline
        Step 1a: Build payload (ShellScript)
        Step 1b: Validate SYSID reviewer access - Layer 2 (Http)
        Step 1c: Validate security group belongs to SYSID (Http)
        Step 2:  Raise ServiceNow RITM (Http)
        Step 3:  HarnessApproval - Security Team
        Step 4:  HarnessApproval - SYSID Reviewer (disallowPipelineExecutor: true)
        Step 5:  Apply rule removals (Http) [conditional]
        Step 6:  Apply rule additions (Http) [conditional]
        Step 7:  Update RITM to Implemented (Http)
        Stage 2: Notify Requestor on Success
        Stage 3: Notify Admin on Failure
```

## 3-Layer Access Control

| Layer | Where | How |
|---|---|---|
| 1 - Form gate | Workflow Page 1 | SelectFieldFromApi reviewer-check with appendUser. Required field - empty = Next blocked |
| 2 - Pipeline validation | Step 1b | Http GET reviewer-check. Assertion fails if not reviewer. Catches form bypass. |
| 3 - 4-eyes approval | Step 4 | HarnessApproval with disallowPipelineExecutor: true. Submitter cannot self-approve. |

## Mock API

Port `:8084`. Start with: `cd mock-api && go run main.go`

Test reviewer emails: `alice@example.com`, `bob@example.com`, `charlie@example.com`

| Endpoint | Purpose |
|---|---|
| GET /sysids | List all SYSIDs |
| GET /sysid/:id/details | SYSID name, tier, reviewerGroup |
| GET /sysid/:id/reviewer-check?owner=email | Access check |
| GET /sysid/:id/accounts | Cloud accounts for SYSID |
| GET /accounts/:id/regions | Regions for account |
| GET /sysid/:id/security-groups?account=&region= | Security groups |
| GET /security-groups/:sgId/rules | Current rules |
| POST /security-groups/:sgId/change-request | Accept change, return RITM |

---

Author: Rohid Dev - github.com/rohiddev
