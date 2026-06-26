# Exception Lifecycle

The exception list is the perimeter.

A data perimeter without an exception lifecycle becomes a set of undocumented allowlists. That is worse than an explicit risk decision because nobody knows what is intentional, what is temporary, and what should be removed.

Do not hide exceptions in policy comments, one-off JSON edits, ticket links without context, or pipeline variables that only one team understands. The exception register should be the system of record. Policies should implement approved decisions from that register.

## Required Fields

Every exception should record:

- Exception ID.
- Status: `proposed`, `approved`, `active`, `expired`, or `revoked`.
- Owner.
- Business reason.
- Affected AWS service.
- Source account, principal, vendor, or AWS service integration.
- Target resource scope.
- Policy layer affected: SCP, RCP, resource policy, identity policy, endpoint policy, or other.
- Environment or OU.
- Approval owner.
- Creation date.
- Expiration date or review date.
- Validation evidence.
- CloudTrail evidence link or query.
- IAM Access Analyzer evidence.
- Rollback plan.

## Example Record

```yaml
id: EX-1042
status: active
type: vendor-principal
owner: security-architecture@example.com
approval_owner: head-of-cloud-security@example.com
business_reason: Temporary vendor read access while evidence export is migrated to a private integration.
affected_service: s3
source:
  vendor: Example Vendor
  principal_arns:
    - arn:aws:iam::123456789012:role/VendorEvidenceReadOnlyRole
target_resource_scope:
  accounts:
    - "123456789012"
  resources:
    - arn:aws:s3:::example-evidence-bucket/*
policy_layers:
  - rcp
  - resource-policy
environment: sandbox-ou
related_policy_sids:
  - DenyResourceAccessFromPrincipalsOutsideOrganization
created_at: "2026-06-25"
review_by: "2026-08-15"
expires_at: "2026-09-01"
evidence:
  - ticket:SEC-1042
cloudtrail_evidence:
  query: athena:cloudtrail-vendor-access-review
  result: only documented principal observed
access_analyzer_evidence:
  finding: access-analyzer:finding-reviewed
  result: external access reviewed and accepted
rollback_plan: Remove the vendor principal from the bucket policy and revoke the exception from the RCP change set.
```

## Review Cadence

High-risk exceptions should be reviewed at least monthly. Narrow, low-risk exceptions can be reviewed quarterly if they have clear ownership, monitoring, and an expiration path.

Any exception without an owner, evidence, or rollback plan should be treated as unapproved. Convenience is not architecture.

## Approval Checklist

- Scope is narrower than the business request.
- Affected policy layers are named.
- Source account, principal, vendor, or AWS service is explicit.
- CloudTrail evidence supports the expected access path.
- Access Analyzer findings are reviewed where the resource type is supported.
- Expiration or review date is set.
- Rollback has been tested or is simple enough to execute during an incident.
- Break-glass access is not used as a standing vendor or operations path.

## Revocation Checklist

- Confirm the business need has ended.
- Remove resource policy, identity policy, endpoint policy, or RCP exception logic.
- Re-run validator and policy review.
- Review CloudTrail for denied events after removal.
- Resolve or archive Access Analyzer findings.
- Mark the exception `revoked` or `expired`.
- Keep the record for audit history.

## Common Exception Types

Vendor integrations should name the vendor, principal ARN, target resources, and expiration date.

Audit tools and backup systems should identify the source account, service principal or role, affected services, and expected schedule.

Security tooling should use stable automation roles and avoid broad cross-account principals.

Cross-account pipelines should document source account, target account, artifact path, and rollback owner.

Break-glass roles should be rare, tested, monitored, and reviewed separately from normal operations.
