# Production Readiness Checklist

Use this before attaching policies broadly. It is a review checklist, not a deployment approval by itself.

## AWS Facts

- [ ] Current AWS Organizations RCP quotas checked.
- [ ] Current AWS Organizations SCP quotas checked.
- [ ] Current RCP supported-service list checked.
- [ ] Management account exclusion understood.
- [ ] Service-linked role caveat understood.
- [ ] AWS-managed KMS key caveat understood.
- [ ] `kms:RetireGrant` caveat understood.

## Policy Validation

- [ ] All JSON policies parse successfully.
- [ ] Customer-managed RCP statements use `Effect: Deny`.
- [ ] RCP `Principal` is `"*"`.
- [ ] RCPs do not use `NotAction`.
- [ ] RCPs do not use `NotPrincipal`.
- [ ] RCPs do not use global `"*"` as the sole `Action`.
- [ ] `Resource` or `NotResource` is present and intentional.
- [ ] RCP minified size is under the current limit.
- [ ] SCP syntax and size are checked.
- [ ] Placeholder values are replaced before attachment.
- [ ] Policy Sids are stable and unique.

## Rollout Evidence

- [ ] Sandbox account or sandbox OU test completed.
- [ ] IAM Access Analyzer reviewed where supported and useful.
- [ ] CloudTrail reviewed before and after sandbox attachment.
- [ ] AccessDenied events reviewed.
- [ ] Cross-account access paths reviewed.
- [ ] Public access findings reviewed.
- [ ] Expected AWS service integrations tested.
- [ ] Break-glass path tested.
- [ ] Rollback path documented and executable.

## Exception Governance

- [ ] Exception register updated.
- [ ] Expiring exceptions reviewed.
- [ ] Expired exceptions removed or explicitly renewed.
- [ ] Vendor integrations documented.
- [ ] Audit, backup, security tooling, and pipeline exceptions documented.
- [ ] Break-glass exceptions reviewed separately from normal operations.

## Workload Scope

- [ ] Public workload OUs reviewed.
- [ ] Cognito or public auth flows tested, if applicable.
- [ ] Sign-up, sign-in, token exchange, federation, and application flows tested where relevant.
- [ ] Root attachment explicitly approved after lower-scope validation.
