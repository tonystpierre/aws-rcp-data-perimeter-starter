# Rollout Runbook

Use this as a rollout checklist. Do not start at the organization root.

1. Confirm current AWS RCP/SCP support, syntax, quotas, and service exclusions in official AWS documentation.
2. Replace placeholders: organization ID, account IDs, CIDRs, VPC IDs, Regions, role ARNs, and approved source accounts. Choose an attachment plan before editing: do not concatenate every example, and account for `RCPFullAWSAccess` consuming one direct RCP attachment slot.
3. Run the local checks:

   ```bash
   python tools/validate_policy_pack.py
   python -m unittest
   ```

4. Review each policy with security, platform, application, and incident response owners.
5. Test in a sandbox account or sandbox OU.
6. Use IAM Access Analyzer where useful to reduce blind spots around external and internal access.
7. Review CloudTrail denied events and expected service integrations.
8. Add only documented exceptions with owner, reason, evidence, review date, and rollback plan.
9. Move one OU at a time, starting with low-criticality workloads.
10. Attach to root only after lower-scope validation and executive acceptance of residual risk.
11. Maintain rollback access, including break-glass permissions needed to detach or revise policies.

## Console Sign-In Checks

AWS Sign-In RCPs can affect root, IAM user, federated, and IAM Identity Center console sign-in flows. Test excluded principals before enabling console authorization in production.

Confirm that `signin:Authenticate`, `signin:AuthorizeOAuth2Access`, and `signin:CreateOAuth2Token` are all covered where intended. The starter policy does not govern programmatic access using access keys or SigV4-signed API calls.

AWS documents `aws:SourceVpce` and `aws:VpcSourceIp` as supported Sign-In condition keys. This starter example does not use them. Add them only after validating endpoint behavior and condition logic.

Console authorization write operations are documented as requiring `us-east-1`; read operations can use other supported Regions. Confirm the current behavior before rollout.
