# Quotas And Sharding

AWS Organizations policy limits shape the architecture. They are not implementation details to discover during rollout.

The quota values below were reviewed against the AWS Organizations quotas documentation on 2026-06-26. Re-check the official documentation before implementation because quota names, support lists, and service behavior can change.

| Policy type | Current document size limit | Current direct attachment limit |
| --- | ---: | ---: |
| Resource Control Policy | 5,120 characters | 5 per root, OU, or account |
| Service Control Policy | 10,240 characters | 10 per root, OU, or account |

For RCPs, `RCPFullAWSAccess` is automatically attached when RCPs are enabled, cannot be detached, and counts toward the five direct RCP attachments allowed on a root, OU, or account. In practice, plan for at most four customer-managed RCPs at a single attachment target.

AWS also documents that console-created policies remove extra whitespace, while policies saved through SDK or CLI operations are saved as provided. Run the validator and check minified size before treating a policy as attachable.

## Sharding Model

Do not build one giant perimeter policy. Split RCPs by stable function so each shard has a clear owner, blast radius, and exception model:

- Core storage and data services: S3, SQS, DynamoDB, CloudWatch Logs, and similar resource-facing data paths.
- Cryptography and secrets: customer-managed KMS keys and Secrets Manager secrets.
- Network and console access: S3 transport rules and AWS Sign-In controls.
- Tightly controlled exceptions: short-lived or high-risk exceptions that are easier to review as a separate policy.

This repo’s RCP files are examples of that shape. They are not a recommendation to attach every file to the same OU.

## Exception Pressure

Exception-heavy environments hit policy-size and attachment limits quickly. Vendor integrations, backup tools, audit systems, security tooling, and cross-account delivery pipelines often need narrowly scoped handling. If those exceptions are hidden inside ad-hoc policy edits, the perimeter becomes hard to review and harder to roll back.

Keep the exception register authoritative. Let the policy reflect reviewed decisions, not become the only place where exceptions are documented.

## Other Policy Layers Still Matter

RCP sharding does not remove the need for local controls:

- Resource policies still define legitimate local sharing.
- Identity policies and SCPs still govern what principals inside the organization can do.
- Permission boundaries and session policies still constrain delegated administration.
- VPC endpoint policies still matter for network-origin controls.
- Service-specific controls still matter where IAM condition keys do not express the full rule.

Use RCPs for high-level resource-side invariants. Keep application-specific authorization close to the workload.

## Official References

- [AWS Organizations quotas and policy size limits](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html)
- [AWS Organizations Resource Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [AWS Organizations Service Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)
