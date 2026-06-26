# Public Workloads And Cognito

Broad identity-perimeter RCPs need extra care around public-facing workloads.

AWS Organizations currently lists Amazon Cognito among services that support RCPs. That does not mean every Cognito-backed application should inherit the same perimeter shape as private workload OUs.

Public B2C applications may use Cognito user pools, identity pools, federated identity providers, unauthenticated identity-pool flows, token exchange, or temporary AWS credentials for application users. A broad `aws:PrincipalOrgID` perimeter attached at the wrong OU can break authentication paths or create brittle edge cases that only appear during sign-up, sign-in, federation, token refresh, or application API calls.

This is not a claim that Cognito is unsafe. It is an OU design warning.

Use a separate OU, narrower RCP shard, or staged exception model for public auth workloads. Before attaching broad identity-perimeter RCPs to those OUs, test:

- User sign-up and sign-in.
- Managed login and custom authentication flows.
- Social, SAML, and OIDC federation.
- Identity-pool credential exchange.
- Unauthenticated or guest-user flows, if used.
- Application calls to S3, DynamoDB, API backends, or other AWS services after authentication.

Keep public workload exceptions documented in the register. Do not rely on undocumented allowlists hidden in generated policy JSON.

## Official References

- [AWS Organizations Resource Control Policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [Amazon Cognito user pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools.html)
- [Amazon Cognito identity pools](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-identity.html)
