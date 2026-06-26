# Exception Model

Exceptions are normal. Real AWS environments have vendor integrations, AWS service integrations, break-glass roles, migration windows, legacy clients, and acquisition leftovers.

The risk is not that exceptions exist. The risk is that nobody can explain them.

Undocumented exceptions destroy perimeter quality. A policy can look strict while real access lives in forgotten bucket policies, key policies, queue policies, Sign-In exclusions, or one-off IAM roles.

The exception list is the perimeter.

For the full operating lifecycle, required fields, approval checklist, and revocation checklist, see [`exception-lifecycle.md`](exception-lifecycle.md).

## What An Exception Needs

An exception record should be specific enough that a security engineer can review it without hunting for context:

- Stable ID.
- Status.
- Type.
- Owner.
- Business reason.
- Scope.
- Related policy Sids.
- Review date.
- Evidence.
- Rollback plan.

The scope should name the actual boundary: accounts, principals, resources, services, source networks, or source accounts. Avoid labels like "vendor access" unless the principal and resource boundary are also written down.

## Review Cadence

High-risk exceptions should be reviewed at least monthly. Lower-risk exceptions can be reviewed quarterly if they are narrow and monitored.

Any exception without an owner should be removed or escalated. Exceptions must expire or be reviewed. Convenience is not architecture.

## Rollback

Every exception needs a rollback plan before it is approved. The plan may be simple: remove a resource policy statement, revoke a KMS grant, delete a Sign-In excluded principal, or detach a temporary policy.

If rollback requires a migration, the exception is not temporary until that migration has an owner and a date.

## Intentional vs Accidental

An intentional exception has an owner, reason, scope, evidence, review date, and rollback path.

Accidental exposure is access that exists because nobody can explain why it exists.

The goal is not zero exceptions. The goal is that every exception is deliberate, narrow, reviewed, and reversible.
