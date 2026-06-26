# Rollout Evidence

Do not enforce a data perimeter from theory alone. Use evidence before attachment, during sandbox rollout, and after each OU move.

CloudTrail and IAM Access Analyzer reduce blind spots. They do not prove that a policy is safe for every workload path.

## Evidence To Gather

- CloudTrail activity for the target OU before enforcement.
- AccessDenied events during sandbox testing.
- Cross-account resource access.
- External principal access.
- Public access findings.
- AWS service-principal paths for logging, encryption, delivery, eventing, backup, and security tooling.
- Console sign-in paths if using AWS Sign-In RCPs.

Use IAM Access Analyzer deliberately. External access analyzers help identify supported resources shared outside the zone of trust. Internal access analysis can help with selected business-critical resources, but AWS documents pricing for internal access analysis by monitored resource, so start with the resources that matter most.

Start with:

- Sensitive S3 buckets.
- Customer-managed KMS keys.
- DynamoDB tables.
- Secrets Manager secrets.
- SQS queues.
- CodeCommit repositories.
- CloudWatch Logs groups.
- Console sign-in policy paths.

IAM Access Analyzer support varies by analyzer type and resource type. Use CloudTrail and service-specific review for resources that are not covered by the analyzer you enabled.

## Athena Query Templates

These are templates. Adapt database names, table names, CloudTrail schema, partitions, Regions, and organization identifiers before use.

### Recent AccessDenied Events After Sandbox Attachment

```sql
SELECT
  eventtime,
  recipientaccountid,
  eventsource,
  eventname,
  useridentity.accountid AS principal_account,
  useridentity.arn AS principal_arn,
  errorcode,
  errormessage
FROM cloudtrail_logs
WHERE eventtime >= current_timestamp - interval '24' hour
  AND (errorcode LIKE '%AccessDenied%' OR errormessage LIKE '%explicit deny%')
ORDER BY eventtime DESC
LIMIT 200;
```

### Top Services And Actions Impacted

```sql
SELECT
  eventsource,
  eventname,
  errorcode,
  count(*) AS denied_events
FROM cloudtrail_logs
WHERE eventtime >= current_timestamp - interval '7' day
  AND (errorcode LIKE '%AccessDenied%' OR errormessage LIKE '%explicit deny%')
GROUP BY eventsource, eventname, errorcode
ORDER BY denied_events DESC
LIMIT 50;
```

### S3 Calls From Outside The Expected Organization

```sql
SELECT
  eventtime,
  recipientaccountid,
  eventname,
  useridentity.accountid AS principal_account,
  useridentity.arn AS principal_arn,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventtime >= current_timestamp - interval '30' day
  AND useridentity.accountid <> recipientaccountid
ORDER BY eventtime DESC
LIMIT 200;
```

### KMS Use By Unexpected Principals

```sql
SELECT
  eventtime,
  recipientaccountid,
  eventname,
  useridentity.accountid AS principal_account,
  useridentity.arn AS principal_arn,
  requestparameters
FROM cloudtrail_logs
WHERE eventsource = 'kms.amazonaws.com'
  AND eventname IN ('Decrypt', 'GenerateDataKey', 'GenerateDataKeyWithoutPlaintext')
  AND eventtime >= current_timestamp - interval '30' day
  AND useridentity.accountid <> recipientaccountid
ORDER BY eventtime DESC
LIMIT 200;
```

### Public Or Cross-Account Resource Access Indicators

```sql
SELECT
  eventtime,
  recipientaccountid,
  eventsource,
  eventname,
  useridentity.type AS principal_type,
  useridentity.accountid AS principal_account,
  useridentity.arn AS principal_arn,
  sourceipaddress
FROM cloudtrail_logs
WHERE eventtime >= current_timestamp - interval '30' day
  AND (
    useridentity.type = 'Anonymous'
    OR (useridentity.accountid IS NOT NULL AND useridentity.accountid <> recipientaccountid)
  )
ORDER BY eventtime DESC
LIMIT 200;
```

### AWS Sign-In Denied Events

```sql
SELECT
  eventtime,
  recipientaccountid,
  eventsource,
  eventname,
  useridentity.arn AS principal_arn,
  sourceipaddress,
  awsregion,
  errorcode,
  errormessage
FROM cloudtrail_logs
WHERE eventsource = 'signin.amazonaws.com'
  AND eventtime >= current_timestamp - interval '7' day
  AND (errorcode IS NOT NULL OR errormessage IS NOT NULL)
ORDER BY eventtime DESC
LIMIT 200;
```

## Evidence Review Loop

1. Review baseline CloudTrail activity before attaching the RCP.
2. Attach only in a sandbox account or sandbox OU.
3. Watch AccessDenied events and service integration paths.
4. Add only documented exceptions.
5. Re-run Access Analyzer where useful.
6. Move one OU at a time.
7. Keep rollback ready until denied-event volume and exception records are understood.

## Official References

- [IAM Access Analyzer](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html)
- [IAM Access Analyzer policy generation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-generation.html)
- [AWS CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-user-guide.html)
