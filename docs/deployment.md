# Deployment checklist

## AWS

- [ ] S3 Block Public Access enabled on both buckets.
- [ ] Bucket encryption configured.
- [ ] Versioning enabled where appropriate.
- [ ] Lifecycle rules configured for quarantine, uploads, logs, and vault data.
- [ ] GuardDuty Malware Protection for S3 configured on the quarantine bucket.
- [ ] IAM policies follow least privilege. The application role needs:
  - data bucket: `s3:PutObject`, `s3:GetObject`, `s3:DeleteObject`, `s3:GetObjectTagging` (GuardDuty verdict), `s3:ListBucketVersions` and `s3:DeleteObjectVersion` (malware purge)
  - vault bucket: `s3:PutObject` only
  - `comprehend:DetectPiiEntities`, `comprehend:DetectEntities`
  - with `AUTO_CREATE_BUCKETS=true` only: `s3:CreateBucket`, `s3:PutBucketPublicAccessBlock`, `s3:PutEncryptionConfiguration`, `s3:PutBucketVersioning`
- [ ] Token-vault access is separated from normal application access. Only an audited detokenization role can read the vault.
- [ ] CloudTrail/data-event logging reviewed for sensitive buckets.
- [ ] AWS credentials are supplied through workload identity/roles where possible.
- [ ] AWS Comprehend access is restricted to the required region and APIs.

## Application

- [ ] `AUTO_CREATE_BUCKETS=false`
- [ ] `GUARDDUTY_FAIL_OPEN=false`
- [ ] `STRICT_VALIDATION=true` (server-only; there is no per-request override)
- [ ] `CORS_ORIGINS` contains only trusted origins.
- [ ] API authentication and authorization enabled at the deployment boundary, including the SSE stream and `/logs`. Pipeline IDs bound to their uploader.
- [ ] TLS enabled.
- [ ] Rate limits configured (each stream triggers paid Comprehend and LLM calls).
- [ ] Upload size limit reviewed, and a request-body limit set at the proxy slightly above `MAX_UPLOAD_SIZE_MB`.
- [ ] Logs do not contain raw PII or credentials.
- [ ] Retention configured for `LOG_DIR` on the API host (not cleaned automatically).
- [ ] Dependency scanning enabled.
- [ ] Container runs as a non-root user if containerized (the provided image uses UID 10001).
- [ ] Production frontend uses `npm run build && npm run start` (or a static host), not the compose dev server.
- [ ] Frontend lockfile committed and `npm audit` / Dependabot enabled.
- [ ] Multi-instance deployments use durable pipeline state.

## LLM

- [ ] Provider agreement and data-retention settings reviewed.
- [ ] Prompt and tool permissions reviewed.
- [ ] Only tokenized text is allowed across the LLM boundary.
- [ ] Prompt injection defenses are reviewed separately from PII protection.
- [ ] Model changes are tested against the validation suite.
- [ ] Raw-text processing by AWS Comprehend covered by your data-processing assessment.
- [ ] Release exit criteria in [test-plan.md](test-plan.md) met.
