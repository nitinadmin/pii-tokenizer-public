# Security review

**Scope:** backend (`src/pii_tokenizer`), frontend (`frontend/src`), container and CI configuration, and project documentation.
**Version reviewed:** 1.0.0, with fixes applied in 1.1.0 (see [CHANGELOG](../CHANGELOG.md)).
**Date:** 2026-10-08
**Method:** manual code review against the trust boundaries in [architecture.md](architecture.md), with automated tests added for each fixed finding ([test-plan.md](test-plan.md)). No live AWS or Anthropic environment was used, and no penetration testing was performed.

Severity reflects impact on the project's core promise: raw PII must not reach the LLM, and the token vault must not be readable by unauthorised parties.

## Summary

| ID | Severity | Finding | Status |
|---|---|---|---|
| SR-01 | Critical | Token vault (original values) streamed to any holder of the pipeline ID | Fixed |
| SR-02 | High | Strict validation could be disabled per request with `?strict=false` | Fixed |
| SR-03 | High | Detection-engine failures were silently ignored; strict mode still passed | Fixed |
| SR-04 | High | No authentication or authorisation on any endpoint | Open (deployment) |
| SR-05 | Medium | PDFs parsed before the GuardDuty verdict | Fixed |
| SR-06 | Medium | Pipeline ID was 48 bits and reusable; it is the only access control | Fixed |
| SR-07 | Medium | Client filenames (often PII) written to logs and S3 keys | Fixed |
| SR-08 | Medium | Markdown code fences bypassed the injection scan | Fixed |
| SR-09 | Medium | "Verifying no raw PII in LLM payload" was logged but never checked | Fixed |
| SR-10 | Medium | Malware "deleted" from a versioned bucket stayed recoverable | Fixed |
| SR-11 | Medium | Exception messages (may echo content) logged and returned to client | Fixed |
| SR-12 | Medium | No rate limiting; unbounded in-memory upload store | Open |
| SR-13 | Medium | Residual validator cannot detect names or addresses missed by every engine | Open (inherent) |
| SR-14 | Medium | Frontend had no lockfile; `next ^14.2.0` floats across security releases | Partially fixed |
| SR-15 | Low | GuardDuty `UNSUPPORTED` reported as `CLEAN` | Fixed |
| SR-16 | Low | Auto-created buckets had no Block Public Access | Fixed |
| SR-17 | Low | CORS allowed credentials and any header | Fixed |
| SR-18 | Low | Upload body read fully into memory before the size check | Partially fixed |
| SR-19 | Low | Container could not start (log directory not writable) | Fixed |
| SR-20 | Low | Logs endpoint is unauthenticated; local log files are never deleted | Open |
| SR-21 | Low | Documents can contain literal `[TOKEN_…]` strings | Open |
| SR-22 | Low | Supply-chain hygiene: actions and base image not pinned by digest; no dependency scanning in CI | Open |
| SR-23 | Info | Raw document text is sent to AWS Comprehend | Documented |

## Fixed findings

### SR-01 — Token vault exposed to the browser (Critical)
The `tokens` SSE event contained `TokenEntry.original` for every detection, and the UI had a "Reveal originals" button. Anyone who could open `/api/pipeline/{id}/stream` therefore received the complete vault mapping, bypassing the separate vault bucket and its IAM controls.
**Fix:** the stream now sends a masked `preview` in place of `original` ([pipeline.py `_client_tokens`](../src/pii_tokenizer/routers/pipeline.py)). Originals are written only to the vault bucket. The reveal control has been removed from [TokenMap.jsx](../frontend/src/components/TokenMap.jsx).
**Tests:** TP-LEAK-01, TP-DATA-02.

### SR-02 — Strict mode was client-controlled (High)
`GET /stream?strict=false` overrode `STRICT_VALIDATION=true`, so any client could send unvalidated text to the LLM.
**Fix:** the parameter has been removed; the server setting is the only control. The frontend toggle has been removed.
**Tests:** TP-STRICT-01.

### SR-03 — Silent engine failure (High)
Comprehend errors were caught per chunk and logged as warnings. An unhandled Presidio error (for example spaCy's 1,000,000-character limit) crashed the stream. Because the validator only knows regex patterns and already-detected values, a missing NER engine left names undetected **and** validation still passed.
**Fix:** `tokenize_document` now returns the list of failed engines. Any partial results are kept and applied. The pipeline adds an "All detection engines completed" check, which fails validation, so strict mode halts before anything is written to the vault or sent to the LLM.
**Tests:** TP-STRICT-02, TP-STRICT-03, TP-DETECT-02.

### SR-05 — PDF parsed before the malware verdict (Medium)
`pdfplumber` ran during upload, before GuardDuty had scanned the object. A parser exploit would have bypassed the malware gate.
**Fix:** text files are decoded at upload, which involves no parsing. PDFs are extracted in the stream only after a non-blocking GuardDuty verdict, from the **promoted S3 object**, so the bytes parsed are exactly the bytes scanned.
**Tests:** TP-MAL-02.

### SR-06 — Weak, reusable pipeline ID (Medium)
IDs were 12 hex characters (48 bits) and could be streamed repeatedly. Repeated streams re-ran the pipeline and re-sent the document.
**Fix:** IDs are now 128-bit `secrets.token_hex(16)` values and are format-validated before any lookup or filesystem access. Each upload can be streamed once (concurrent attempts get 409), and the in-memory raw text is dropped when the stream ends. If the client disconnects before promotion, the quarantine object is deleted.
**Tests:** TP-ACCESS-01..03.

### SR-07 — Filenames in logs and S3 keys (Medium)
Filenames such as `jane_doe_w2.pdf` were logged, stored in S3 log objects, and used as S3 key components. Because the filename is attacker-controlled, it could also inject characters into keys.
**Fix:** S3 keys use `document<ext>` built from the allow-listed extension, and logs record only the extension and size.
**Tests:** TP-LEAK-02.

### SR-08 — Markdown fence bypass (Medium)
Content inside triple-backtick fences in `.md` files was excluded from the injection scan, so any payload could be hidden there.
**Fix:** fenced content is scanned like everything else. Trade-off: Markdown notes that contain script examples are now blocked.
**Tests:** TP-INPUT-03.

### SR-09 — LLM boundary check was only a log line (Medium)
**Fix:** `generate_summary` now runs `count_payload_leaks` (residual patterns plus every known original value) immediately before the call. In strict mode a leak raises `LLMBoundaryError` and no client is created. The model name is now logged from configuration instead of a hard-coded "Claude Sonnet". The document is wrapped in `<document>` tags, and the system prompt tells the model to treat it as data.
**Tests:** TP-LLM-01.

### SR-10 — Malware left recoverable (Medium)
On the versioned bucket that the app creates, `delete_object` only added a delete marker.
**Fix:** `purge_object` deletes every version. This requires `s3:ListBucketVersions` and `s3:DeleteObjectVersion`, and falls back to a plain delete with a warning.
**Tests:** TP-MAL-01 (call path; version deletion itself needs the AWS integration test TP-AWS-03).

### SR-11 — Exception text leaked (Medium)
LLM, Comprehend, PDF and S3 exception messages were logged in full, and the LLM error was returned to the browser as the summary.
**Fix:** only the exception type, or the AWS error code, is logged, and the client receives a generic message.
**Tests:** TP-LEAK-04.

### SR-15 to SR-19 (Low)
- **SR-15:** `UNSUPPORTED` now reports status `UNSUPPORTED` with a warning. It still does not block, because the fast scan already restricts file types. Test: TP-MAL-03.
- **SR-16:** `AUTO_CREATE_BUCKETS` now enables all four Block Public Access settings.
- **SR-17:** CORS now uses `allow_credentials=False` and `allow_headers=["Content-Type"]`. The API uses no cookies.
- **SR-18:** the handler reads at most `MAX_UPLOAD_SIZE_MB + 1` bytes. However, Starlette has already spooled the whole multipart body by then, so a **proxy-level body limit is still required** ([deployment.md](deployment.md)). Test: TP-INPUT-01.
- **SR-19:** the Dockerfile creates `/app/logs` owned by the non-root user and installs `en_core_web_lg`. The build has not been verified here, because no Docker daemon was available (TP-BUILD-02).

## Open findings

### SR-04 — No authentication (High, deployment responsibility)
Every endpoint is anonymous. The 128-bit, single-use pipeline ID limits casual access, but it is a bearer secret, not an identity. Put an authenticating proxy or gateway in front of the API, and bind each pipeline ID to the user who uploaded it. Note that `EventSource` cannot send custom headers, so stream authentication needs a cookie (re-enable CORS credentials for the exact origin) or a short-lived signed URL.

### SR-12 — No rate limiting; unbounded memory (Medium)
Each upload holds up to 10 MB of text in `_uploads` for up to `UPLOAD_TTL_SECONDS`, and every stream triggers paid Comprehend and LLM calls. Add rate limits at the gateway, a cap on pending uploads, and a durable job store (already listed in the architecture notes).

### SR-13 — Validator blind spot (Medium, inherent)
Residual validation covers SSNs, emails, phone numbers, card numbers, IPs and repeats of detected values. A name or address that every engine missed **passes** validation. This is a limitation of detection-based tokenisation; the README describes the pipeline as risk reduction for this reason. Mitigations: a labelled evaluation corpus (TP-DETECT-03), allow-lists of expected document types, and human review for high-risk documents.

### SR-14 — Frontend dependencies (Medium, partially fixed)
`next` is a caret range, and Next 14 has had security releases (for example CVE-2025-29927, which affects middleware; this app has none). A `package-lock.json` has now been generated, resolving `next` 14.2.35, and CI uses `npm ci`, so builds are reproducible. Still open: commit the lockfile, enable `npm audit` / Dependabot, and plan an upgrade off the 14.x line.

### SR-20 — Logs (Low)
`/api/pipeline/{id}/logs` is anonymous, which SR-04 covers. Files in `LOG_DIR` are never deleted. Logs contain offsets, types and token IDs but no values, so the risk is mainly metadata. Add rotation or retention.

### SR-21 — Literal token strings in documents (Low)
A document can contain text such as `[TOKEN_PERSON_001]`. The validator treats it as an already-tokenised region, and any future detokenisation feature would replace it with a real vault value, which is a spoofing risk. Before detokenisation is built, escape or reject pre-existing token-shaped strings, or use per-run random token prefixes.

### SR-22 — Supply chain (Low)
GitHub Actions are pinned by tag, not commit SHA. `python:3.11-slim` is not pinned by digest. CI has no `pip-audit` or `npm audit` step.

### SR-23 — Comprehend processes raw text (Info)
Raw document text is sent to AWS Comprehend in the configured region. This is expected, but it should be part of the data-processing assessment. It is now stated in the README.

## Verified as not issues
- **Frontend XSS:** React escapes all rendered values, and there is no `dangerouslySetInnerHTML`. LLM output is rendered as plain text.
- **Promotion integrity:** promotion is a server-side `copy_object` of the scanned key, and keys are server-generated, so the scanned and promoted bytes cannot differ.
- **Logs endpoint path traversal:** `pipeline_id` is now validated as 32 hex characters before it is used in a path. Before the fix, the `pipeline-` prefix and the `.json` suffix already prevented a traversal.
- **Secrets:** no credentials in the repository. `.env` is ignored by both git and Docker.
