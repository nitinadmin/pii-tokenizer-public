# Test plan

This plan lists what must be true for the PII Tokenizer to be safe to run. For each requirement it gives the test that proves it, and says whether that test is automated. Test IDs appear as comments in the test files, so `grep -rn TP-STRICT-02 tests/` finds the implementation.

## Requirements under test

| Req | Requirement |
|---|---|
| R1 | Only validated, tokenised text crosses the LLM boundary while `STRICT_VALIDATION=true`, and no client can change that. |
| R2 | Original PII values are stored only in the vault bucket. They are never sent to the browser or written to logs, data-bucket objects or S3 keys. |
| R3 | Files are scanned (fast scan, then GuardDuty) before they are parsed or processed, and the malware gate fails closed. |
| R4 | Any degraded detection (a failed engine, or residuals after remediation) is reported and halts the pipeline in strict mode. |
| R5 | Pipeline runs cannot be enumerated or replayed. |
| R6 | Inputs are limited in size and type on the server. |
| R7 | Temporary data (quarantine objects, in-memory text) is cleaned up. |

## Levels and environments

| Level | Runs where | External services | Command |
|---|---|---|---|
| Unit and API (automated) | Developer machine, CI | None. S3, GuardDuty, Comprehend, Presidio and Anthropic are faked in [tests/conftest.py](../tests/conftest.py) | `pytest` |
| Build (automated/manual) | CI, release | Package registries | `npm run build`, `docker build .` |
| AWS integration (manual, before each release) | Dedicated non-production AWS account | Real S3, GuardDuty, Comprehend | See checklist below |
| Detection accuracy (manual, on engine or model changes) | Developer machine with spaCy model | Presidio, Comprehend | Labelled synthetic corpus |

Never use real customer documents in any test. Use only synthetic PII, such as `123-45-6789` and `jane@example.com`.

## Automated test cases

| ID | Req | Case | Expected | Test |
|---|---|---|---|---|
| TP-API-01 | — | `GET /health` | 200 `{"status":"ok"}` | `test_api.py::test_health_endpoint` |
| TP-FLOW-01 | R1 | Happy path, text file | Pipeline completes; LLM payload contains tokens and no raw values | `test_pipeline.py::test_happy_path_sends_only_tokenized_text_to_llm` |
| TP-STRICT-01 | R1 | Client sends `?strict=false` while the server is strict | Ignored; LLM step skipped on failure | `test_strict_query_parameter_cannot_disable_strict_mode` |
| TP-STRICT-02 | R1, R4 | Comprehend fails | Validation FAIL with "All detection engines completed" check; nothing written to vault or tokenized prefixes; no LLM call | `test_failed_detection_engine_halts_in_strict_mode` |
| TP-STRICT-03 | R1 | Server configured `STRICT_VALIDATION=false`, validation fails | Continues; NON-STRICT warning logged | `test_non_strict_server_setting_continues_with_warning` |
| TP-LLM-01 | R1 | Payload with a known original or SSN pattern | `LLMBoundaryError`; LLM client never constructed | `test_tokenizer.py::test_llm_boundary_blocks_raw_pii_before_any_call` |
| TP-LEAK-01 | R2 | Token events on the stream | No `original` field; masked `preview` only; final tokenised text clean | `test_token_map_originals_never_sent_to_client` |
| TP-LEAK-02 | R2 | Filename containing a name | Absent from S3 keys, stream and saved log; fast scan logs extension only | `test_filename_not_in_s3_keys_or_logs`, `test_security.py::test_fast_scan_logs_extension_not_filename` |
| TP-LEAK-03 | R2 | Tokenizer log lines | Contain no detected values | `test_tokenizer_logs_never_contain_values` |
| TP-LEAK-04 | R2 | LLM exception containing document text | Message not logged or returned | `test_llm_error_message_not_echoed` |
| TP-DATA-02 | R2 | Storage split | Vault object holds originals; tokenized object does not | `test_vault_holds_originals_and_is_separate` |
| TP-MAL-01 | R3 | GuardDuty `THREAT` | Quarantine object purged; not promoted; pipeline halts | `test_guardduty_threat_purges_and_halts` |
| TP-MAL-02 | R3 | PDF upload | Not parsed at upload; parsed only after GuardDuty and promotion; never parsed when blocked | `test_pdf_is_parsed_only_after_guardduty_clears_it`, `test_pdf_not_parsed_when_guardduty_blocks` |
| TP-MAL-03 | R3 | GuardDuty tag values | `NO_THREATS_FOUND`→CLEAN, `THREATS_FOUND`→THREAT (blocks), `UNSUPPORTED`→UNSUPPORTED (does not block) | `test_security.py::test_guardduty_verdicts` |
| TP-MAL-04 | R3 | No verdict within `GUARDDUTY_MAX_WAIT` | Blocks by default; `SKIPPED` only with `GUARDDUTY_FAIL_OPEN=true` | `test_guardduty_fails_closed_without_verdict` |
| TP-INPUT-01 | R6 | Upload of limit+1 bytes / exactly limit | 413 / 200 | `test_upload_size_limit_enforced_server_side` |
| TP-INPUT-02 | R6 | Disallowed extension; PDF bytes named `.txt` | Blocked | `test_disallowed_extension_is_blocked`, `test_disguised_pdf_is_blocked` |
| TP-INPUT-03 | R6 | `<script>` payload, including inside a Markdown code fence | Blocked | `test_script_payload_is_blocked`, `test_markdown_code_fence_does_not_hide_payload` |
| TP-INPUT-04 | R3, R6 | PDF containing `/JavaScript` | Blocked with `PDF_ACTIVE_CONTENT` finding | `test_pdf_with_javascript_is_blocked` |
| TP-INPUT-05 | R6 | Plain benign text | Passes fast scan | `test_text_file_passes_basic_security_scan` |
| TP-DETECT-01 | R4 | Repeated detected value | Every occurrence gets the same token | `test_consistency_pass_reuses_existing_token` |
| TP-DETECT-02 | R4 | Engine raises with partial results | Engine reported as failed; partial and other engines' detections still applied | `test_failed_engine_is_reported_and_partial_results_kept` |
| TP-ACCESS-01 | R5 | Pipeline ID format | 32 lowercase hex characters (128 bits) | `test_pipeline_id_is_128_bit_hex` |
| TP-ACCESS-02 | R5, R7 | Second stream of the same upload | 404/409; in-memory text dropped; concurrent second stream gets 409 | `test_stream_is_single_use`, `test_concurrent_second_stream_is_rejected` |
| TP-ACCESS-03 | R5 | Malformed IDs on `/stream` and `/logs` | 404 without filesystem access | `test_malformed_pipeline_ids_rejected` |
| TP-DATA-01 | R7 | Upload never streamed, TTL expires | Quarantine object deleted | `test_unstarted_upload_cleaned_from_quarantine_on_ttl` |

## Build checks

| ID | Check | How | Status |
|---|---|---|---|
| TP-BUILD-01 | Frontend builds | `cd frontend && npm run build` (CI job `frontend`) | Automated in CI |
| TP-BUILD-02 | API and frontend images build | CI job `docker` (`docker build` for both images) | Automated in CI |
| TP-BUILD-04 | Stack starts: API healthy and running as UID 10001, frontend serves `/`, and SSE events arrive one by one through the frontend proxy | `docker compose up --build`, then `docker compose ps` (both healthy), `docker compose exec api id -u` returns `10001`, and run one document end to end in the UI | Manual |
| TP-BUILD-03 | Lint | `ruff check src tests` | Automated in CI |

## AWS integration checklist (manual, before each release)

Run these in a non-production account, with the IAM policies from [deployment.md](deployment.md).

| ID | Case | Expected |
|---|---|---|
| TP-AWS-01 | Upload the EICAR test file renamed `.txt` | GuardDuty tags `THREATS_FOUND`; pipeline halts; object gone from `quarantine/` |
| TP-AWS-02 | Upload a clean file with GuardDuty Malware Protection disabled | Blocks after `GUARDDUTY_MAX_WAIT` (fail-closed) |
| TP-AWS-03 | After TP-AWS-01, `aws s3api list-object-versions --prefix quarantine/<id>/` | No versions or delete markers remain |
| TP-AWS-04 | Run with the application role and try `s3:GetObject` on the vault bucket from the data-plane role | Denied (vault separation is enforced by IAM, not by the app) |
| TP-AWS-05 | Revoke `comprehend:DetectPiiEntities` and run a document | Validation FAIL, "All detection engines completed" false, no LLM call |
| TP-AWS-06 | `AUTO_CREATE_BUCKETS=true` in a fresh account | Both buckets have Block Public Access, SSE and versioning |

## Detection accuracy (manual, on engine, model or pattern changes)

| ID | Case | Expected |
|---|---|---|
| TP-DETECT-03 | Run a labelled synthetic corpus (names, addresses, IDs, mixed formats, PDFs) and compute recall per PII type | Recall for each type at or above the agreed baseline; any regression blocks the change. Record results in the PR. |
| TP-PERF-01 | Text longer than 1,000,000 characters (spaCy `max_length`) | Presidio reported as a failed engine; strict mode halts (no crash) |

## Known gaps

- No automated frontend tests. The masked token map and the removed strict toggle are covered by API tests only.
- AWS behaviour (GuardDuty tagging, IAM denial, version purge) is checked only manually.
- Detection quality has no automated baseline. TP-DETECT-03 needs a corpus to be created and versioned.
- Authentication, rate limiting and the durable job store are deployment concerns ([security-review.md](security-review.md) SR-04, SR-12), so this plan does not cover them.

## Exit criteria for a release

1. `pytest` and `ruff check src tests` pass in CI.
2. TP-BUILD-01, TP-BUILD-02 and TP-BUILD-04 pass.
3. TP-AWS-01 to TP-AWS-06 pass in the integration account.
4. TP-DETECT-03 has been run if detection code, engines or models changed.
5. No open Critical or High findings in [security-review.md](security-review.md) other than those accepted as deployment responsibilities.
