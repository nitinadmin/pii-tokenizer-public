# Changelog

## 1.1.0 — 2026-10-08

Security fixes from [docs/security-review.md](docs/security-review.md):

- **Breaking:** strict validation is server-side only; the `strict` query parameter on `/stream` was removed (SR-02).
- **Breaking:** the `tokens` SSE event no longer contains `original`; each token has a masked `preview` instead. The UI "Reveal originals" control was removed (SR-01).
- **Breaking:** pipeline IDs are 32 hex characters, and each upload can be streamed once; a concurrent second stream returns 409 (SR-06).
- **Breaking:** PDFs are extracted after the GuardDuty verdict; extracted text arrives in a new `document` SSE event instead of the upload response (SR-05).
- A failed detection engine now fails validation and halts strict mode (SR-03).
- A real pre-send PII check now runs before the LLM call (SR-09).
- Filenames are no longer used in S3 keys or logs (SR-07). Exception messages are no longer logged or returned (SR-11).
- Markdown code fences are now scanned (SR-08). Malware objects are purged across all versions (SR-10).
- GuardDuty `UNSUPPORTED` is reported as such (SR-15). Auto-created buckets get Block Public Access (SR-16). CORS tightened (SR-17).
- Docker: writable log directory for the non-root user, spaCy model installed, healthcheck added (SR-19).
- Docker: production frontend image (Next.js standalone, non-root); `docker compose up --build` now runs the whole app with no local Python or Node. Ports bound to `127.0.0.1`. CI builds both images.
- Default model updated to `claude-sonnet-5-5`.
- Explicit ruff rule set (CI lint was failing on newer ruff), `build` added to dev dependencies, CI uses `npm ci` with the lockfile.
- Added [docs/test-plan.md](docs/test-plan.md) and 26 new tests (31 total).

## 1.0.0

Initial release.


- Initial public packaging of the PII Tokenization Pipeline.
- Added `src/pii_tokenizer` package layout.
- Added `pyproject.toml` and console entry point.
- Added automated Python tests and GitHub Actions CI.
- Added deployment, architecture, contribution, and security documentation.
- Added container and Docker Compose support.
- Added safer default for S3 bucket provisioning.
- Added AWS SDK credential-chain support when explicit credentials are not configured.
