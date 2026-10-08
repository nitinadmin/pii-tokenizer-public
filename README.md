# PII Tokenizer

[![CI](https://github.com/YOUR_ORG/pii-tokenizer/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_ORG/pii-tokenizer/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**Security-first document processing that detects and replaces PII before content is sent to an LLM.**

PII Tokenizer is a full-stack reference implementation built around **FastAPI + Next.js**, with layered document security, Microsoft Presidio, regex detection, AWS Comprehend, AWS S3/GuardDuty, validation/remediation, and an Anthropic-compatible LLM integration.

> **Security notice:** This project is a reference implementation, not a certified compliance product. Do not assume that tokenization guarantees that a document contains no sensitive information. Perform your own threat modeling, testing, IAM review, dependency review, and compliance assessment before production use.

## Why this project

Sending customer or employee documents directly to an LLM can expose names, addresses, account identifiers, phone numbers, email addresses, and other sensitive data.

The pipeline follows a simple boundary:

**Upload → security gate → PII detection → tokenization → validation → LLM**

Only the validated tokenized representation should cross the LLM boundary.

## Architecture

```text
┌──────────────────┐        REST + SSE        ┌──────────────────────┐
│     Next.js      │ ◄──────────────────────► │       FastAPI        │
│   Web Console    │                           │      Pipeline        │
└──────────────────┘                           └──────────┬───────────┘
                                                         │
                   ┌─────────────────────────────────────┼────────────────────┐
                   │                                     │                    │
              ┌────▼─────┐                         ┌─────▼─────┐       ┌─────▼─────┐
              │ AWS S3   │                         │  Presidio │       │ AWS       │
              │ Quarantine│                        │  + Regex  │       │ Comprehend │
              └────┬─────┘                         └───────────┘       └───────────┘
                   │
              ┌────▼─────┐                         ┌─────────────┐
              │ GuardDuty│                         │ Anthropic   │
              │ Malware  │                         │ LLM         │
              └──────────┘                         └─────────────┘
```

## Security design

The pipeline includes multiple independent controls:

1. **Server-side upload limits.** Client-side controls are advisory only. Also cap the request body at your proxy, because the multipart body is received before the app checks its size.
2. **File-type validation.** Extension allow-list plus magic-byte checks detect disguised binaries.
3. **Text injection/XSS scanning.** Suspicious active-content patterns are scored and can block processing. Markdown code fences are scanned too.
4. **PDF active-content scanning.** Raw PDF bytes are inspected before anything parses them.
5. **GuardDuty Malware Protection.** Files wait in quarantine and fail closed by default. PDFs are parsed only after a non-blocking verdict, from the promoted object. A threat removes every version of the object. `UNSUPPORTED` verdicts proceed on the fast scan alone and are reported as such.
6. **S3 separation.** Data and token-vault buckets are distinct. Original values are written only to the vault and are never sent to the browser.
7. **Position-based replacement.** Avoids unsafe global string replacement during initial tokenization.
8. **Consistency pass.** Repeated detected values receive the same token.
9. **Residual validation and remediation.** The output is scanned again before the LLM step.
10. **Strict validation, set on the server.** With `STRICT_VALIDATION=true` (the default), the pipeline stops if validation fails or any detection engine is unavailable. Clients cannot override this.
11. **LLM boundary check.** Immediately before the call, the payload is checked again for known original values and PII patterns. In strict mode nothing is sent if any are found.
12. **PII-safe operational logs.** Logs record token IDs, types, offsets, engines and file extensions. They never include raw values, filenames or exception messages.
13. **Unguessable, single-use runs.** Pipeline IDs are 128-bit random values, and each upload can be streamed once.

### Important limitation

PII detection is probabilistic and incomplete. A document may contain sensitive information that the configured engines do not recognize. Residual validation only recognizes SSNs, emails, phone numbers, card numbers, IP addresses and repeats of values already detected. **A name or address that every engine misses will pass validation.** The application should therefore be treated as a **risk-reduction control**, not proof that a document is PII-free.

Raw document text is sent to AWS Comprehend in your configured region for detection. Include this in your data-processing assessment.

The API has **no authentication**. Until you put one in front of it, anyone who holds a pipeline ID can read that run's stream and logs. See [docs/security-review.md](docs/security-review.md) for open findings.

## Repository layout

```text
pii-tokenizer/
├── src/pii_tokenizer/
│   ├── main.py
│   ├── config.py
│   ├── models/
│   ├── routers/
│   └── services/
├── frontend/
├── tests/
├── docs/
│   ├── architecture.md
│   ├── deployment.md
│   ├── security-review.md
│   └── test-plan.md
├── .github/workflows/ci.yml
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
├── SECURITY.md
├── CONTRIBUTING.md
├── LICENSE
└── README.md
```

## Requirements

- Python 3.11+
- Node.js 18.17+ (CI uses 20)
- AWS account with S3 and AWS Comprehend
- AWS GuardDuty Malware Protection for S3 for the full security workflow
- Anthropic API key
- An English spaCy model supported by the installed Presidio/spaCy versions

## Quick start (Docker, recommended)

You need Docker with Compose v2. You don't need Python, Node or spaCy on your machine.

```bash
git clone https://github.com/YOUR_ORG/pii-tokenizer.git
cd pii-tokenizer
cp .env.example .env      # add your AWS settings and ANTHROPIC_API_KEY
docker compose up --build
```

Open `http://localhost:3000`. The API is at `http://localhost:8000` (OpenAPI at `/docs`).

- The first build downloads the spaCy model and takes several minutes. The API image is about 1.5 GB.
- Both ports are bound to `127.0.0.1`, so only this machine can reach the app. The API has no authentication; read [docs/deployment.md](docs/deployment.md) before exposing it.
- With no GuardDuty Malware Protection on your bucket, every upload is blocked after `GUARDDUTY_MAX_WAIT` (fail-closed). To try the app locally without GuardDuty, set `GUARDDUTY_FAIL_OPEN=true` in `.env`, and never do this in production.
- Logs persist in the `api_logs` volume. `docker compose down -v` removes it.
- After changing `.env`, run `docker compose up -d`. After changing code, add `--build`.

## Quick start (local development)

### 1. Clone and configure

```bash
git clone https://github.com/YOUR_ORG/pii-tokenizer.git
cd pii-tokenizer

cp .env.example .env
# Edit .env with your environment-specific values.
```

### 2. Install the Python package

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

Install the spaCy model required by your Presidio configuration. For the original configuration:

```bash
python -m spacy download en_core_web_lg
```

### 3. Start the API

```bash
uvicorn pii_tokenizer.main:app --reload --port 8000
```

API: `http://localhost:8000`  
Health: `http://localhost:8000/health`  
OpenAPI: `http://localhost:8000/docs`

### 4. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`.

### Container images

| Image | Built from | Runs as | Notes |
|---|---|---|---|
| API | [Dockerfile](Dockerfile) | UID 10001 | Includes `en_core_web_lg`; `/health` healthcheck; logs in `/app/logs` |
| Frontend | [frontend/Dockerfile](frontend/Dockerfile) | `node` | Production Next.js standalone server; no dev dependencies |

The frontend proxies `/api/*` to the API. Next.js fixes that address **at build time** through the `API_URL` build argument (default `http://api:8000`). If the API runs elsewhere, rebuild with `--build-arg API_URL=...`.

## Configuration

See `.env.example` for all supported settings.

### Production recommendations

- Set `AUTO_CREATE_BUCKETS=false`.
- Use IAM roles/workload identity rather than long-lived AWS access keys.
- Keep `GUARDDUTY_FAIL_OPEN=false`.
- Keep `STRICT_VALIDATION=true`.
- Use a dedicated token-vault bucket and a separate IAM role for detokenization.
- Restrict CORS to known application origins.
- Configure S3 Block Public Access, bucket policies, lifecycle rules, and encryption according to your organization's requirements.
- Grant the application role write-only access to the vault bucket, and give read access only to a separate, audited detokenization role.
- Put the API behind authentication, authorization, TLS, rate limiting, and request-size controls. `EventSource` cannot send headers, so authenticate the stream with a cookie or a short-lived signed URL.
- Consider AWS KMS rather than SSE-S3 if your threat model requires customer-managed keys.
- Do not use the local in-memory pipeline store as a multi-instance production job store.

## API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Liveness/health check |
| `POST` | `/api/upload` | Upload and perform the fast security gate |
| `GET` | `/api/pipeline/{id}/stream` | Run the pipeline and stream progress using SSE (once per upload) |
| `GET` | `/api/pipeline/{id}/logs` | Retrieve pipeline logs |

**Upload** returns `pipeline_id` (32 hex characters) and the fast-scan result. It returns 413 when the file exceeds `MAX_UPLOAD_SIZE_MB`, and 422 when the file is blocked; the 422 body has `message`, `pipeline_id`, `security` and `logs`.

**Stream** takes no query parameters. It returns 404 for an unknown or malformed ID, and 409 when the upload is already being processed. SSE events:

| Event | Data |
|---|---|
| `step` | `{step, status}`: steps `security`, `s3`, `tokenize`, `validate`, `llm`, `output`; statuses `running`, `complete`, `retrying`, `pass`, `fail`, `skipped` |
| `security` | `{security, blocked, s3_path}` |
| `document` | `{text}`: extracted PDF text (PDF uploads only) |
| `tokens` | `{tokens, tokenized_text}`: each token has `token`, `pii_type`, `label`, `engine`, `position`, `confidence` and a masked `preview`. Original values are never included. |
| `validation` | `{report}` |
| `summary` | `{summary}` |
| `done` | `{pipeline_id, logs, error?}` |

Interactive API documentation is available at `/docs`.

## Supported input

- Extensions: `.txt .csv .md .json .log .xml .tsv .pdf`. Text must be UTF-8.
- PDFs must contain extractable text. Scanned (image-only) and password-protected PDFs are rejected; OCR is not included.
- Detection is configured for English.
- Documents longer than spaCy's 1,000,000-character limit cause a Presidio failure, which halts the pipeline in strict mode.

## Data stored

| Location | Content | Cleanup |
|---|---|---|
| Data bucket `quarantine/{id}/` | Raw upload until the malware verdict | Removed on promotion or block; also when the stream ends early or the TTL expires |
| Data bucket `uploads/{id}/` | Raw upload after the scan | Your lifecycle rules |
| Data bucket `tokenized/`, `summaries/`, `logs/` | Tokenized text, LLM summary, run log | Your lifecycle rules |
| Vault bucket `vault/{id}/token-map.json` | Original values and their tokens | Your lifecycle rules |
| `LOG_DIR` on the API host | Run logs (no values) | Not cleaned up automatically |
| API process memory | Upload text until the stream ends | Dropped at stream end or after `UPLOAD_TTL_SECONDS` |

S3 keys use `document.<ext>`; client filenames are never stored.

## Development

Run the test suite (offline; AWS, Presidio and the LLM are faked):

```bash
pytest
```

[docs/test-plan.md](docs/test-plan.md) maps each test to the requirement it covers, and lists the manual AWS and detection-accuracy checks to run before a release.

Run linting:

```bash
ruff check src tests
```

Run coverage:

```bash
pytest --cov
```

Build the package:

```bash
python -m build
```

## Frontend

The frontend is intentionally kept separate from the Python distribution. It provides:

- drag-and-drop upload
- security scan results
- tokenized document view
- token map (masked previews only)
- validation report
- LLM summary
- pipeline logs
- SSE progress

## AWS architecture notes

The application expects the following logical storage boundaries:

- **Data bucket:** quarantine objects, promoted uploads, summaries, operational logs.
- **Token vault bucket:** PII-to-token mappings. This bucket should have tighter IAM controls than the data bucket.
- **GuardDuty Malware Protection:** scans objects while they remain in the quarantine prefix.

See [docs/deployment.md](docs/deployment.md) for a deployment checklist, [docs/architecture.md](docs/architecture.md) for design details, and [docs/security-review.md](docs/security-review.md) for the security review.

## Responsible disclosure

Please do not report security vulnerabilities through public GitHub issues. Follow the process in [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
