# Architecture

## Trust boundaries

The most important trust boundary is the transition from raw document content to the tokenized document sent to the LLM.

```text
Untrusted upload
      |
      v
+--------------------+
| Size / file type   |   upload request: no parsing; text files decoded,
| active content     |   PDFs scanned as raw bytes only
+--------------------+
      |
      v
+--------------------+
| S3 quarantine      |   fail-closed: no verdict = blocked
| + GuardDuty        |   threat = every object version purged
+--------------------+
      |  promoted by server-side copy
      v
+--------------------+
| PDF extraction     |   parses the promoted (scanned) bytes only
+--------------------+
      |
      v
+--------------------+
| PII detection      |   any failed engine is reported
| Presidio           |
| Regex              |
| Comprehend (AWS)   |   receives raw text
+--------------------+
      |
      v
+--------------------+
| Validation         |
| + remediation      |
+--------------------+
      |
      |  PASS (or STRICT_VALIDATION=false on the server)
      v
+--------------------+
| Vault + tokenized  |
| output to S3       |
+--------------------+
      |
      v
+--------------------+
| LLM boundary check |   known originals + PII patterns; strict = refuse
+--------------------+
      |
      v
+--------------------+
| LLM                |
| tokenized text     |
+--------------------+
```

Strict mode is a server setting. No request parameter changes it.

## What the browser receives

The SSE stream is the uploader's channel. It carries the document (extracted PDF text, and tokenized text including intermediate versions), validation reports with masked previews, and the token list with **masked previews only**. The original-to-token mapping is never sent to the browser.

Until the API has authentication, the 128-bit pipeline ID is the only thing that gates the stream and logs. Each upload can be streamed once.

## Token vault

A token entry contains the original value and metadata. The vault therefore has materially higher sensitivity than tokenized output. The application writes it but never reads it back.

Recommended production model:

- data-plane role: read/write uploads and tokenized artifacts
- vault role: **write-only** to token mappings (the application)
- detokenization role: tightly controlled and audited (no detokenization feature exists yet; see security review SR-21 before building one)
- application users: no direct S3 access

## Current application state

Pipeline metadata, including the upload's raw text, is stored in process memory until the stream ends or `UPLOAD_TTL_SECONDS` passes. This is suitable for a demo or single-instance deployment. For production, replace it with a durable job/state store and an authenticated job model that binds each pipeline to its uploader.

## LLM boundary

The application should treat the tokenized document as the only permitted payload to the LLM. The document is wrapped in `<document>` tags, and the model is told to treat it as untrusted data. The model has no tools. Any future feature that adds document context, retrieval, tools or agent actions should preserve this boundary explicitly and keep the pre-send check in `llm_service.generate_summary`.
