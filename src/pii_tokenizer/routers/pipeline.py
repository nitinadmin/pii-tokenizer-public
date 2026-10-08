import asyncio
import json
import os
import re
import secrets
import time

from fastapi import APIRouter, File, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from pii_tokenizer.config import settings
from pii_tokenizer.models.schemas import (
    SecurityFinding as SecurityFindingSchema,
)
from pii_tokenizer.models.schemas import (
    SecurityScanResponse,
    TokenEntry,
    UploadResponse,
    ValidationCheck,
    ValidationReport,
)
from pii_tokenizer.services import (
    llm_service,
    pdf_service,
    s3_service,
    security_service,
    tokenizer_service,
    validator_service,
)
from pii_tokenizer.services.logger_service import PipelineLogger

router = APIRouter(prefix="/api", tags=["pipeline"])

# In-memory store for active pipeline runs (LOCAL DEV ONLY — lost on restart).
# Entries are evicted after UPLOAD_TTL_SECONDS; stale quarantine objects are
# deleted on eviction so they don't accumulate in S3.
_uploads: dict[str, dict] = {}

# Pipeline IDs are 128-bit random values. Until an authentication layer is in
# front of the API, the ID is the only thing that gates the stream and logs,
# so it must be unguessable and is validated before touching the filesystem.
PIPELINE_ID_RE = re.compile(r"[0-9a-f]{32}")


def _require_valid_id(pipeline_id: str) -> None:
    if not PIPELINE_ID_RE.fullmatch(pipeline_id):
        raise HTTPException(404, "Pipeline ID not found.")


def _object_name(filename: str) -> str:
    """Name used for S3 keys. Built from the (allow-listed) extension only:
    the client's filename is attacker-controlled and often contains PII
    (``jane_doe_w2.pdf``), so it never reaches S3 keys or logs."""
    return f"document{os.path.splitext(filename)[1].lower()}"


def _evict_stale_uploads(log: PipelineLogger | None = None):
    now = time.time()
    stale = [
        pid for pid, meta in _uploads.items()
        if now - meta.get("created_at", now) > settings.UPLOAD_TTL_SECONDS
    ]
    for pid in stale:
        meta = _uploads.pop(pid, None)
        if meta and meta.get("quarantine_key") and not meta.get("promoted"):
            try:
                cleanup_log = log or PipelineLogger(pid)
                s3_service.delete_object(meta["quarantine_key"], cleanup_log)
            except Exception:
                pass


def _scan_to_schema(scan) -> SecurityScanResponse:
    return SecurityScanResponse(
        passed=scan.passed,
        threat_score=scan.threat_score,
        findings=[
            SecurityFindingSchema(
                category=f.category, severity=f.severity,
                description=f.description, detail=f.detail,
            )
            for f in scan.findings
        ],
        guardduty_status=scan.guardduty_status,
        scanned_engines=scan.scanned_engines,
    )


def _client_tokens(tokens: list[TokenEntry]) -> list[dict]:
    """Token map as sent to the browser: original values are replaced by a
    masked preview. Originals live only in the vault bucket."""
    return [
        {**t.model_dump(exclude={"original"}), "preview": validator_service.mask_value(t.original)}
        for t in tokens
    ]


def _apply_engine_check(report: ValidationReport, failed_engines: list[str]) -> None:
    """A failed detection engine means part of the document was never
    scanned, which the residual validator cannot detect on its own."""
    passed = not failed_engines
    report.checks.append(ValidationCheck(name="All detection engines completed", passed=passed))
    if not passed:
        report.issues.append(f"Detection engine(s) unavailable: {', '.join(failed_engines)}")
        report.overall_status = "FAIL"


@router.post("/upload", response_model=UploadResponse)
async def upload_file(file: UploadFile = File(...)):
    """Receive a file, run the FAST security checks (file-type + XSS), and
    stage it in S3 quarantine. The slow GuardDuty malware scan — and PDF
    parsing, which must wait for its verdict — run in the SSE stream.

    Server-side size limit is enforced here — the client-side limit is
    advisory only and trivially bypassed. The multipart body has already been
    received by this point, so also cap request size at the proxy."""
    if not file.filename:
        raise HTTPException(400, "No file provided")

    max_bytes = settings.MAX_UPLOAD_SIZE_MB * 1024 * 1024
    content = await file.read(max_bytes + 1)
    if len(content) == 0:
        raise HTTPException(400, "Empty file")
    if len(content) > max_bytes:
        raise HTTPException(413, f"File exceeds the {settings.MAX_UPLOAD_SIZE_MB} MB limit")

    pipeline_id = secrets.token_hex(16)
    log = PipelineLogger(pipeline_id)
    _evict_stale_uploads(log)

    log.info(f"[UPLOAD] Receiving file ({len(content) / 1024:.1f} KB)")

    # ── Fast scan (sync, cheap): file-type + XSS. Hard-block here. ──
    loop = asyncio.get_event_loop()
    scan = await loop.run_in_executor(
        None, security_service.run_fast_scan, content, file.filename, log
    )
    scan_response = _scan_to_schema(scan)

    if not scan.passed:
        log.error(f"[UPLOAD] BLOCKED — fast security scan failed ({len(scan.findings)} findings)")
        log.save()
        raise HTTPException(
            status_code=422,
            detail={
                "message": "File blocked by security scan",
                "pipeline_id": pipeline_id,
                "security": scan_response.model_dump(),
                "logs": [e.model_dump() for e in log.get_entries()],
            },
        )

    # ── Stage in quarantine. GuardDuty verdict comes later, in the stream. ──
    is_pdf = file.filename.lower().endswith(".pdf")
    object_name = _object_name(file.filename)
    await loop.run_in_executor(None, s3_service.ensure_all_buckets, log)
    quarantine_key = f"quarantine/{pipeline_id}/{object_name}"
    s3_path = await loop.run_in_executor(
        None, s3_service.upload_file, quarantine_key, content, log
    )
    log.success("[UPLOAD] File staged in quarantine — awaiting malware scan")

    _uploads[pipeline_id] = {
        "quarantine_key": quarantine_key,
        "object_name": object_name,
        "is_pdf": is_pdf,
        # PDFs are NOT parsed here: extraction runs on the promoted object
        # only after GuardDuty has cleared it.
        "text": None if is_pdf else content.decode("utf-8", errors="replace"),
        "s3_path": s3_path,
        "fast_scan": scan,
        "created_at": time.time(),
        "promoted": False,
        "started": False,
    }

    return UploadResponse(
        pipeline_id=pipeline_id,
        file_key=quarantine_key,
        file_name=file.filename,
        file_size=len(content),
        s3_path=s3_path,
        security=scan_response,
    )


@router.get("/pipeline/{pipeline_id}/stream")
async def run_pipeline_stream(pipeline_id: str):
    """Run security (GuardDuty) → promote → extract → tokenize →
    validate/remediate → LLM → output, streaming progress via SSE.

    Strict validation is a SERVER setting (STRICT_VALIDATION) and cannot be
    changed per request. Each upload can be streamed exactly once; its
    in-memory state is dropped when the stream ends.

    Heavy synchronous work (Presidio, Comprehend, Claude API) runs in a
    thread executor so the event loop — and every other request — stays
    responsive."""
    _require_valid_id(pipeline_id)
    meta = _uploads.get(pipeline_id)
    if not meta:
        raise HTTPException(404, "Pipeline ID not found. Upload a file first.")
    if meta["started"]:
        raise HTTPException(409, "This upload has already been processed. Upload the file again.")
    meta["started"] = True

    async def event_generator():
        try:
            async for event in _pipeline_events(pipeline_id, meta, settings.STRICT_VALIDATION):
                yield event
        finally:
            _uploads.pop(pipeline_id, None)
            if not meta["promoted"]:
                # Client went away (or the run failed) before promotion: don't
                # leave the object in quarantine. Fire-and-forget so a
                # cancelled generator doesn't block the event loop.
                asyncio.get_event_loop().run_in_executor(
                    None, s3_service.delete_object, meta["quarantine_key"],
                    PipelineLogger(pipeline_id),
                )

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


async def _pipeline_events(pipeline_id: str, meta: dict, strict_mode: bool):
    loop = asyncio.get_event_loop()
    log = PipelineLogger(pipeline_id)
    object_name = meta["object_name"]
    fast_scan = meta["fast_scan"]

    def send(event_type: str, data: dict) -> str:
        return f"event: {event_type}\ndata: {json.dumps(data)}\n\n"

    def halt(message: str, skipped_step: str, error: str | None = None):
        log.error(message)
        log.save()
        yield send("step", {"step": skipped_step, "status": "skipped"})
        yield send("done", {
            "pipeline_id": pipeline_id,
            "error": error,
            "logs": [e.model_dump() for e in log.get_entries()],
        })

    # ── Step: GuardDuty malware scan (async, fail-closed) ──
    yield send("step", {"step": "security", "status": "running"})

    gd_status, gd_findings = await security_service.scan_guardduty(
        meta["quarantine_key"], log
    )

    combined = security_service.SecurityScanResult(
        passed=fast_scan.passed and not security_service.guardduty_verdict_blocks(gd_status),
        threat_score=fast_scan.threat_score + sum(
            100 for f in gd_findings if f.severity == "CRITICAL"
        ),
        findings=fast_scan.findings + gd_findings,
        guardduty_status=gd_status,
        scanned_engines=fast_scan.scanned_engines + ["AWS GuardDuty Malware Protection"],
    )
    scan_schema = _scan_to_schema(combined)

    if security_service.guardduty_verdict_blocks(gd_status):
        # Remove every version of the quarantined object and halt — hard block.
        await loop.run_in_executor(
            None, s3_service.purge_object, meta["quarantine_key"], log
        )
        meta["promoted"] = True  # nothing left in quarantine to clean up
        log.error("[PIPELINE] Halted — file blocked at malware scan")
        log.save()
        yield send("security", {
            "security": scan_schema.model_dump(), "blocked": True, "s3_path": None,
        })
        yield send("step", {"step": "security", "status": "fail"})
        yield send("done", {
            "pipeline_id": pipeline_id,
            "logs": [e.model_dump() for e in log.get_entries()],
        })
        return

    # ── Promote quarantine → uploads via server-side copy ──
    final_key = f"uploads/{pipeline_id}/{object_name}"
    s3_path = await loop.run_in_executor(
        None, s3_service.promote_object, meta["quarantine_key"], final_key, log
    )
    meta["promoted"] = True

    yield send("security", {
        "security": scan_schema.model_dump(), "blocked": False, "s3_path": s3_path,
    })
    yield send("step", {"step": "security", "status": "complete"})
    yield send("step", {"step": "s3", "status": "complete"})

    # ── PDF text extraction — only now, on the exact bytes GuardDuty cleared ──
    text = meta["text"]
    if meta["is_pdf"]:
        try:
            content = await loop.run_in_executor(None, s3_service.download_bytes, final_key)
            text = await loop.run_in_executor(None, pdf_service.extract_text, content, log)
        except pdf_service.PDFExtractionError as e:
            for event in halt(f"[PIPELINE] Halted — PDF extraction failed: {e}", "tokenize",
                              error=str(e)):
                yield event
            return
        yield send("document", {"text": text})

    # ── Step: tokenize (heavy — run in executor) ──
    yield send("step", {"step": "tokenize", "status": "running"})

    tokenized_text, tokens, failed_engines = await loop.run_in_executor(
        None, tokenizer_service.tokenize_document, text, log
    )

    # Same value -> same token everywhere: catches undetected repeat
    # occurrences of already-detected values before validation runs.
    tokenized_text, _ = await loop.run_in_executor(
        None, tokenizer_service.consistency_pass, tokenized_text, tokens, log
    )

    yield send("step", {"step": "tokenize", "status": "complete"})
    yield send("tokens", {
        "tokens": _client_tokens(tokens),
        "tokenized_text": tokenized_text,
    })

    # ── Step: validate, with DIRECT REMEDIATION on failure ──
    yield send("step", {"step": "validate", "status": "running"})

    report = await loop.run_in_executor(
        None, validator_service.validate_tokenization,
        text, tokenized_text, tokens, log, 1,
    )

    if report.overall_status == "FAIL":
        log.warn(f"[VALIDATION] Pass 1 FAILED — {report.missed} issue(s)")
        yield send("step", {"step": "validate", "status": "retrying"})

        # The validator knows the exact residual spans — tokenize them
        # directly instead of re-running the same engines and hoping.
        spans = validator_service.find_residual_spans(tokenized_text)
        if spans:
            tokenized_text, tokens = tokenizer_service.remediate_residuals(
                tokenized_text, spans, tokens, log
            )
        tokenized_text, _ = await loop.run_in_executor(
            None, tokenizer_service.consistency_pass, tokenized_text, tokens, log
        )
        yield send("tokens", {
            "tokens": _client_tokens(tokens),
            "tokenized_text": tokenized_text,
        })

        report = await loop.run_in_executor(
            None, validator_service.validate_tokenization,
            text, tokenized_text, tokens, log, 2,
        )

    _apply_engine_check(report, failed_engines)

    yield send("step", {"step": "validate", "status": report.overall_status.lower()})
    yield send("validation", {"report": report.model_dump()})

    if report.overall_status != "PASS":
        if strict_mode:
            for event in halt(
                "[PIPELINE] Halted — validation failed "
                f"({len(report.issues)} issue(s), {len(report.residual_details)} residual "
                "location(s); see validation report). Manual review required.",
                "llm",
            ):
                yield event
            return
        log.warn(
            "[PIPELINE] NON-STRICT MODE (STRICT_VALIDATION=false): continuing despite "
            f"{len(report.issues)} validation issue(s). "
            "The document sent to the LLM may contain un-tokenized PII."
        )

    # ── Store tokenized output + vault AFTER validation passes ──
    tok_name = f"{object_name}.txt" if meta["is_pdf"] else object_name
    tok_key = f"tokenized/{pipeline_id}/{tok_name}"
    await loop.run_in_executor(
        None, s3_service.upload_text, tok_key, tokenized_text, log
    )

    # Token vault → SEPARATE bucket. Reading the tokenized output must
    # not grant the ability to reverse it.
    vault_key = f"vault/{pipeline_id}/token-map.json"
    await loop.run_in_executor(
        None, s3_service.upload_json, vault_key,
        {"tokens": [t.model_dump() for t in tokens]},
        log, settings.S3_VAULT_BUCKET_NAME,
    )
    log.info(f"[VAULT] Token map stored in dedicated vault bucket: "
             f"s3://{settings.S3_VAULT_BUCKET_NAME}/{vault_key}")

    # ── Step: LLM summary (network-bound — executor) ──
    yield send("step", {"step": "llm", "status": "running"})

    try:
        summary = await loop.run_in_executor(
            None, llm_service.generate_summary, tokenized_text, tokens, log, strict_mode
        )
    except llm_service.LLMBoundaryError:
        for event in halt("[PIPELINE] Halted — raw PII detected in LLM payload", "llm"):
            yield event
        return
    yield send("step", {"step": "llm", "status": "complete"})
    yield send("summary", {"summary": summary})

    # ── Step: output ──
    yield send("step", {"step": "output", "status": "running"})
    summary_key = f"summaries/{pipeline_id}/summary.md"
    await loop.run_in_executor(
        None, s3_service.upload_text, summary_key, summary, log
    )
    log_key = f"logs/{pipeline_id}/activity.json"
    log.save()
    await loop.run_in_executor(
        None, s3_service.upload_json, log_key,
        {"entries": [e.model_dump() for e in log.get_entries()]}, log,
    )
    log.success("[OUTPUT] All artifacts stored")

    yield send("step", {"step": "output", "status": "complete"})
    yield send("done", {
        "pipeline_id": pipeline_id,
        "logs": [e.model_dump() for e in log.get_entries()],
    })


@router.get("/pipeline/{pipeline_id}/logs")
async def get_logs(pipeline_id: str):
    _require_valid_id(pipeline_id)
    log_path = settings.LOG_DIR / f"pipeline-{pipeline_id}.json"
    if not log_path.exists():
        raise HTTPException(404, "Log file not found")
    return json.loads(log_path.read_text())
