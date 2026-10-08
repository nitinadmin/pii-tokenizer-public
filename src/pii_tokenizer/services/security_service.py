import asyncio
import functools
import os
import re
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError

from pii_tokenizer.config import settings
from pii_tokenizer.services.logger_service import PipelineLogger

# ── XSS / injection patterns ────────────────────────────────────────────────
XSS_PATTERNS: list[tuple[str, str, int]] = [
    (r"<script[\s>]", "Inline <script> tag", 100),
    (r"</script>", "Closing </script> tag", 100),
    (r"javascript\s*:", "javascript: URI scheme", 90),
    (r"vbscript\s*:", "vbscript: URI scheme", 90),
    (r"data\s*:\s*text/html", "data:text/html payload", 85),
    (r"\bon\w+\s*=", "Inline event handler (onclick, onerror, …)", 80),
    (r"eval\s*\(", "eval() call", 90),
    (r"expression\s*\(", "CSS expression()", 80),
    (r"document\s*\.\s*cookie", "document.cookie access", 95),
    (r"document\s*\.\s*write", "document.write() call", 80),
    (r"document\s*\.\s*location", "document.location manipulation", 80),
    (r"window\s*\.\s*location", "window.location manipulation", 75),
    (r"innerHTML\s*=", "innerHTML assignment", 70),
    (r"<iframe[\s>]", "Embedded <iframe> tag", 90),
    (r"<embed[\s>]", "Embedded <embed> tag", 85),
    (r"<object[\s>]", "Embedded <object> tag", 85),
    (r"<svg[\s>].*?onload", "SVG with onload", 90),
    (r"<img[^>]+onerror", "Image with onerror handler", 85),
    (r"&#x[0-9a-fA-F]+;", "Hex-encoded HTML entity", 40),
    (r"%3[Cc]script", "URL-encoded <script>", 95),
    (r"fromCharCode", "String.fromCharCode (deobfuscation)", 70),
    (r"atob\s*\(", "Base64 decode via atob()", 65),
    (r"('\s*(OR|AND)\s+')", "SQL injection probe (string)", 50),
    (r"(--\s*$|;\s*DROP\s)", "SQL comment / DROP statement", 60),
    (r"UNION\s+SELECT", "UNION SELECT injection", 70),
]

XSS_BLOCK_THRESHOLD = 80

# Cap how many occurrences of one pattern count toward the score.
# Without this, a legitimate technical document that mentions `onclick=`
# twenty times in prose gets blocked. Three occurrences of a high-severity
# pattern is already conclusive; more adds no signal.
MAX_OCCURRENCES_COUNTED = 3


# ── PDF active-content threat patterns ──────────────────────────────────────
# PDFs are binary, so the text XSS scan doesn't apply. The PDF attack surface
# is active content: embedded JavaScript, launch actions (execute external
# programs), rich media. Scored like XSS patterns; raw-byte scan runs BEFORE
# any parsing so a malicious PDF is never handed to a parser.
# Note: /OpenAction and /AA appear in many benign PDFs (initial-view settings),
# so they score low on their own — they only block in combination with
# scripting markers.
PDF_THREAT_PATTERNS: list[tuple[bytes, str, int]] = [
    (rb"/JavaScript", "Embedded JavaScript action", 90),
    (rb"/JS\s*[(<\[]", "JavaScript code entry", 85),
    (rb"/Launch", "Launch action (executes external programs)", 95),
    (rb"/RichMedia", "Rich media (Flash) content", 80),
    (rb"/EmbeddedFile", "Embedded file attachment", 60),
    (rb"/XFA", "XFA forms (scripting-capable)", 50),
    (rb"/OpenAction", "Automatic open action", 25),
    (rb"/AA\b", "Additional (automatic) actions", 30),
]

PDF_MAGIC = b"%PDF"


def _is_pdf_filename(filename: str) -> bool:
    return filename.lower().endswith(".pdf")


DANGEROUS_MAGIC_BYTES: list[tuple[bytes, str]] = [
    (b"MZ", "Windows executable (PE/EXE/DLL)"),
    (b"\x7fELF", "Linux executable (ELF)"),
    (b"PK\x03\x04", "ZIP archive (could contain macros)"),
    (b"\xd0\xcf\x11\xe0", "OLE compound file (Office macro-enabled)"),
    (b"\x00\x00\x01\x00", "Windows icon file"),
    (b"\xca\xfe\xba\xbe", "Java class / macOS universal binary"),
    (b"Rar!", "RAR archive"),
    (b"\x1f\x8b", "Gzip archive"),
]

ALLOWED_EXTENSIONS = {".txt", ".csv", ".md", ".json", ".log", ".xml", ".tsv", ".pdf"}


@dataclass
class SecurityFinding:
    category: str       # "XSS", "MALWARE", "FILE_TYPE"
    severity: str       # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    description: str
    detail: str


@dataclass
class SecurityScanResult:
    passed: bool
    threat_score: int
    findings: list[SecurityFinding] = field(default_factory=list)
    guardduty_status: str = "PENDING"
    scanned_engines: list[str] = field(default_factory=list)


# ── Engine 1: File-type validation ──────────────────────────────────────────

def _validate_file_type(content: bytes, filename: str, log: PipelineLogger) -> list[SecurityFinding]:
    log.info("[SECURITY] Running file-type validation...")
    findings: list[SecurityFinding] = []

    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        findings.append(SecurityFinding(
            category="FILE_TYPE", severity="HIGH",
            description=f"Disallowed file extension: {ext}",
            detail=f"Allowed types: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        ))
        log.warn(f"[SECURITY] Blocked extension: {ext}")

    header = content[:8]
    is_pdf_name = _is_pdf_filename(filename)
    is_pdf_content = header[:len(PDF_MAGIC)] == PDF_MAGIC

    # Positive PDF validation: extension and content must AGREE.
    if is_pdf_name and not is_pdf_content:
        findings.append(SecurityFinding(
            category="FILE_TYPE", severity="CRITICAL",
            description="File claims .pdf but is not a PDF",
            detail="Header does not match the %PDF signature — possible disguised payload",
        ))
        log.warn("[SECURITY] .pdf extension with non-PDF content")
    elif is_pdf_content and not is_pdf_name:
        findings.append(SecurityFinding(
            category="FILE_TYPE", severity="CRITICAL",
            description="PDF content disguised with a non-.pdf extension",
            detail="Header matches %PDF but the filename claims a text format",
        ))
        log.warn("[SECURITY] PDF content with non-pdf extension")

    for magic, desc in DANGEROUS_MAGIC_BYTES:
        if header[:len(magic)] == magic:
            findings.append(SecurityFinding(
                category="FILE_TYPE", severity="CRITICAL",
                description=f"Binary file detected: {desc}",
                detail=f"File header matches {desc} signature",
            ))
            log.warn(f"[SECURITY] Dangerous file type: {desc}")
            break

    # Null-byte check only applies to text formats; PDFs are legitimately binary.
    if not (is_pdf_name and is_pdf_content) and b"\x00" in content[:4096]:
        findings.append(SecurityFinding(
            category="FILE_TYPE", severity="HIGH",
            description="Null bytes detected in file content",
            detail="File may be a binary disguised as text",
        ))
        log.warn("[SECURITY] Null bytes found — possible binary file")

    if not findings:
        log.info("[SECURITY] File-type validation: PASS")
    return findings


# ── Engine 2: XSS / injection deep scan ─────────────────────────────────────

def _scan_xss(content_text: str, filename: str, log: PipelineLogger) -> tuple[int, list[SecurityFinding]]:
    log.info("[SECURITY] Running XSS / injection deep scan...")

    # Markdown code fences are scanned like everything else: excluding them
    # let any payload through by wrapping it in ``` fences.
    scan_text = content_text

    findings: list[SecurityFinding] = []
    total_score = 0

    for pattern, desc, score in XSS_PATTERNS:
        matches = list(re.finditer(pattern, scan_text, re.IGNORECASE))
        if matches:
            counted = min(len(matches), MAX_OCCURRENCES_COUNTED)
            total_score += score * counted
            line_num = scan_text[:matches[0].start()].count("\n") + 1
            severity = ("CRITICAL" if score >= 90 else "HIGH" if score >= 70
                        else "MEDIUM" if score >= 50 else "LOW")
            findings.append(SecurityFinding(
                category="XSS", severity=severity, description=desc,
                detail=(f"First match at line {line_num}; {len(matches)} occurrence(s), "
                        f"{counted} counted toward score"),
            ))
            log.warn(f"[SECURITY] XSS pattern: {desc} (score +{score * counted}, line {line_num})")

    if total_score == 0:
        log.info("[SECURITY] XSS scan: PASS — no patterns detected")
    else:
        log.warn(f"[SECURITY] XSS scan: threat score {total_score} (block threshold: {XSS_BLOCK_THRESHOLD})")

    return total_score, findings


# ── Engine 2b: PDF active-content scan (raw bytes, pre-parse) ───────────────

def _scan_pdf_threats(content: bytes, log: PipelineLogger) -> tuple[int, list[SecurityFinding]]:
    """Scan raw PDF bytes for active-content markers. Runs BEFORE any PDF
    parsing so a malicious document never reaches a parser."""
    import re as _re
    log.info("[SECURITY] Running PDF active-content scan (raw bytes)...")
    findings: list[SecurityFinding] = []
    total_score = 0

    for pattern, desc, score in PDF_THREAT_PATTERNS:
        matches = _re.findall(pattern, content)
        if matches:
            counted = min(len(matches), MAX_OCCURRENCES_COUNTED)
            total_score += score * counted
            severity = ("CRITICAL" if score >= 90 else "HIGH" if score >= 70
                        else "MEDIUM" if score >= 50 else "LOW")
            findings.append(SecurityFinding(
                category="PDF_ACTIVE_CONTENT", severity=severity, description=desc,
                detail=f"{len(matches)} occurrence(s) in PDF structure, {counted} counted toward score",
            ))
            log.warn(f"[SECURITY] PDF threat: {desc} (score +{score * counted})")

    if total_score == 0:
        log.info("[SECURITY] PDF scan: PASS — no active content detected")
    else:
        log.warn(f"[SECURITY] PDF scan: threat score {total_score} (block threshold: {XSS_BLOCK_THRESHOLD})")

    return total_score, findings


# ── Fast scan (synchronous, runs in the upload request) ─────────────────────

def run_fast_scan(content: bytes, filename: str, log: PipelineLogger) -> SecurityScanResult:
    """File-type validation + XSS deep scan. Fast and CPU-only — safe to run
    inline in the upload request. GuardDuty runs separately (async) because
    it can take up to a minute."""

    log.info("=" * 60)
    log.info("[SECURITY] Starting fast security scan (file-type + XSS)...")
    # Extension only — filenames are attacker-controlled and often contain PII.
    ext = os.path.splitext(filename)[1].lower() or "(none)"
    log.info(f"[SECURITY] File type: {ext} ({len(content)} bytes)")
    log.info("=" * 60)

    findings: list[SecurityFinding] = []
    engines = ["File-type validator", "XSS / injection scanner"]

    findings.extend(_validate_file_type(content, filename, log))

    if _is_pdf_filename(filename):
        # Binary format: text XSS scan does not apply. Scan the raw bytes
        # for PDF active content (JavaScript, launch actions, rich media).
        engines[-1] = "PDF active-content scanner"
        xss_score, threat_findings = _scan_pdf_threats(content, log)
        findings.extend(threat_findings)
    else:
        try:
            text = content.decode("utf-8", errors="replace")
        except Exception:
            text = ""
        xss_score, xss_findings = _scan_xss(text, filename, log)
        findings.extend(xss_findings)

    has_critical = any(f.severity == "CRITICAL" for f in findings)
    has_high = any(f.severity == "HIGH" for f in findings)
    passed = not (has_critical or has_high or xss_score >= XSS_BLOCK_THRESHOLD)

    if passed:
        log.success(f"[SECURITY] Fast scan PASSED (XSS score: {xss_score}) — GuardDuty scan pending")
    else:
        log.error(f"[SECURITY] Fast scan BLOCKED — score {xss_score}, {len(findings)} finding(s)")

    return SecurityScanResult(
        passed=passed,
        threat_score=xss_score,
        findings=findings,
        guardduty_status="PENDING",
        scanned_engines=engines,
    )


# ── GuardDuty Malware Protection (async, fail-closed) ───────────────────────

async def scan_guardduty(s3_key: str, log: PipelineLogger) -> tuple[str, list[SecurityFinding]]:
    """Poll the quarantined S3 object's tags for GuardDuty's verdict.

    NON-BLOCKING: uses asyncio.sleep and runs boto3 calls in a thread
    executor, so the event loop stays responsive during the (up to 60s) wait.

    FAIL-CLOSED: if the scan never completes (GuardDuty not enabled, tag
    never appears, errors), the result is treated as a block unless
    GUARDDUTY_FAIL_OPEN=true is explicitly set for dev environments.
    """
    log.info("[SECURITY] Initiating GuardDuty Malware Protection scan...")
    findings: list[SecurityFinding] = []
    loop = asyncio.get_event_loop()

    kwargs = {"region_name": settings.AWS_REGION}
    if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
        kwargs.update(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        if settings.AWS_SESSION_TOKEN:
            kwargs["aws_session_token"] = settings.AWS_SESSION_TOKEN
    s3 = boto3.client("s3", **kwargs)
    bucket = settings.S3_BUCKET_NAME
    max_wait = settings.GUARDDUTY_MAX_WAIT
    poll_interval = 5
    elapsed = 0
    status = "PENDING"

    while elapsed < max_wait:
        try:
            get_tags = functools.partial(s3.get_object_tagging, Bucket=bucket, Key=s3_key)
            resp = await loop.run_in_executor(None, get_tags)
            tags = {t["Key"]: t["Value"] for t in resp.get("TagSet", [])}
            scan_tag = tags.get("GuardDutyMalwareScanStatus", "")

            if scan_tag == "NO_THREATS_FOUND":
                status = "CLEAN"
                log.success("[SECURITY] GuardDuty scan: NO THREATS FOUND")
                break
            elif scan_tag == "THREATS_FOUND":
                status = "THREAT"
                log.error("[SECURITY] GuardDuty scan: THREATS FOUND — blocking")
                findings.append(SecurityFinding(
                    category="MALWARE", severity="CRITICAL",
                    description="Malware detected by AWS GuardDuty",
                    detail=f"Object {s3_key} flagged as malicious",
                ))
                break
            elif scan_tag == "UNSUPPORTED":
                # Not blocked (the fast scan already restricts file types),
                # but reported honestly rather than as CLEAN.
                status = "UNSUPPORTED"
                log.warn("[SECURITY] GuardDuty: object type not scannable — proceeding "
                         "on fast-scan result only")
                break
            elif scan_tag == "FAILED":
                status = "ERROR"
                log.warn("[SECURITY] GuardDuty scan reported FAILED")
                break
        except ClientError as e:
            log.warn(f"[SECURITY] GuardDuty tag poll error: "
                     f"{e.response.get('Error', {}).get('Code', type(e).__name__)}")

        log.info(f"[SECURITY] GuardDuty scan in progress... ({elapsed}s / {max_wait}s)")
        await asyncio.sleep(poll_interval)
        elapsed += poll_interval

    if status == "PENDING":
        status = "TIMEOUT"
        log.warn("[SECURITY] GuardDuty scan timed out — "
                 "GuardDuty Malware Protection may not be enabled on this bucket")

    # ── FAIL-CLOSED enforcement ──
    if status in ("TIMEOUT", "ERROR"):
        if settings.GUARDDUTY_FAIL_OPEN:
            log.warn("[SECURITY] GUARDDUTY_FAIL_OPEN=true — proceeding WITHOUT malware verdict (dev mode)")
            status = "SKIPPED"
        else:
            log.error("[SECURITY] FAIL-CLOSED policy: GuardDuty verdict unavailable — blocking upload. "
                      "Set GUARDDUTY_FAIL_OPEN=true only for local dev without GuardDuty.")
            findings.append(SecurityFinding(
                category="MALWARE", severity="HIGH",
                description="Malware scan unavailable — blocked by fail-closed policy",
                detail=(f"GuardDuty verdict not received within {max_wait}s. "
                        "Enable GuardDuty Malware Protection on the bucket, "
                        "or set GUARDDUTY_FAIL_OPEN=true for local development."),
            ))
            status = "BLOCKED_UNAVAILABLE"

    return status, findings


def guardduty_verdict_blocks(status: str) -> bool:
    """True if this GuardDuty status should block the pipeline."""
    return status in ("THREAT", "BLOCKED_UNAVAILABLE")
