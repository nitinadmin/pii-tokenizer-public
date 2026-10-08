import re
from dataclasses import dataclass

import boto3

from pii_tokenizer.config import settings
from pii_tokenizer.models.schemas import TokenEntry
from pii_tokenizer.services.logger_service import PipelineLogger

# ---------------------------------------------------------------------------
# Presidio setup (lazy-loaded so import errors surface at call time)
# ---------------------------------------------------------------------------
_presidio_analyzer = None


def _get_presidio():
    global _presidio_analyzer
    if _presidio_analyzer is None:
        from presidio_analyzer import AnalyzerEngine
        _presidio_analyzer = AnalyzerEngine()
    return _presidio_analyzer


REGEX_PATTERNS = [
    ("SSN", r"\b\d{3}-\d{2}-\d{4}\b", "Social Security Number"),
    ("PHONE", r"\b(?:\+1[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b", "Phone Number"),
    ("ZIPCODE", r"\b\d{5}(?:-\d{4})?\b", "ZIP Code"),
    ("IP_ADDRESS", r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b", "IP Address"),
]

TOKEN_ID_RE = re.compile(r"\[TOKEN_([A-Z_]+)_(\d{3})\]")


class EngineUnavailableError(Exception):
    """A detection engine failed. Its coverage is missing from the result, so
    the caller must treat the tokenization as incomplete. Any detections the
    engine did produce are carried on the exception so they are still applied."""

    def __init__(self, message: str, partial: list["_Detection"] | None = None):
        super().__init__(message)
        self.partial = partial or []


@dataclass
class _Detection:
    pii_type: str
    original: str
    label: str
    engine: str
    start: int
    end: int
    confidence: float


# ---------------------------------------------------------------------------
# Engine 1 — MS Presidio
# ---------------------------------------------------------------------------
def _run_presidio(text: str, log: PipelineLogger) -> list[_Detection]:
    log.info("[TOKENIZER] Engine 1/3: MS Presidio analyzer starting...")
    analyzer = _get_presidio()

    entities = [
        "EMAIL_ADDRESS", "CREDIT_CARD", "US_PASSPORT", "US_DRIVER_LICENSE",
        "MEDICAL_LICENSE", "US_BANK_NUMBER", "IBAN_CODE", "US_SSN",
        "PHONE_NUMBER", "PERSON", "LOCATION",
    ]
    log.info(f"[TOKENIZER] Presidio scanning for: {', '.join(entities)}")

    results = analyzer.analyze(text=text, entities=entities, language="en")
    detections = [
        _Detection(
            pii_type=r.entity_type,
            original=text[r.start:r.end],
            label=r.entity_type.replace("_", " ").title(),
            engine="MS Presidio",
            start=r.start,
            end=r.end,
            confidence=round(r.score, 4),
        )
        for r in results
    ]
    log.info(f"[TOKENIZER] Presidio found {len(detections)} entities")
    return detections


# ---------------------------------------------------------------------------
# Engine 2 — Regex
# ---------------------------------------------------------------------------
def _run_regex(text: str, log: PipelineLogger) -> list[_Detection]:
    log.info("[TOKENIZER] Engine 2/3: Regex pattern matcher starting...")
    types = [p[0] for p in REGEX_PATTERNS]
    log.info(f"[TOKENIZER] Regex scanning for: {', '.join(types)}")

    detections: list[_Detection] = []
    for pii_type, pattern, label in REGEX_PATTERNS:
        for m in re.finditer(pattern, text):
            if pii_type == "ZIPCODE":
                num = int(m.group()[:5])
                if num < 501 or num > 99950:
                    continue
            detections.append(_Detection(
                pii_type=pii_type,
                original=m.group(),
                label=label,
                engine="Regex",
                start=m.start(),
                end=m.end(),
                confidence=0.95,
            ))
    log.info(f"[TOKENIZER] Regex found {len(detections)} entities")
    return detections


# ---------------------------------------------------------------------------
# Engine 3 — AWS Comprehend (chunked WITH OVERLAP so entities straddling a
# chunk boundary are not missed; duplicates are removed by offset key)
# ---------------------------------------------------------------------------
CHUNK_SIZE = 4500
CHUNK_OVERLAP = 200


def _run_comprehend(text: str, log: PipelineLogger) -> list[_Detection]:
    log.info("[TOKENIZER] Engine 3/3: AWS Comprehend NER starting...")
    log.info("[TOKENIZER] Comprehend scanning for: PERSON, DATE, ADDRESS, PII entities")
    log.info(f"[TOKENIZER] Chunking: {CHUNK_SIZE} chars with {CHUNK_OVERLAP}-char overlap")

    kwargs = {"region_name": settings.AWS_REGION}
    if settings.AWS_ACCESS_KEY_ID and settings.AWS_SECRET_ACCESS_KEY:
        kwargs.update(
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        )
        if settings.AWS_SESSION_TOKEN:
            kwargs["aws_session_token"] = settings.AWS_SESSION_TOKEN
    client = boto3.client("comprehend", **kwargs)

    detections: list[_Detection] = []
    seen: set[tuple[int, int, str]] = set()
    offset = 0
    failed_calls = 0

    while offset < len(text):
        chunk = text[offset:offset + CHUNK_SIZE]

        try:
            pii_resp = client.detect_pii_entities(Text=chunk, LanguageCode="en")
            for ent in pii_resp.get("Entities", []):
                start = ent["BeginOffset"] + offset
                end = ent["EndOffset"] + offset
                key = (start, end, ent["Type"])
                if key in seen:
                    continue
                seen.add(key)
                detections.append(_Detection(
                    pii_type=ent["Type"],
                    original=text[start:end],
                    label=ent["Type"].replace("_", " ").title(),
                    engine="AWS Comprehend",
                    start=start,
                    end=end,
                    confidence=round(ent.get("Score", 0.9), 4),
                ))
        except Exception as e:
            failed_calls += 1
            # Exception type only: messages can echo request content.
            log.warn(f"[TOKENIZER] Comprehend PII detection error on chunk: {type(e).__name__}")

        try:
            ner_resp = client.detect_entities(Text=chunk, LanguageCode="en")
            pii_types = {"PERSON", "DATE", "LOCATION"}
            for ent in ner_resp.get("Entities", []):
                if ent["Type"] not in pii_types:
                    continue
                start = ent["BeginOffset"] + offset
                end = ent["EndOffset"] + offset
                if ent["Type"] == "DATE" and (end - start) < 6:
                    continue
                key = (start, end, ent["Type"])
                if key in seen:
                    continue
                seen.add(key)
                detections.append(_Detection(
                    pii_type=ent["Type"],
                    original=text[start:end],
                    label=ent["Type"].replace("_", " ").title(),
                    engine="AWS Comprehend",
                    start=start,
                    end=end,
                    confidence=round(ent.get("Score", 0.85), 4),
                ))
        except Exception as e:
            failed_calls += 1
            log.warn(f"[TOKENIZER] Comprehend NER error on chunk: {type(e).__name__}")

        if offset + CHUNK_SIZE >= len(text):
            break
        offset += CHUNK_SIZE - CHUNK_OVERLAP

    if failed_calls:
        raise EngineUnavailableError(
            f"AWS Comprehend: {failed_calls} call(s) failed", partial=detections
        )
    log.info(f"[TOKENIZER] Comprehend found {len(detections)} entities")
    return detections


# ---------------------------------------------------------------------------
# De-duplicate overlapping detections (keep highest confidence)
# ---------------------------------------------------------------------------
def _deduplicate(detections: list[_Detection]) -> list[_Detection]:
    detections.sort(key=lambda d: (-d.confidence, d.start))
    kept: list[_Detection] = []
    taken: list[tuple[int, int]] = []
    for d in detections:
        if not any(not (d.end <= s or d.start >= e) for s, e in taken):
            kept.append(d)
            taken.append((d.start, d.end))
    return sorted(kept, key=lambda d: d.start)


def _counters_from_tokens(tokens: list[TokenEntry]) -> dict[str, int]:
    """Recover the per-type counters from an existing token list so that
    remediation continues the numbering instead of colliding."""
    counters: dict[str, int] = {}
    for t in tokens:
        m = TOKEN_ID_RE.match(t.token)
        if m:
            ptype, num = m.group(1), int(m.group(2))
            counters[ptype] = max(counters.get(ptype, 0), num)
    return counters


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def tokenize_document(
    text: str, log: PipelineLogger
) -> tuple[str, list[TokenEntry], list[str]]:
    """Run all three engines, de-duplicate, replace PII with tokens.

    Returns (tokenized_text, tokens, failed_engines). A failed engine does not
    abort tokenization (the other engines' results are still applied), but the
    caller must not treat the output as fully scanned — in strict mode the
    pipeline halts before the LLM step.

    Replacement is POSITION-BASED (splice by offset, processed in descending
    offset order) — never string.replace — so a value that happens to be a
    substring of other content is not corrupted, and each detection is
    replaced exactly once at its detected location.

    SECURITY: log entries must NEVER contain the original PII value. Logs are
    displayed on screen and stored in S3 outside the vault's access controls.
    Only offsets, types, engines, and token IDs are logged.
    """
    all_detections: list[_Detection] = []
    failed_engines: list[str] = []
    for name, engine in (
        ("MS Presidio", _run_presidio),
        ("Regex", _run_regex),
        ("AWS Comprehend", _run_comprehend),
    ):
        try:
            all_detections.extend(engine(text, log))
        except Exception as e:
            failed_engines.append(name)
            if isinstance(e, EngineUnavailableError):
                all_detections.extend(e.partial)
            log.error(f"[TOKENIZER] Engine unavailable — {name}: {type(e).__name__}")

    unique = _deduplicate(all_detections)
    log.info(f"[TOKENIZER] Total unique PII after dedup: {len(unique)}")

    # Assign token IDs in document order
    counters: dict[str, int] = {}
    entries: list[TokenEntry] = []
    for d in unique:
        counters[d.pii_type] = counters.get(d.pii_type, 0) + 1
        token_id = f"[TOKEN_{d.pii_type}_{counters[d.pii_type]:03d}]"
        entries.append(TokenEntry(
            token=token_id,
            original=d.original,
            pii_type=d.pii_type,
            label=d.label,
            engine=d.engine,
            position=d.start,
            confidence=d.confidence,
        ))
        # PII-safe log line: position + token only, never the value
        log.info(
            f"[TOKENIZER] {d.label} at offset {d.start}-{d.end} → {token_id} "
            f"(engine: {d.engine}, confidence: {d.confidence * 100:.1f}%)"
        )

    # Splice in descending offset order so earlier offsets stay valid
    tokenized = text
    for d, entry in sorted(zip(unique, entries, strict=True), key=lambda p: -p[0].start):
        tokenized = tokenized[:d.start] + entry.token + tokenized[d.end:]

    if failed_engines:
        log.warn(f"[TOKENIZER] Tokenization INCOMPLETE — failed engine(s): "
                 f"{', '.join(failed_engines)}")
    else:
        log.success(f"[TOKENIZER] Tokenization complete — {len(entries)} entities processed")
    return tokenized, entries, failed_engines


def consistency_pass(
    tokenized_text: str,
    tokens: list[TokenEntry],
    log: PipelineLogger,
) -> tuple[str, int]:
    """Same value -> same token, EVERYWHERE it appears.

    Engines detect occurrences, not values: "John Anderson" flagged at
    offset 100 gets tokenized there, but an undetected second occurrence at
    offset 900 survives — the most common cause of validation failures.
    Since the value->token mapping already exists, every remaining exact
    occurrence can be safely replaced with the SAME token.

    Originals are processed longest-first to avoid substring collisions, and
    values shorter than 4 chars are skipped (too risky to blind-replace).
    """
    log.info("[CONSISTENCY] Scanning for untokenized occurrences of detected values...")
    replaced = 0

    for t in sorted(tokens, key=lambda t: -len(t.original)):
        if len(t.original) < 4:
            continue
        count = tokenized_text.count(t.original)
        if count > 0:
            tokenized_text = tokenized_text.replace(t.original, t.token)
            replaced += count
            # PII-safe log: token + count only, never the value
            log.info(
                f"[CONSISTENCY] {count} additional occurrence(s) of {t.label} → {t.token}"
            )

    if replaced:
        log.success(f"[CONSISTENCY] {replaced} additional occurrence(s) tokenized")
    else:
        log.info("[CONSISTENCY] No additional occurrences found")
    return tokenized_text, replaced


def remediate_residuals(
    tokenized_text: str,
    spans: list[dict],
    existing_tokens: list[TokenEntry],
    log: PipelineLogger,
) -> tuple[str, list[TokenEntry]]:
    """Directly tokenize residual PII spans found by the validator.

    The validator knows the exact offsets of anything it flagged, so instead
    of re-running the whole engine stack and hoping for a different result,
    we tokenize those spans surgically. This guarantees the next validation
    pass converges.
    """
    log.info(f"[REMEDIATION] Directly tokenizing {len(spans)} residual span(s)...")
    counters = _counters_from_tokens(existing_tokens)
    new_entries: list[TokenEntry] = []

    # Descending offset order keeps earlier offsets valid while splicing
    for span in sorted(spans, key=lambda s: -s["start"]):
        ptype = span["pii_type"]
        counters[ptype] = counters.get(ptype, 0) + 1
        token_id = f"[TOKEN_{ptype}_{counters[ptype]:03d}]"
        original = tokenized_text[span["start"]:span["end"]]

        new_entries.append(TokenEntry(
            token=token_id,
            original=original,
            pii_type=ptype,
            label=span["label"],
            engine="Validator remediation",
            position=span["start"],
            confidence=1.0,
        ))
        tokenized_text = (
            tokenized_text[:span["start"]] + token_id + tokenized_text[span["end"]:]
        )
        # PII-safe log line
        log.info(f"[REMEDIATION] {span['label']} at offset {span['start']} → {token_id}")

    log.success(f"[REMEDIATION] {len(new_entries)} residual span(s) tokenized")
    return tokenized_text, existing_tokens + list(reversed(new_entries))
