from pydantic import BaseModel


class TokenEntry(BaseModel):
    token: str
    original: str
    pii_type: str
    label: str
    engine: str
    position: int
    confidence: float


class ValidationCheck(BaseModel):
    name: str
    passed: bool


class ResidualDetail(BaseModel):
    label: str        # e.g. "SSN", "Untokenized occurrence of Person"
    pii_type: str
    line: int
    column: int
    start: int
    end: int
    preview: str      # masked: first char + bullets + last char


class ValidationReport(BaseModel):
    overall_status: str
    confidence: int
    total_pii: int
    tokenized: int
    missed: int
    scan_pass: int
    issues: list[str]
    checks: list[ValidationCheck]
    residual_details: list[ResidualDetail] = []


class LogEntry(BaseModel):
    time: str
    level: str
    message: str


class SecurityFinding(BaseModel):
    category: str       # XSS, MALWARE, FILE_TYPE
    severity: str       # CRITICAL, HIGH, MEDIUM, LOW
    description: str
    detail: str


class SecurityScanResponse(BaseModel):
    passed: bool
    threat_score: int
    findings: list[SecurityFinding]
    guardduty_status: str
    scanned_engines: list[str]


class UploadResponse(BaseModel):
    pipeline_id: str
    file_key: str
    file_name: str
    file_size: int
    s3_path: str
    security: SecurityScanResponse
    extracted_text: str | None = None  # populated for PDFs (server-side extraction)


class PipelineResult(BaseModel):
    pipeline_id: str
    file_name: str
    s3_path: str
    original_text: str
    tokenized_text: str
    tokens: list[TokenEntry]
    validation: ValidationReport
    llm_summary: str
    logs: list[LogEntry]
