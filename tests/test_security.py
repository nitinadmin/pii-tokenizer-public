from pii_tokenizer.services.logger_service import PipelineLogger
from pii_tokenizer.services.security_service import run_fast_scan


def test_text_file_passes_basic_security_scan():
    # TP-INPUT-05
    log = PipelineLogger("test-security-pass")
    result = run_fast_scan(b"Hello, this is a normal document.\n", "sample.txt", log)
    assert result.passed is True


def test_disguised_pdf_is_blocked():
    # TP-INPUT-02
    log = PipelineLogger("test-security-pdf")
    result = run_fast_scan(b"%PDF-1.7\nmalicious", "sample.txt", log)
    assert result.passed is False
    assert any(f.category == "FILE_TYPE" for f in result.findings)


def test_script_payload_is_blocked():
    # TP-INPUT-03
    log = PipelineLogger("test-security-xss")
    result = run_fast_scan(b"<script>alert(1)</script>", "sample.txt", log)
    assert result.passed is False
    assert any(f.category == "XSS" for f in result.findings)


def test_markdown_code_fence_does_not_hide_payload():
    # TP-INPUT-03: fenced code used to be excluded from the scan
    log = PipelineLogger("test-security-md")
    result = run_fast_scan(b"# Notes\n```\n<script>alert(1)</script>\n```\n", "notes.md", log)
    assert result.passed is False


def test_pdf_with_javascript_is_blocked():
    # TP-INPUT-04
    log = PipelineLogger("test-security-pdfjs")
    result = run_fast_scan(b"%PDF-1.7\n<< /S /JavaScript /JS (app.alert(1)) >>", "a.pdf", log)
    assert result.passed is False
    assert any(f.category == "PDF_ACTIVE_CONTENT" for f in result.findings)


def test_disallowed_extension_is_blocked():
    # TP-INPUT-02
    log = PipelineLogger("test-security-ext")
    assert run_fast_scan(b"hello", "a.html", log).passed is False


def test_fast_scan_logs_extension_not_filename():
    # TP-LEAK-02
    log = PipelineLogger("test-security-name")
    run_fast_scan(b"hello", "Jane_Doe_W2.txt", log)
    assert all("Jane_Doe" not in e.message for e in log.get_entries())


class _FakeS3:
    def __init__(self, tag):
        self.tag = tag

    def get_object_tagging(self, **kwargs):
        tags = [{"Key": "GuardDutyMalwareScanStatus", "Value": self.tag}] if self.tag else []
        return {"TagSet": tags}


def _guardduty(monkeypatch, tag, max_wait=5, fail_open=False):
    import asyncio

    from pii_tokenizer.config import settings
    from pii_tokenizer.services import security_service

    monkeypatch.setattr(security_service.boto3, "client", lambda *a, **k: _FakeS3(tag))
    monkeypatch.setattr(settings, "GUARDDUTY_MAX_WAIT", max_wait)
    monkeypatch.setattr(settings, "GUARDDUTY_FAIL_OPEN", fail_open)
    status, _ = asyncio.run(security_service.scan_guardduty("k", PipelineLogger("gd")))
    return status, security_service.guardduty_verdict_blocks(status)


def test_guardduty_verdicts(monkeypatch):
    # TP-MAL-03
    assert _guardduty(monkeypatch, "NO_THREATS_FOUND") == ("CLEAN", False)
    assert _guardduty(monkeypatch, "THREATS_FOUND") == ("THREAT", True)
    assert _guardduty(monkeypatch, "UNSUPPORTED") == ("UNSUPPORTED", False)


def test_guardduty_fails_closed_without_verdict(monkeypatch):
    # TP-MAL-04 (max_wait=0: no polling, verdict never arrives)
    assert _guardduty(monkeypatch, None, max_wait=0) == ("BLOCKED_UNAVAILABLE", True)
    assert _guardduty(monkeypatch, None, max_wait=0, fail_open=True) == ("SKIPPED", False)
