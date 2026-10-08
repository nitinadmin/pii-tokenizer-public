"""End-to-end pipeline behaviour through the HTTP API (offline fakes).

Test IDs (e.g. TP-STRICT-01) refer to docs/test-plan.md.
"""

import json
import re

from conftest import parse_sse, run_pipeline

from pii_tokenizer.config import settings
from pii_tokenizer.routers import pipeline

DOC = b"Customer Jane Doe\nEmail: jane@example.com\nSSN: 123-45-6789\n"


def _steps(events):
    return {(d["step"], d["status"]) for e, d in events if e == "step"}


def test_happy_path_sends_only_tokenized_text_to_llm(env, client):
    # TP-FLOW-01
    _, events, _ = run_pipeline(client, "jane_doe_record.txt", DOC)
    assert ("output", "complete") in _steps(events)
    assert len(env.llm_payloads) == 1
    payload = env.llm_payloads[0]
    for raw in ("Jane Doe", "jane@example.com", "123-45-6789"):
        assert raw not in payload
    assert "[TOKEN_PERSON_001]" in payload


def test_strict_query_parameter_cannot_disable_strict_mode(env, client):
    # TP-STRICT-01
    env.comprehend_fails = True
    _, events, _ = run_pipeline(client, "a.txt", DOC, query="?strict=false")
    assert ("llm", "skipped") in _steps(events)
    assert env.llm_payloads == []


def test_failed_detection_engine_halts_in_strict_mode(env, client):
    # TP-STRICT-02
    env.comprehend_fails = True
    _, events, _ = run_pipeline(client, "a.txt", DOC)
    report = next(d["report"] for e, d in events if e == "validation")
    assert report["overall_status"] == "FAIL"
    assert {"name": "All detection engines completed", "passed": False} in report["checks"]
    assert env.llm_payloads == []
    # Nothing was written to the vault or tokenized prefixes
    assert not any(k.startswith(("vault/", "tokenized/")) for k in env.objects)


def test_non_strict_server_setting_continues_with_warning(env, client, monkeypatch):
    # TP-STRICT-03
    monkeypatch.setattr(settings, "STRICT_VALIDATION", False)
    env.comprehend_fails = True
    _, events, _ = run_pipeline(client, "a.txt", DOC)
    assert len(env.llm_payloads) == 1
    logs = next(d["logs"] for e, d in events if e == "done")
    assert any("NON-STRICT MODE" in entry["message"] for entry in logs)


def test_token_map_originals_never_sent_to_client(env, client):
    # TP-LEAK-01: the original->token mapping (vault content) stays server-side.
    # (Intermediate tokenized text can still show residuals of the user's own
    # document before remediation; that is progress output, not the vault.)
    _, events, _ = run_pipeline(client, "a.txt", DOC)
    token_events = [d for e, d in events if e == "tokens"]
    assert token_events
    for ev in token_events:
        for t in ev["tokens"]:
            assert "original" not in t
            assert "•" in t["preview"]
            assert t["preview"] not in ("Jane Doe", "jane@example.com", "123-45-6789")
    final_text = token_events[-1]["tokenized_text"]
    for raw in ("Jane Doe", "jane@example.com", "123-45-6789"):
        assert raw not in final_text


def test_filename_not_in_s3_keys_or_logs(env, client):
    # TP-LEAK-02
    up, events, body = run_pipeline(client, "Jane_Doe_SSN.txt", DOC)
    assert all("Jane_Doe" not in k for k in env.objects)
    assert "Jane_Doe" not in body
    log_file = settings.LOG_DIR / f"pipeline-{up.json()['pipeline_id']}.json"
    assert "Jane_Doe" not in log_file.read_text()


def test_pipeline_id_is_128_bit_hex(env, client):
    # TP-ACCESS-01
    up = client.post("/api/upload", files={"file": ("a.txt", DOC)})
    assert re.fullmatch(r"[0-9a-f]{32}", up.json()["pipeline_id"])


def test_stream_is_single_use(env, client):
    # TP-ACCESS-02
    up = client.post("/api/upload", files={"file": ("a.txt", DOC)})
    pid = up.json()["pipeline_id"]
    assert client.get(f"/api/pipeline/{pid}/stream").status_code == 200
    assert client.get(f"/api/pipeline/{pid}/stream").status_code in (404, 409)
    assert pid not in pipeline._uploads  # raw text dropped from memory


def test_concurrent_second_stream_is_rejected(env, client):
    # TP-ACCESS-02
    up = client.post("/api/upload", files={"file": ("a.txt", DOC)})
    pid = up.json()["pipeline_id"]
    pipeline._uploads[pid]["started"] = True
    assert client.get(f"/api/pipeline/{pid}/stream").status_code == 409


def test_malformed_pipeline_ids_rejected(env, client):
    # TP-ACCESS-03
    for bad in ("abc", "..", "0" * 31, "G" * 32, "0" * 33):
        assert client.get(f"/api/pipeline/{bad}/logs").status_code == 404
        assert client.get(f"/api/pipeline/{bad}/stream").status_code == 404


def test_guardduty_threat_purges_and_halts(env, client):
    # TP-MAL-01
    from pii_tokenizer.services.security_service import SecurityFinding
    env.guardduty = ("THREAT", [SecurityFinding("MALWARE", "CRITICAL", "Malware", "x")])
    _, events, _ = run_pipeline(client, "a.txt", DOC)
    assert ("security", "fail") in _steps(events)
    assert len(env.purged) == 1 and env.purged[0].startswith("quarantine/")
    assert "promote" not in env.calls
    assert env.llm_payloads == []


def test_pdf_is_parsed_only_after_guardduty_clears_it(env, client):
    # TP-MAL-02
    pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF"
    up = client.post("/api/upload", files={"file": ("scan.pdf", pdf)})
    assert up.status_code == 200, up.text
    assert "pdf_extract" not in env.calls
    pid = up.json()["pipeline_id"]
    events = parse_sse(client.get(f"/api/pipeline/{pid}/stream").text)
    calls = env.calls
    assert calls.index("guardduty") < calls.index("promote") < calls.index("pdf_extract")
    assert any(e == "document" for e, _ in events)


def test_pdf_not_parsed_when_guardduty_blocks(env, client):
    # TP-MAL-02
    env.guardduty = ("BLOCKED_UNAVAILABLE", [])
    pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog >> endobj\n%%EOF"
    run_pipeline(client, "scan.pdf", pdf)
    assert "pdf_extract" not in env.calls


def test_upload_size_limit_enforced_server_side(env, client, monkeypatch):
    # TP-INPUT-01
    monkeypatch.setattr(settings, "MAX_UPLOAD_SIZE_MB", 1)
    big = b"a" * (1024 * 1024 + 1)
    assert client.post("/api/upload", files={"file": ("a.txt", big)}).status_code == 413
    exact = b"a" * (1024 * 1024)
    assert client.post("/api/upload", files={"file": ("a.txt", exact)}).status_code == 200


def test_unstarted_upload_cleaned_from_quarantine_on_ttl(env, client, monkeypatch):
    # TP-DATA-01
    up = client.post("/api/upload", files={"file": ("a.txt", DOC)})
    key = up.json()["file_key"]
    assert key in env.objects
    monkeypatch.setattr(settings, "UPLOAD_TTL_SECONDS", -1)
    client.post("/api/upload", files={"file": ("b.txt", DOC)})  # triggers eviction
    assert key not in env.objects


def test_vault_holds_originals_and_is_separate(env, client):
    # TP-DATA-02 (the fake S3 is flat, so check by key prefix + content)
    run_pipeline(client, "a.txt", DOC)
    vault = [k for k in env.objects if k.startswith("vault/")]
    tokenized = [k for k in env.objects if k.startswith("tokenized/")]
    assert len(vault) == 1 and len(tokenized) == 1
    assert "Jane Doe" in json.dumps(json.loads(env.objects[vault[0]]))
    assert b"Jane Doe" not in env.objects[tokenized[0]]
