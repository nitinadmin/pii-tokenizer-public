from pii_tokenizer.models.schemas import TokenEntry
from pii_tokenizer.services.logger_service import PipelineLogger
from pii_tokenizer.services.tokenizer_service import consistency_pass


def test_consistency_pass_reuses_existing_token():
    # TP-DETECT-01
    token = TokenEntry(
        token="[TOKEN_EMAIL_ADDRESS_001]",
        original="alice@example.com",
        pii_type="EMAIL_ADDRESS",
        label="Email Address",
        engine="test",
        position=0,
        confidence=1.0,
    )
    log = PipelineLogger("test-consistency")
    text, replaced = consistency_pass(
        "Contact alice@example.com or email alice@example.com.",
        [token],
        log,
    )
    assert text == (
        "Contact [TOKEN_EMAIL_ADDRESS_001] or email [TOKEN_EMAIL_ADDRESS_001]."
    )
    assert replaced == 2


def test_failed_engine_is_reported_and_partial_results_kept(monkeypatch):
    # TP-DETECT-02
    from pii_tokenizer.services import tokenizer_service as ts

    partial = [ts._Detection("PERSON", "Jane Doe", "Person", "AWS Comprehend", 0, 8, 0.9)]

    def broken_comprehend(text, log):
        raise ts.EngineUnavailableError("AWS Comprehend: 1 call(s) failed", partial=partial)

    monkeypatch.setattr(ts, "_run_presidio", lambda text, log: [])
    monkeypatch.setattr(ts, "_run_comprehend", broken_comprehend)
    text, tokens, failed = ts.tokenize_document("Jane Doe called 555-123-4567", PipelineLogger("t"))
    assert failed == ["AWS Comprehend"]
    assert "Jane Doe" not in text and "555-123-4567" not in text
    assert {t.pii_type for t in tokens} == {"PERSON", "PHONE"}


def test_tokenizer_logs_never_contain_values(monkeypatch):
    # TP-LEAK-03
    from pii_tokenizer.services import tokenizer_service as ts

    monkeypatch.setattr(ts, "_run_presidio", lambda text, log: [])
    monkeypatch.setattr(ts, "_run_comprehend", lambda text, log: [])
    log = PipelineLogger("t")
    ts.tokenize_document("SSN 123-45-6789, phone 555-123-4567", log)
    assert all("123-45-6789" not in e.message and "555-123-4567" not in e.message
               for e in log.get_entries())


def test_llm_boundary_blocks_raw_pii_before_any_call(monkeypatch):
    # TP-LLM-01
    import anthropic
    import pytest

    from pii_tokenizer.services import llm_service

    def must_not_construct(**kwargs):
        raise AssertionError("LLM client must not be created when the payload leaks PII")

    monkeypatch.setattr(anthropic, "Anthropic", must_not_construct)
    token = TokenEntry(token="[TOKEN_PERSON_001]", original="Jane Doe", pii_type="PERSON",
                       label="Person", engine="t", position=0, confidence=1.0)
    with pytest.raises(llm_service.LLMBoundaryError):
        llm_service.generate_summary("Hello Jane Doe", [token], PipelineLogger("t"))
    with pytest.raises(llm_service.LLMBoundaryError):
        llm_service.generate_summary("SSN 123-45-6789", [], PipelineLogger("t"))


def test_llm_error_message_not_echoed(monkeypatch):
    # TP-LEAK-04
    import anthropic

    from pii_tokenizer.services import llm_service

    class Boom:
        def __init__(self, **kwargs):
            raise RuntimeError("echo: secret document text")

    monkeypatch.setattr(anthropic, "Anthropic", Boom)
    log = PipelineLogger("t")
    out = llm_service.generate_summary("[TOKEN_PERSON_001] said hi", [], log)
    assert "secret document text" not in out
    assert all("secret document text" not in e.message for e in log.get_entries())
