"""Shared fixtures: an offline pipeline with AWS, Presidio and the LLM faked.

Nothing here talks to a network service. The fakes record what the pipeline
did so tests can assert on S3 keys, LLM payloads and call ordering.
"""

import json
import re

import pytest
from fastapi.testclient import TestClient

from pii_tokenizer.config import settings
from pii_tokenizer.main import app
from pii_tokenizer.routers import pipeline
from pii_tokenizer.services import (
    pdf_service,
    s3_service,
    security_service,
    tokenizer_service,
)
from pii_tokenizer.services.tokenizer_service import EngineUnavailableError, _Detection

NAME_RE = re.compile(r"\b(?:Jane Doe|John Smith)\b")


class FakeEnv:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.purged: list[str] = []
        self.llm_payloads: list[str] = []
        self.calls: list[str] = []          # ordered trace of notable steps
        self.guardduty = ("CLEAN", [])
        self.comprehend_fails = False


def _fake_presidio(text, log):
    return [
        _Detection("PERSON", m.group(), "Person", "MS Presidio", m.start(), m.end(), 0.9)
        for m in NAME_RE.finditer(text)
    ]


@pytest.fixture
def env(monkeypatch, tmp_path):
    fake = FakeEnv()
    monkeypatch.setattr(settings, "LOG_DIR", tmp_path)
    monkeypatch.setattr(settings, "STRICT_VALIDATION", True)
    pipeline._uploads.clear()

    def upload_file(key, content, log, bucket=None):
        fake.objects[key] = content
        return f"s3://fake/{key}"

    def promote_object(src, dst, log):
        fake.calls.append("promote")
        fake.objects[dst] = fake.objects.pop(src)
        return f"s3://fake/{dst}"

    monkeypatch.setattr(s3_service, "ensure_all_buckets", lambda log: None)
    monkeypatch.setattr(s3_service, "upload_file", upload_file)
    monkeypatch.setattr(s3_service, "promote_object", promote_object)
    monkeypatch.setattr(s3_service, "delete_object",
                        lambda key, log, bucket=None: fake.objects.pop(key, None))
    monkeypatch.setattr(s3_service, "purge_object",
                        lambda key, log, bucket=None: (fake.purged.append(key),
                                                       fake.objects.pop(key, None)))
    monkeypatch.setattr(s3_service, "download_bytes",
                        lambda key, bucket=None: fake.objects[key])

    async def scan_guardduty(key, log):
        fake.calls.append("guardduty")
        return fake.guardduty

    monkeypatch.setattr(security_service, "scan_guardduty", scan_guardduty)

    def comprehend(text, log):
        if fake.comprehend_fails:
            raise EngineUnavailableError("AWS Comprehend: 1 call(s) failed")
        return []

    monkeypatch.setattr(tokenizer_service, "_run_presidio", _fake_presidio)
    monkeypatch.setattr(tokenizer_service, "_run_comprehend", comprehend)

    def extract_text(content, log):
        fake.calls.append("pdf_extract")
        return "Patient Jane Doe, email jane@example.com"

    monkeypatch.setattr(pdf_service, "extract_text", extract_text)

    class FakeAnthropic:
        def __init__(self, **kwargs):
            self.messages = self

        def create(self, **kwargs):
            fake.llm_payloads.append(kwargs["messages"][0]["content"])

            class Block:
                type = "text"
                text = "summary"

            class Msg:
                content = [Block()]

            return Msg()

    import anthropic
    monkeypatch.setattr(anthropic, "Anthropic", FakeAnthropic)
    return fake


@pytest.fixture
def client():
    return TestClient(app)


def parse_sse(body: str) -> list[tuple[str, dict]]:
    events = []
    for block in body.strip().split("\n\n"):
        lines = dict(line.split(": ", 1) for line in block.splitlines() if ": " in line)
        if "event" in lines:
            events.append((lines["event"], json.loads(lines["data"])))
    return events


def run_pipeline(client, filename: str, content: bytes, query: str = ""):
    """Upload + stream. Returns (upload_response, events, raw_stream_body)."""
    up = client.post("/api/upload", files={"file": (filename, content)})
    assert up.status_code == 200, up.text
    pid = up.json()["pipeline_id"]
    stream = client.get(f"/api/pipeline/{pid}/stream{query}")
    assert stream.status_code == 200, stream.text
    return up, parse_sse(stream.text), stream.text
