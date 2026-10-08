import json
import logging
from datetime import datetime, timezone

from pii_tokenizer.config import settings
from pii_tokenizer.models.schemas import LogEntry

logger = logging.getLogger("pii-pipeline")
logger.setLevel(logging.DEBUG)

if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)


class PipelineLogger:
    """Accumulates structured log entries for a single pipeline run and
    persists them to a JSON file on disk."""

    def __init__(self, pipeline_id: str):
        self.pipeline_id = pipeline_id
        self.entries: list[LogEntry] = []
        self.log_path = settings.LOG_DIR / f"pipeline-{pipeline_id}.json"

    def _ts(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]

    def log(self, level: str, message: str):
        entry = LogEntry(time=self._ts(), level=level, message=message)
        self.entries.append(entry)
        log_fn = getattr(logger, level.lower(), logger.info)
        log_fn(f"[{self.pipeline_id}] {message}")

    def info(self, message: str):
        self.log("INFO", message)

    def warn(self, message: str):
        self.log("WARN", message)

    def error(self, message: str):
        self.log("ERROR", message)

    def success(self, message: str):
        self.log("SUCCESS", message)

    def save(self):
        """Persist all log entries to a JSON file."""
        data = {
            "pipeline_id": self.pipeline_id,
            "total_entries": len(self.entries),
            "entries": [e.model_dump() for e in self.entries],
        }
        self.log_path.write_text(json.dumps(data, indent=2))
        logger.info(f"Log saved to {self.log_path}")

    def get_entries(self) -> list[LogEntry]:
        return self.entries
