const API_BASE = "/api";

/**
 * Upload a file to the backend. Returns metadata including pipeline_id
 * and security scan results.
 *
 * Throws a SecurityBlockedError if the file is rejected by the security scan.
 */
export class SecurityBlockedError extends Error {
  constructor(detail) {
    super(detail.message || "File blocked by security scan");
    this.name = "SecurityBlockedError";
    this.security = detail.security;
    this.logs = detail.logs;
    this.pipelineId = detail.pipeline_id;
  }
}

export async function uploadFile(file) {
  const form = new FormData();
  form.append("file", file);

  const res = await fetch(`${API_BASE}/upload`, {
    method: "POST",
    body: form,
  });

  if (res.status === 422) {
    const err = await res.json().catch(() => ({}));
    const detail = err.detail || err;
    throw new SecurityBlockedError(detail);
  }

  if (res.status === 413) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || "File exceeds the server-side size limit");
  }

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.detail || `Upload failed (${res.status})`);
  }

  return res.json();
}

/**
 * Connect to the pipeline SSE stream and call handlers for each event type.
 * Strict validation is configured on the server and cannot be changed here.
 *
 * handlers: { onStep, onSecurity, onDocument, onTokens, onValidation,
 *             onSummary, onDone, onError }
 */
export function streamPipeline(pipelineId, handlers) {
  const url = `${API_BASE}/pipeline/${pipelineId}/stream`;
  const source = new EventSource(url);

  source.addEventListener("step", (e) => {
    handlers.onStep?.(JSON.parse(e.data));
  });

  source.addEventListener("security", (e) => {
    handlers.onSecurity?.(JSON.parse(e.data));
  });

  source.addEventListener("document", (e) => {
    handlers.onDocument?.(JSON.parse(e.data));
  });

  source.addEventListener("tokens", (e) => {
    handlers.onTokens?.(JSON.parse(e.data));
  });

  source.addEventListener("validation", (e) => {
    handlers.onValidation?.(JSON.parse(e.data));
  });

  source.addEventListener("summary", (e) => {
    handlers.onSummary?.(JSON.parse(e.data));
  });

  source.addEventListener("done", (e) => {
    handlers.onDone?.(JSON.parse(e.data));
    source.close();
  });

  source.onerror = (err) => {
    handlers.onError?.(err);
    source.close();
  };

  return source;
}

/**
 * Fetch saved logs for a completed pipeline run.
 */
export async function fetchLogs(pipelineId) {
  const res = await fetch(`${API_BASE}/pipeline/${pipelineId}/logs`);
  if (!res.ok) throw new Error("Failed to fetch logs");
  return res.json();
}
