"use client";
import { useState, useCallback } from "react";
import { uploadFile, streamPipeline, SecurityBlockedError } from "@/lib/api";
import FileUpload from "@/components/FileUpload";
import StepIndicator from "@/components/StepIndicator";
import DocumentViewer from "@/components/DocumentViewer";
import TokenMap from "@/components/TokenMap";
import ValidationReport from "@/components/ValidationReport";
import LogPanel from "@/components/LogPanel";
import LLMSummary from "@/components/LLMSummary";
import SecurityReport from "@/components/SecurityReport";

const TABS = [
  { id: "document", label: "Document", icon: "doc" },
  { id: "security", label: "Security", icon: "shield" },
  { id: "tokens", label: "Token map", icon: "key" },
  { id: "validation", label: "Validation", icon: "check" },
  { id: "summary", label: "Summary", icon: "sparkle" },
  { id: "logs", label: "Logs", icon: "terminal" },
];

const TAB_ICONS = {
  doc: (
    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
    </svg>
  ),
  shield: (
    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
    </svg>
  ),
  key: (
    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
    </svg>
  ),
  check: (
    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  ),
  sparkle: (
    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
    </svg>
  ),
  terminal: (
    <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
    </svg>
  ),
};

export default function Home() {
  const [stepStatuses, setStepStatuses] = useState({});
  const [originalText, setOriginalText] = useState("");
  const [tokenizedText, setTokenizedText] = useState("");
  const [tokens, setTokens] = useState([]);
  const [validation, setValidation] = useState(null);
  const [summary, setSummary] = useState("");
  const [logs, setLogs] = useState([]);
  const [activeTab, setActiveTab] = useState("document");
  const [isProcessing, setIsProcessing] = useState(false);
  const [fileName, setFileName] = useState("");
  const [s3Path, setS3Path] = useState("");
  const [error, setError] = useState("");
  const [llmLoading, setLlmLoading] = useState(false);
  const [securityResult, setSecurityResult] = useState(null);
  const [securityBlocked, setSecurityBlocked] = useState(false);
  const [validationFailed, setValidationFailed] = useState(false);

  const updateStep = useCallback((id, status) => {
    setStepStatuses((prev) => ({ ...prev, [id]: status }));
  }, []);

  const handleFile = useCallback(
    async (file, preReadText) => {
      setIsProcessing(true);
      setError("");
      setStepStatuses({});
      setTokens([]);
      setTokenizedText("");
      setValidation(null);
      setSummary("");
      setLogs([]);
      setFileName(file.name);
      setActiveTab("document");
      setLlmLoading(false);
      setSecurityResult(null);
      setSecurityBlocked(false);
      setValidationFailed(false);

      const isPdf = file.name.toLowerCase().endsWith(".pdf");
      const text = isPdf ? "" : (preReadText ?? (await file.text()));
      setOriginalText(isPdf ? "Extracting text from PDF on the server…" : text);

      updateStep("upload", "running");
      try {
        const meta = await uploadFile(file);
        setSecurityResult(meta.security);
        updateStep("upload", "complete");
        updateStep("security", "running");
        setS3Path(meta.s3_path);

        streamPipeline(meta.pipeline_id, {
          onSecurity({ security, blocked, s3_path }) {
            setSecurityResult(security);
            if (s3_path) setS3Path(s3_path);
            if (blocked) {
              setSecurityBlocked(true);
              setActiveTab("security");
              setError("Upload blocked — the malware scan failed. See the Security tab.");
            }
          },
          onDocument({ text: t }) {
            setOriginalText(t);
          },
          onStep({ step, status }) {
            updateStep(step, status);
            if (step === "llm" && status === "running") setLlmLoading(true);
            if (step === "llm" && status === "complete") setLlmLoading(false);
          },
          onTokens({ tokens: t, tokenized_text: tt }) {
            setTokens(t);
            setTokenizedText(tt);
          },
          onValidation({ report }) {
            setValidation(report);
            setActiveTab("validation");
            if (report.overall_status === "FAIL") setValidationFailed(true);
          },
          onSummary({ summary: s }) {
            setSummary(s);
            setActiveTab("summary");
          },
          onDone({ logs: l, error: e }) {
            if (e) setError(e);
            setLogs(l || []);
            setIsProcessing(false);
          },
          onError() {
            setError("Connection to pipeline lost. Check that the backend is running.");
            setIsProcessing(false);
          },
        });
      } catch (err) {
        if (err instanceof SecurityBlockedError) {
          setSecurityResult(err.security);
          setSecurityBlocked(true);
          setLogs(err.logs || []);
          updateStep("upload", "complete");
          updateStep("security", "fail");
          setActiveTab("security");
          setError("Upload blocked — the file failed security validation. See the Security tab.");
        } else {
          setError(err.message);
          updateStep("upload", "fail");
        }
        setIsProcessing(false);
      }
    },
    [updateStep]
  );

  const reset = () => {
    setStepStatuses({});
    setOriginalText("");
    setTokenizedText("");
    setTokens([]);
    setValidation(null);
    setSummary("");
    setLogs([]);
    setFileName("");
    setS3Path("");
    setError("");
    setIsProcessing(false);
    setActiveTab("document");
    setSecurityResult(null);
    setSecurityBlocked(false);
    setValidationFailed(false);
  };

  const showUpload = !originalText && !isProcessing;
  const pipelineComplete = stepStatuses.output === "complete";

  return (
    <div className="min-h-screen" style={{ background: "var(--bg-secondary)" }}>
      <div className="max-w-[880px] mx-auto px-5 py-10">

        {/* ── Header ── */}
        <header className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <div
              className="w-8 h-8 rounded-lg flex items-center justify-center"
              style={{ background: "var(--accent-subtle)", border: "1px solid var(--accent-muted)" }}
            >
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2.2} style={{ color: "var(--accent)" }}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <div>
              <h1 className="text-lg font-semibold tracking-tight" style={{ color: "var(--text-primary)" }}>
                PII Tokenization Pipeline
              </h1>
            </div>
            {pipelineComplete && <span className="badge badge-success ml-auto">Complete</span>}
            {securityBlocked && <span className="badge badge-danger ml-auto">Blocked</span>}
          </div>
          <p className="text-[13px] leading-relaxed ml-11" style={{ color: "var(--text-tertiary)" }}>
            Detect and replace personal data with reversible tokens before LLM processing.
          </p>
        </header>

        {/* ── Step indicator ── */}
        <StepIndicator statuses={stepStatuses} />

        {/* ── Validation warning banner ── */}
        {/* Only reachable when the server runs with STRICT_VALIDATION=false */}
        {validationFailed && stepStatuses.llm === "complete" && (
          <div
            className="mb-5 px-4 py-3 rounded-lg text-[13px] leading-relaxed animate-fade-in"
            style={{
              background: "var(--warning-subtle)",
              border: "1px solid var(--warning-muted)",
              color: "var(--warning)",
            }}
          >
            <span className="font-semibold">Validation incomplete — </span>
            {validation?.residual_details?.length || "some"} residual PII location(s)
            could not be tokenized. The LLM summary was generated from a document that
            may contain un-tokenized PII. See the Validation tab for exact locations.
          </div>
        )}

        {/* ── Error ── */}
        {error && (
          <div
            className="mb-5 px-4 py-3 rounded-lg text-[13px] leading-relaxed animate-fade-in"
            style={{
              background: "var(--danger-subtle)",
              border: "1px solid var(--danger-muted)",
              color: "var(--danger)",
            }}
          >
            {error}
          </div>
        )}

        {/* ── Upload area ── */}
        {showUpload ? (
          <div className="animate-fade-in">
            <FileUpload
              onFileSelected={handleFile}
              onClientScan={(result) => {
                if (result.blocked) setSecurityBlocked(true);
              }}
              disabled={isProcessing}
            />
          </div>
        ) : (
          <div className="animate-fade-in">
            {/* ── File info bar ── */}
            <div
              className="flex items-center gap-2.5 mb-4 px-4 py-2.5 rounded-lg"
              style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}
            >
              <svg width="15" height="15" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)", flexShrink: 0 }}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
              </svg>
              <span className="font-mono text-xs font-medium truncate" style={{ color: "var(--text-primary)" }}>
                {fileName}
              </span>
              {s3Path && (
                <>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)", flexShrink: 0 }}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                  </svg>
                  <span className="font-mono text-[11px] truncate" style={{ color: "var(--accent)" }}>
                    {s3Path}
                  </span>
                </>
              )}
              {!isProcessing && (
                <button
                  onClick={reset}
                  className="ml-auto flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-all hover:opacity-80"
                  style={{
                    background: "var(--bg-elevated)",
                    border: "1px solid var(--border)",
                    color: "var(--text-secondary)",
                  }}
                >
                  <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182" />
                  </svg>
                  New file
                </button>
              )}
            </div>

            {/* ── Tab bar ── */}
            <div
              className="flex gap-1 p-1 mb-5 rounded-lg overflow-x-auto"
              style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border-subtle)" }}
            >
              {TABS.map((tab) => {
                const isActive = activeTab === tab.id;
                const isDanger = tab.id === "security" && securityBlocked;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className="flex items-center gap-1.5 px-3 py-2 text-[12px] font-medium rounded-md transition-all whitespace-nowrap flex-1 justify-center"
                    style={{
                      background: isActive ? "var(--bg-elevated)" : "transparent",
                      color: isDanger
                        ? "var(--danger)"
                        : isActive
                        ? "var(--text-primary)"
                        : "var(--text-tertiary)",
                      boxShadow: isActive ? "var(--shadow-sm)" : "none",
                    }}
                  >
                    <span style={{ opacity: isActive ? 1 : 0.6 }}>{TAB_ICONS[tab.icon]}</span>
                    {tab.label}
                    {isDanger && (
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: "var(--danger)" }} />
                    )}
                  </button>
                );
              })}
            </div>

            {/* ── Tab content ── */}
            <div className="mb-6 animate-fade-in" key={activeTab}>
              {activeTab === "document" && (
                <DocumentViewer original={originalText} tokenized={tokenizedText} />
              )}
              {activeTab === "security" && (
                securityResult ? (
                  <SecurityReport scan={securityResult} />
                ) : (
                  <div className="card">
                    <div className="text-center py-16 text-sm" style={{ color: "var(--text-tertiary)" }}>
                      Security scan results will appear after upload.
                    </div>
                  </div>
                )
              )}
              {activeTab === "tokens" && <TokenMap tokens={tokens} />}
              {activeTab === "validation" && <ValidationReport report={validation} />}
              {activeTab === "summary" && <LLMSummary summary={summary} isLoading={llmLoading} />}
              {activeTab === "logs" && <LogPanel logs={logs} />}
            </div>

            {/* ── Inline log panel (when not on logs tab) ── */}
            {activeTab !== "logs" && logs.length > 0 && <LogPanel logs={logs} />}
          </div>
        )}

        {/* ── Architecture footer ── */}
        <footer
          className="mt-8 p-5 rounded-xl"
          style={{ background: "var(--bg-elevated)", border: "1px solid var(--border)", boxShadow: "var(--shadow-sm)" }}
        >
          <div className="flex items-center gap-2 mb-3">
            <svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)" }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M11.25 11.25l.041-.02a.75.75 0 011.063.852l-.708 2.836a.75.75 0 001.063.853l.041-.021M21 12a9 9 0 11-18 0 9 9 0 0118 0zm-9-3.75h.008v.008H12V8.25z" />
            </svg>
            <span className="text-[11px] font-semibold uppercase tracking-wider" style={{ color: "var(--text-tertiary)" }}>
              Pipeline architecture
            </span>
          </div>
          <div className="font-mono text-[11.5px] leading-7" style={{ color: "var(--text-tertiary)" }}>
            <div>
              Upload →{" "}
              <span style={{ color: "var(--danger)" }}>Security gate</span>{" "}
              <span style={{ opacity: 0.5 }}>(XSS + file-type + GuardDuty malware)</span>
            </div>
            <div>
              → <span style={{ color: "var(--accent)" }}>S3</span>{" "}
              <span style={{ opacity: 0.5 }}>(quarantine → uploads/)</span>
              → <span style={{ color: "var(--warning)" }}>Tokenizer</span>{" "}
              <span style={{ opacity: 0.5 }}>(Presidio + Regex + Comprehend)</span>
            </div>
            <div>
              → <span style={{ color: "var(--success)" }}>Validation</span>{" "}
              <span style={{ opacity: 0.5 }}>(re-tokenize on fail)</span>
              → <span style={{ color: "var(--accent)" }}>Claude API</span>
              → <span style={{ color: "var(--accent)" }}>S3 output</span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  );
}
