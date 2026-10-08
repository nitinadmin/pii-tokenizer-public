"use client";
import { useCallback, useRef, useState } from "react";

const CLIENT_XSS_PATTERNS = [
  { regex: /<script[\s>]/gi, desc: "Inline <script> tag", score: 100 },
  { regex: /javascript\s*:/gi, desc: "javascript: URI scheme", score: 90 },
  { regex: /vbscript\s*:/gi, desc: "vbscript: URI scheme", score: 90 },
  { regex: /\bon\w+\s*=/gi, desc: "Inline event handler", score: 80 },
  { regex: /eval\s*\(/gi, desc: "eval() call", score: 90 },
  { regex: /document\s*\.\s*cookie/gi, desc: "document.cookie access", score: 95 },
  { regex: /document\s*\.\s*write/gi, desc: "document.write() call", score: 80 },
  { regex: /<iframe[\s>]/gi, desc: "Embedded <iframe>", score: 90 },
  { regex: /<embed[\s>]/gi, desc: "Embedded <embed>", score: 85 },
  { regex: /<object[\s>]/gi, desc: "Embedded <object>", score: 85 },
  { regex: /innerHTML\s*=/gi, desc: "innerHTML assignment", score: 70 },
  { regex: /%3[Cc]script/gi, desc: "URL-encoded <script>", score: 95 },
  { regex: /fromCharCode/gi, desc: "String.fromCharCode", score: 70 },
  { regex: /data\s*:\s*text\/html/gi, desc: "data:text/html payload", score: 85 },
  { regex: /atob\s*\(/gi, desc: "Base64 decode via atob()", score: 65 },
];

const ALLOWED_EXTENSIONS = [".txt", ".csv", ".md", ".json", ".log", ".xml", ".tsv", ".pdf"];
const MAX_FILE_SIZE = 10 * 1024 * 1024;

function runClientScan(text, fileName) {
  const findings = [];
  let totalScore = 0;

  const ext = "." + fileName.split(".").pop().toLowerCase();
  if (!ALLOWED_EXTENSIONS.includes(ext)) {
    findings.push({ severity: "HIGH", desc: `Disallowed file extension: ${ext}` });
    totalScore += 80;
  }

  if (text.includes("\x00")) {
    findings.push({ severity: "HIGH", desc: "Null bytes detected — possible binary file" });
    totalScore += 80;
  }

  for (const { regex, desc, score } of CLIENT_XSS_PATTERNS) {
    const matches = text.match(regex);
    if (matches) {
      totalScore += score * matches.length;
      findings.push({
        severity: score >= 90 ? "CRITICAL" : score >= 70 ? "HIGH" : "MEDIUM",
        desc: `${desc} (${matches.length} found)`,
      });
    }
  }

  return { findings, totalScore, blocked: totalScore >= 80 };
}

const SEVERITY_COLORS = {
  CRITICAL: { bg: "var(--danger-subtle)", text: "var(--danger)", border: "var(--danger-muted)" },
  HIGH: { bg: "var(--warning-subtle)", text: "var(--warning)", border: "var(--warning-muted)" },
  MEDIUM: { bg: "var(--warning-subtle)", text: "var(--warning)", border: "var(--warning-muted)" },
};

export default function FileUpload({ onFileSelected, onClientScan, disabled }) {
  const inputRef = useRef(null);
  const [dragging, setDragging] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [clientResult, setClientResult] = useState(null);

  const processFile = useCallback(
    async (file) => {
      if (!file || disabled) return;
      setScanning(true);
      setClientResult(null);

      if (file.size > MAX_FILE_SIZE) {
        setClientResult({
          blocked: true, totalScore: 999,
          findings: [{ severity: "HIGH", desc: `File exceeds 10 MB limit (${(file.size / 1024 / 1024).toFixed(1)} MB)` }],
        });
        setScanning(false);
        return;
      }

      const isPdf = file.name.toLowerCase().endsWith(".pdf");
      if (isPdf) {
        setScanning(false);
        onFileSelected(file, null);
        return;
      }

      const text = await file.text();
      const result = runClientScan(text, file.name);
      setClientResult(result);
      onClientScan?.(result);
      setScanning(false);
      if (!result.blocked) onFileSelected(file, text);
    },
    [onFileSelected, onClientScan, disabled]
  );

  const dismiss = () => setClientResult(null);

  return (
    <div>
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); processFile(e.dataTransfer.files?.[0]); }}
        onClick={() => !disabled && !scanning && inputRef.current?.click()}
        className="relative transition-all cursor-pointer group"
        style={{
          border: `2px dashed ${dragging ? "var(--accent)" : "var(--border)"}`,
          borderRadius: "var(--radius-lg)",
          padding: "48px 32px",
          textAlign: "center",
          background: dragging ? "var(--accent-subtle)" : "var(--bg-elevated)",
          boxShadow: dragging ? "var(--shadow-glow)" : "var(--shadow-sm)",
          opacity: disabled || scanning ? 0.5 : 1,
          cursor: disabled || scanning ? "not-allowed" : "pointer",
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ALLOWED_EXTENSIONS.join(",")}
          className="hidden"
          onChange={(e) => processFile(e.target.files?.[0])}
          disabled={disabled || scanning}
        />

        {scanning ? (
          <>
            <div
              className="w-12 h-12 mx-auto mb-4 rounded-xl flex items-center justify-center"
              style={{ background: "var(--warning-subtle)", border: "1px solid var(--warning-muted)" }}
            >
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8} style={{ color: "var(--warning)", animation: "spin 1s linear infinite" }}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
              </svg>
            </div>
            <p className="text-[14px] font-medium" style={{ color: "var(--text-primary)" }}>
              Scanning for malicious content…
            </p>
          </>
        ) : (
          <>
            <div
              className="w-12 h-12 mx-auto mb-4 rounded-xl flex items-center justify-center transition-colors"
              style={{
                background: dragging ? "var(--accent-muted)" : "var(--bg-tertiary)",
                border: `1px solid ${dragging ? "var(--accent)" : "var(--border)"}`,
              }}
            >
              <svg width="20" height="20" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8} style={{ color: dragging ? "var(--accent)" : "var(--text-tertiary)" }}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
              </svg>
            </div>
            <p className="text-[14px] font-medium mb-1.5" style={{ color: "var(--text-primary)" }}>
              Drop a document here or click to browse
            </p>
            <p className="text-[12px] mb-1" style={{ color: "var(--text-secondary)" }}>
              .txt, .csv, .md, .json, .log, .xml, .pdf — up to 10 MB
            </p>
            <p className="text-[11px]" style={{ color: "var(--text-tertiary)" }}>
              Files are scanned for XSS and malware before processing
            </p>
          </>
        )}
      </div>

      {/* Blocked result */}
      {clientResult?.blocked && (
        <div className="card mt-4 animate-fade-in" style={{ borderColor: "var(--danger-muted)" }}>
          <div
            className="flex items-center gap-2 px-4 py-2.5"
            style={{ background: "var(--danger-subtle)" }}
          >
            <svg width="16" height="16" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--danger)" }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m0-10.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.75c0 5.592 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.249-8.25-3.286zm0 13.036h.008v.008H12v-.008z" />
            </svg>
            <span className="text-[13px] font-semibold" style={{ color: "var(--danger)" }}>
              Upload blocked — threat score: {clientResult.totalScore}
            </span>
          </div>
          <div className="p-4">
            {clientResult.findings.map((f, i) => {
              const colors = SEVERITY_COLORS[f.severity] || SEVERITY_COLORS.MEDIUM;
              return (
                <div key={i} className="flex items-center gap-2.5 py-2 text-[12px]">
                  <span
                    className="px-2 py-0.5 rounded-md text-[10px] font-semibold"
                    style={{ background: colors.bg, color: colors.text, border: `1px solid ${colors.border}` }}
                  >
                    {f.severity}
                  </span>
                  <span style={{ color: "var(--text-primary)" }}>{f.desc}</span>
                </div>
              );
            })}
            <button
              onClick={dismiss}
              className="mt-3 px-4 py-2 text-[12px] font-medium rounded-md transition-all hover:opacity-80"
              style={{ background: "var(--bg-tertiary)", border: "1px solid var(--border)", color: "var(--text-secondary)" }}
            >
              Dismiss and try another file
            </button>
          </div>
        </div>
      )}

      {/* Passed with warnings */}
      {clientResult && !clientResult.blocked && clientResult.findings.length > 0 && (
        <div
          className="mt-3 px-4 py-2.5 rounded-lg text-[12px] animate-fade-in"
          style={{ background: "var(--warning-subtle)", border: "1px solid var(--warning-muted)", color: "var(--warning)" }}
        >
          <span className="font-semibold">Client scan notice:</span> {clientResult.findings.length} low-risk
          pattern(s) detected — proceeding to server-side deep scan.
        </div>
      )}
    </div>
  );
}
