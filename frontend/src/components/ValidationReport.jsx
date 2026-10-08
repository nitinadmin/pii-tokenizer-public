"use client";

export default function ValidationReport({ report }) {
  if (!report) {
    return (
      <div className="card">
        <div className="text-center py-16 text-[13px]" style={{ color: "var(--text-tertiary)" }}>
          Validation results will appear after the tokenizer completes.
        </div>
      </div>
    );
  }

  const passed = report.overall_status === "PASS";

  return (
    <div className="card" style={{ borderColor: passed ? "var(--success-muted)" : "var(--danger-muted)" }}>
      {/* Status header */}
      <div
        className="flex items-center gap-2.5 px-4 py-3"
        style={{ background: passed ? "var(--success-subtle)" : "var(--danger-subtle)" }}
      >
        <div
          className="w-7 h-7 rounded-full flex items-center justify-center"
          style={{ background: passed ? "var(--success-muted)" : "var(--danger-muted)" }}
        >
          {passed ? (
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} style={{ color: "var(--success)" }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          ) : (
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} style={{ color: "var(--danger)" }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
            </svg>
          )}
        </div>
        <div>
          <div className="text-[13px] font-semibold" style={{ color: passed ? "var(--success)" : "var(--danger)" }}>
            Validation {passed ? "passed" : "failed"}
          </div>
          <div className="text-[11px]" style={{ color: passed ? "var(--success)" : "var(--danger)", opacity: 0.75 }}>
            {report.confidence}% confidence
          </div>
        </div>
      </div>

      <div className="p-4">
        {/* Metrics */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-4">
          {[
            { label: "PII detected", value: report.total_pii },
            { label: "Tokenized", value: report.tokenized, color: "var(--success)" },
            { label: "Missed", value: report.missed, color: report.missed > 0 ? "var(--danger)" : "var(--success)" },
            { label: "Scan pass", value: report.scan_pass },
          ].map((m) => (
            <div key={m.label} className="metric-card">
              <div className="metric-label">{m.label}</div>
              <div className="metric-value" style={{ color: m.color || "var(--text-primary)" }}>
                {m.value}
              </div>
            </div>
          ))}
        </div>

        {/* Residual locations */}
        {report.residual_details?.length > 0 && (
          <div className="mb-4">
            <div className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-tertiary)" }}>
              Residual PII locations ({report.residual_details.length})
            </div>
            <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border-subtle)" }}>
              {report.residual_details.map((d, i) => (
                <div
                  key={i}
                  className="flex items-center gap-3 px-3 py-2 text-[12px] font-mono"
                  style={{
                    background: i % 2 === 0 ? "transparent" : "var(--bg-secondary)",
                    borderBottom: i < report.residual_details.length - 1 ? "1px solid var(--border-subtle)" : "none",
                  }}
                >
                  <span className="whitespace-nowrap font-semibold" style={{ color: "var(--warning)" }}>
                    L{d.line}:{d.column}
                  </span>
                  <span style={{ color: "var(--text-primary)" }}>{d.label}</span>
                  <span className="ml-auto text-[11px]" style={{ color: "var(--text-tertiary)" }}>{d.preview}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Issues */}
        {report.issues?.length > 0 && (
          <div className="mb-4">
            <div className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-tertiary)" }}>
              Issues
            </div>
            {report.issues.map((issue, i) => (
              <div
                key={i}
                className="flex items-center gap-2.5 py-2 px-3 text-[12px]"
                style={{ borderBottom: i < report.issues.length - 1 ? "1px solid var(--border-subtle)" : "none" }}
              >
                <svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--warning)", flexShrink: 0 }}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
                </svg>
                <span style={{ color: "var(--text-primary)" }}>{issue}</span>
              </div>
            ))}
          </div>
        )}

        {/* Verification checks */}
        {report.checks?.length > 0 && (
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-tertiary)" }}>
              Verification checks
            </div>
            {report.checks.map((check, i) => (
              <div key={i} className="flex items-center gap-2.5 py-1.5 px-3 text-[12px]">
                {check.passed ? (
                  <svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} style={{ color: "var(--success)", flexShrink: 0 }}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
                  </svg>
                ) : (
                  <svg width="13" height="13" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} style={{ color: "var(--danger)", flexShrink: 0 }}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                  </svg>
                )}
                <span style={{ color: "var(--text-primary)" }}>{check.name}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
