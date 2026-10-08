"use client";

const GD_STATUS = {
  CLEAN: { label: "No threats found", color: "var(--success)" },
  THREAT: { label: "Malware detected", color: "var(--danger)" },
  SKIPPED: { label: "Skipped (dev mode)", color: "var(--warning)" },
  PENDING: { label: "Scan in progress…", color: "var(--warning)" },
  TIMEOUT: { label: "Scan timed out", color: "var(--warning)" },
  ERROR: { label: "Scan error", color: "var(--warning)" },
  BLOCKED_UNAVAILABLE: { label: "Blocked (fail-closed)", color: "var(--danger)" },
};

const SEVERITY_STYLE = {
  CRITICAL: { bg: "var(--danger-subtle)", text: "var(--danger)", border: "var(--danger-muted)" },
  HIGH: { bg: "var(--warning-subtle)", text: "var(--warning)", border: "var(--warning-muted)" },
  MEDIUM: { bg: "var(--warning-subtle)", text: "var(--warning)", border: "var(--warning-muted)" },
  LOW: { bg: "var(--accent-subtle)", text: "var(--accent)", border: "var(--accent-muted)" },
};

export default function SecurityReport({ scan }) {
  if (!scan) return null;
  const passed = scan.passed;

  return (
    <div className="card" style={{ borderColor: passed ? "var(--success-muted)" : "var(--danger-muted)" }}>
      {/* Status header */}
      <div
        className="flex items-center gap-2.5 px-4 py-3"
        style={{ background: passed ? "var(--success-subtle)" : "var(--danger-subtle)" }}
      >
        <div
          className="w-7 h-7 rounded-full flex items-center justify-center"
          style={{
            background: passed ? "var(--success-muted)" : "var(--danger-muted)",
          }}
        >
          {passed ? (
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} style={{ color: "var(--success)" }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
            </svg>
          ) : (
            <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} style={{ color: "var(--danger)" }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          )}
        </div>
        <div>
          <div className="text-[13px] font-semibold" style={{ color: passed ? "var(--success)" : "var(--danger)" }}>
            Security scan {passed ? "passed" : "failed"}
          </div>
          <div className="text-[11px]" style={{ color: passed ? "var(--success)" : "var(--danger)", opacity: 0.75 }}>
            Threat score: {scan.threat_score}
          </div>
        </div>
      </div>

      <div className="p-4">
        {/* Metrics */}
        <div className="grid grid-cols-3 gap-3 mb-4">
          <div className="metric-card">
            <div className="metric-label">Threat score</div>
            <div className="metric-value" style={{ color: scan.threat_score > 0 ? "var(--danger)" : "var(--success)" }}>
              {scan.threat_score}
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">Findings</div>
            <div className="metric-value" style={{ color: scan.findings?.length > 0 ? "var(--warning)" : "var(--success)" }}>
              {scan.findings?.length || 0}
            </div>
          </div>
          <div className="metric-card">
            <div className="metric-label">GuardDuty</div>
            <div
              className="text-[13px] font-semibold mt-1"
              style={{ color: GD_STATUS[scan.guardduty_status]?.color || "var(--text-tertiary)" }}
            >
              {GD_STATUS[scan.guardduty_status]?.label || scan.guardduty_status}
            </div>
          </div>
        </div>

        {/* Engines */}
        <div className="mb-4">
          <div className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-tertiary)" }}>
            Scan engines
          </div>
          <div className="flex flex-wrap gap-1.5">
            {scan.scanned_engines?.map((engine, i) => (
              <span key={i} className="badge badge-accent">{engine}</span>
            ))}
          </div>
        </div>

        {/* Findings */}
        {scan.findings?.length > 0 && (
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--text-tertiary)" }}>
              Findings
            </div>
            <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border-subtle)" }}>
              {scan.findings.map((f, i) => {
                const s = SEVERITY_STYLE[f.severity] || SEVERITY_STYLE.LOW;
                return (
                  <div
                    key={i}
                    className="flex items-start gap-2.5 px-3 py-2.5 text-[12px]"
                    style={{
                      borderBottom: i < scan.findings.length - 1 ? "1px solid var(--border-subtle)" : "none",
                    }}
                  >
                    <span
                      className="flex-shrink-0 px-2 py-0.5 rounded text-[10px] font-semibold mt-0.5"
                      style={{ background: s.bg, color: s.text, border: `1px solid ${s.border}` }}
                    >
                      {f.severity}
                    </span>
                    <div>
                      <div className="font-medium" style={{ color: "var(--text-primary)" }}>{f.description}</div>
                      {f.detail && (
                        <div className="mt-0.5 font-mono text-[11px]" style={{ color: "var(--text-tertiary)" }}>
                          {f.detail}
                        </div>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {passed && scan.findings?.length === 0 && (
          <div className="text-center py-6 text-[13px] font-medium" style={{ color: "var(--success)" }}>
            All security checks passed — no threats detected.
          </div>
        )}
      </div>
    </div>
  );
}
