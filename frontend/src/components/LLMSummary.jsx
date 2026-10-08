"use client";

export default function LLMSummary({ summary, isLoading }) {
  if (isLoading) {
    return (
      <div className="card">
        <div className="text-center py-16">
          <div
            className="w-10 h-10 mx-auto mb-3 rounded-lg flex items-center justify-center"
            style={{ background: "var(--accent-subtle)", border: "1px solid var(--accent-muted)" }}
          >
            <svg width="18" height="18" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.8} style={{ color: "var(--accent)", animation: "spin 1.5s linear infinite" }}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
            </svg>
          </div>
          <p className="text-[13px] font-medium" style={{ color: "var(--text-secondary)" }}>
            Generating summary from tokenized document…
          </p>
          <div className="mt-3 mx-auto loading-shimmer rounded" style={{ width: 200, height: 4 }} />
        </div>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="card">
        <div className="text-center py-16 text-[13px]" style={{ color: "var(--text-tertiary)" }}>
          Summary will appear after validation passes.
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)" }}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M9.813 15.904L9 18.75l-.813-2.846a4.5 4.5 0 00-3.09-3.09L2.25 12l2.846-.813a4.5 4.5 0 003.09-3.09L9 5.25l.813 2.846a4.5 4.5 0 003.09 3.09L15.75 12l-2.846.813a4.5 4.5 0 00-3.09 3.09zM18.259 8.715L18 9.75l-.259-1.035a3.375 3.375 0 00-2.455-2.456L14.25 6l1.036-.259a3.375 3.375 0 002.455-2.456L18 2.25l.259 1.035a3.375 3.375 0 002.455 2.456L21.75 6l-1.036.259a3.375 3.375 0 00-2.455 2.456z" />
        </svg>
        <span className="card-header-label">LLM Summary</span>
        <span className="badge badge-accent ml-auto">Tokenized input only</span>
      </div>
      <div
        className="p-5 overflow-y-auto text-[13px] leading-[1.75] whitespace-pre-wrap break-words custom-scroll"
        style={{ maxHeight: 440, color: "var(--text-primary)" }}
      >
        {summary}
      </div>
    </div>
  );
}
