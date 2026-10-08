"use client";

// The server sends a masked `preview` for each token; original values never
// leave the backend.
export default function TokenMap({ tokens }) {
  if (!tokens || tokens.length === 0) {
    return (
      <div className="card">
        <div className="text-center py-16 text-[13px]" style={{ color: "var(--text-tertiary)" }}>
          Token mappings will appear after tokenization completes.
        </div>
      </div>
    );
  }

  const grouped = {};
  tokens.forEach((t) => {
    const key = t.pii_type || t.type;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(t);
  });

  return (
    <div className="card">
      <div className="card-header">
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)" }}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M15.75 5.25a3 3 0 013 3m3 0a6 6 0 01-7.029 5.912c-.563-.097-1.159.026-1.563.43L10.5 17.25H8.25v2.25H6v2.25H2.25v-2.818c0-.597.237-1.17.659-1.591l6.499-6.499c.404-.404.527-1 .43-1.563A6 6 0 1121.75 8.25z" />
        </svg>
        <span className="card-header-label">Token vault</span>

        <span className="ml-auto text-[11px]" style={{ color: "var(--text-tertiary)" }}>
          Originals are stored only in the vault bucket
        </span>

        <span className="badge badge-accent ml-2">{tokens.length} tokens</span>
      </div>

      <div className="p-4 max-h-[380px] overflow-y-auto custom-scroll">
        {Object.entries(grouped).map(([type, items]) => (
          <div key={type} className="mb-4 last:mb-0">
            <div
              className="text-[10px] font-semibold uppercase tracking-widest mb-2 px-1"
              style={{ color: "var(--text-tertiary)" }}
            >
              {items[0]?.label || type}
            </div>
            <div className="rounded-lg overflow-hidden" style={{ border: "1px solid var(--border-subtle)" }}>
              {items.map((t, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2.5 px-3 py-2 text-[12px] font-mono"
                  style={{
                    background: i % 2 === 0 ? "transparent" : "var(--bg-secondary)",
                    borderBottom: i < items.length - 1 ? "1px solid var(--border-subtle)" : "none",
                  }}
                >
                  <span className="token-highlight whitespace-nowrap text-[11px]">
                    {t.token}
                  </span>
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)", flexShrink: 0 }}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M13.5 4.5L21 12m0 0l-7.5 7.5M21 12H3" />
                  </svg>
                  <span
                    className="break-all"
                    style={{ color: "var(--text-tertiary)" }}
                  >
                    {t.preview}
                  </span>
                  <span
                    className="ml-auto text-[10px] font-medium whitespace-nowrap px-1.5 py-0.5 rounded"
                    style={{ background: "var(--bg-tertiary)", color: "var(--text-tertiary)" }}
                  >
                    {t.engine}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
