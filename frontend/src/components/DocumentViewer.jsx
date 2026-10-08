"use client";
import { useState } from "react";

function HighlightedTokens({ text }) {
  const parts = text.split(/(\[TOKEN_[A-Z_]+_\d{3}\])/g);
  return (
    <>
      {parts.map((part, i) =>
        /^\[TOKEN_/.test(part) ? (
          <span key={i} className="token-highlight">{part}</span>
        ) : (
          <span key={i}>{part}</span>
        )
      )}
    </>
  );
}

export default function DocumentViewer({ original, tokenized }) {
  const [view, setView] = useState("original");
  const hasTokenized = !!tokenized;

  return (
    <div className="card">
      <div className="card-header">
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)" }}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
        </svg>
        <span className="card-header-label">
          {view === "tokenized" ? "Tokenized output" : "Original document"}
        </span>

        {hasTokenized && (
          <div className="ml-auto flex gap-1 p-0.5 rounded-md" style={{ background: "var(--bg-secondary)" }}>
            {["original", "tokenized"].map((v) => (
              <button
                key={v}
                onClick={() => setView(v)}
                className="px-3 py-1 text-[11px] font-medium rounded transition-all"
                style={{
                  background: view === v ? "var(--bg-elevated)" : "transparent",
                  color: view === v ? "var(--text-primary)" : "var(--text-tertiary)",
                  boxShadow: view === v ? "var(--shadow-sm)" : "none",
                }}
              >
                {v === "original" ? "Original" : "Tokenized"}
              </button>
            ))}
          </div>
        )}
      </div>

      <pre
        className="p-5 overflow-y-auto font-mono text-[12px] leading-relaxed whitespace-pre-wrap break-words custom-scroll"
        style={{ maxHeight: 440, color: "var(--text-primary)" }}
      >
        {view === "tokenized" && tokenized ? (
          <HighlightedTokens text={tokenized} />
        ) : (
          original || (
            <span style={{ color: "var(--text-tertiary)" }}>No document loaded.</span>
          )
        )}
      </pre>
    </div>
  );
}
