"use client";
import { useEffect, useRef } from "react";

const LEVEL_STYLE = {
  INFO:    { bg: "var(--accent-subtle)", text: "var(--accent)", border: "var(--accent-muted)" },
  WARN:    { bg: "var(--warning-subtle)", text: "var(--warning)", border: "var(--warning-muted)" },
  ERROR:   { bg: "var(--danger-subtle)", text: "var(--danger)", border: "var(--danger-muted)" },
  SUCCESS: { bg: "var(--success-subtle)", text: "var(--success)", border: "var(--success-muted)" },
};

export default function LogPanel({ logs }) {
  const scrollRef = useRef(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="card">
      <div className="card-header">
        <svg width="14" height="14" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ color: "var(--text-tertiary)" }}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M6.75 7.5l3 2.25-3 2.25m4.5 0h3m-9 8.25h13.5A2.25 2.25 0 0021 18V6a2.25 2.25 0 00-2.25-2.25H5.25A2.25 2.25 0 003 6v12a2.25 2.25 0 002.25 2.25z" />
        </svg>
        <span className="card-header-label">Activity log</span>
        <span className="badge badge-accent ml-auto">{logs.length}</span>
      </div>

      <div
        ref={scrollRef}
        className="p-3 overflow-y-auto font-mono text-[11px] leading-relaxed custom-scroll"
        style={{ maxHeight: 360 }}
      >
        {logs.length === 0 ? (
          <div className="text-center py-8 text-[12px]" style={{ color: "var(--text-tertiary)", fontFamily: "Inter, sans-serif" }}>
            Waiting for pipeline activity…
          </div>
        ) : (
          logs.map((log, i) => {
            const s = LEVEL_STYLE[log.level] || LEVEL_STYLE.INFO;
            return (
              <div
                key={i}
                className="flex gap-2.5 py-1.5 animate-slide-in"
                style={{
                  borderBottom: i < logs.length - 1 ? "1px solid var(--border-subtle)" : "none",
                  animationDelay: `${Math.min(i * 20, 300)}ms`,
                }}
              >
                <span className="whitespace-nowrap flex-shrink-0" style={{ color: "var(--text-tertiary)" }}>
                  {log.time}
                </span>
                <span
                  className="flex-shrink-0 px-1.5 py-px rounded text-[9px] font-semibold leading-[18px] tracking-wide"
                  style={{ background: s.bg, color: s.text, border: `1px solid ${s.border}` }}
                >
                  {log.level}
                </span>
                <span className="break-words" style={{ color: "var(--text-primary)" }}>
                  {log.message}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
