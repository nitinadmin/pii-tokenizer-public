"use client";

const STEPS = [
  { id: "upload", label: "Upload" },
  { id: "security", label: "Security" },
  { id: "s3", label: "S3" },
  { id: "tokenize", label: "Tokenize" },
  { id: "validate", label: "Validate" },
  { id: "llm", label: "LLM" },
  { id: "output", label: "Output" },
];

function StepDot({ status }) {
  const isActive = status === "running" || status === "retrying";
  const isDone = status === "complete" || status === "pass";
  const isFail = status === "fail";
  const isSkipped = status === "skipped";

  const dotColor = isFail
    ? "var(--danger)"
    : isDone
    ? "var(--success)"
    : isActive
    ? "var(--accent)"
    : "var(--border)";

  const bgColor = isFail
    ? "var(--danger-subtle)"
    : isDone
    ? "var(--success-subtle)"
    : isActive
    ? "var(--accent-subtle)"
    : "var(--bg-tertiary)";

  return (
    <div
      className="relative flex items-center justify-center"
      style={{
        width: 28,
        height: 28,
        borderRadius: "50%",
        background: bgColor,
        border: `2px solid ${dotColor}`,
        transition: "all 0.3s ease",
        animation: isActive ? "pulse-ring 2s ease-in-out infinite" : "none",
      }}
    >
      {isDone ? (
        <svg width="12" height="12" fill="none" viewBox="0 0 24 24" stroke={dotColor} strokeWidth={3}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
        </svg>
      ) : isFail ? (
        <svg width="11" height="11" fill="none" viewBox="0 0 24 24" stroke={dotColor} strokeWidth={3}>
          <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
        </svg>
      ) : isActive ? (
        <div
          className="rounded-full"
          style={{
            width: 8,
            height: 8,
            background: dotColor,
            animation: "pulse-ring 1.5s ease-in-out infinite",
          }}
        />
      ) : isSkipped ? (
        <div className="rounded-full" style={{ width: 4, height: 4, background: "var(--text-tertiary)" }} />
      ) : (
        <div className="rounded-full" style={{ width: 6, height: 6, background: dotColor }} />
      )}
    </div>
  );
}

export default function StepIndicator({ statuses }) {
  const hasAny = Object.keys(statuses).length > 0;
  if (!hasAny) return null;

  return (
    <div
      className="flex items-center gap-0 px-4 py-3 mb-5 rounded-xl overflow-x-auto"
      style={{
        background: "var(--bg-elevated)",
        border: "1px solid var(--border)",
        boxShadow: "var(--shadow-sm)",
      }}
    >
      {STEPS.map((step, i) => {
        const raw = statuses[step.id] || "pending";
        const isActive = raw === "running" || raw === "retrying";
        const isDone = raw === "complete" || raw === "pass";

        return (
          <div key={step.id} className="flex items-center flex-1 min-w-0">
            <div className="flex flex-col items-center gap-1.5 min-w-[56px]">
              <StepDot status={raw} />
              <span
                className="text-[10px] font-medium tracking-wide whitespace-nowrap transition-colors"
                style={{
                  color: isActive
                    ? "var(--accent)"
                    : isDone
                    ? "var(--success)"
                    : raw === "fail"
                    ? "var(--danger)"
                    : "var(--text-tertiary)",
                  fontWeight: isActive ? 600 : 500,
                }}
              >
                {step.label}
              </span>
            </div>
            {i < STEPS.length - 1 && (
              <div
                className="flex-1 min-w-[8px] mx-0.5 mb-5"
                style={{
                  height: 2,
                  borderRadius: 1,
                  background: isDone ? "var(--success)" : "var(--border)",
                  transition: "background 0.4s ease",
                }}
              />
            )}
          </div>
        );
      })}
    </div>
  );
}
