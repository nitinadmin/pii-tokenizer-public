import "./globals.css";

export const metadata = {
  title: "PII Tokenization Pipeline",
  description:
    "Upload documents, detect and tokenize PII, validate, and generate LLM summaries.",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
