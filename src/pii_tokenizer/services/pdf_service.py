import io

from pii_tokenizer.services.logger_service import PipelineLogger


class PDFExtractionError(Exception):
    """Raised when a PDF cannot be processed, with a user-facing message."""
    pass


# A page with fewer than this many extractable characters is treated as an
# image/scanned page. If most pages are like this, the PDF is scanned.
MIN_CHARS_PER_TEXT_PAGE = 30


def extract_text(content: bytes, log: PipelineLogger) -> str:
    """Extract text from a text-based PDF using pdfplumber.

    Raises PDFExtractionError with a clear message for:
    - encrypted / password-protected PDFs
    - scanned (image-only) PDFs — OCR is not enabled in this deployment
    - corrupt files that fail to parse
    """
    import pdfplumber

    log.info("[PDF] Opening PDF for text extraction (pdfplumber)...")

    try:
        with pdfplumber.open(io.BytesIO(content)) as pdf:
            n_pages = len(pdf.pages)
            log.info(f"[PDF] Document opened: {n_pages} page(s)")

            page_texts: list[str] = []
            empty_pages = 0
            for i, page in enumerate(pdf.pages):
                text = (page.extract_text() or "").strip()
                if len(text) < MIN_CHARS_PER_TEXT_PAGE:
                    empty_pages += 1
                page_texts.append(text)
                log.info(f"[PDF] Page {i + 1}/{n_pages}: extracted {len(text)} characters")

    except PDFExtractionError:
        raise
    except Exception as e:
        msg = str(e).lower()
        if "password" in msg or "encrypt" in msg or "decrypt" in msg:
            log.error("[PDF] Document is password-protected")
            raise PDFExtractionError(
                "This PDF is password-protected. Remove the password and re-upload."
            ) from e
        log.error(f"[PDF] Failed to parse document: {type(e).__name__}")
        raise PDFExtractionError(
            "This PDF could not be parsed. It may be corrupt or use an unsupported format."
        ) from e

    if n_pages == 0:
        raise PDFExtractionError("This PDF contains no pages.")

    # Scanned-PDF detection: if most pages yielded essentially no text,
    # the document is image-based and needs OCR, which is not enabled.
    if empty_pages / n_pages > 0.5:
        log.error(
            f"[PDF] {empty_pages}/{n_pages} pages have no extractable text — "
            "document appears to be scanned"
        )
        raise PDFExtractionError(
            f"This PDF appears to be scanned (no extractable text on "
            f"{empty_pages} of {n_pages} pages). OCR is not enabled in this "
            "deployment — upload a text-based PDF or a plain-text export."
        )

    full_text = "\n\n".join(
        f"--- Page {i + 1} ---\n{t}" for i, t in enumerate(page_texts) if t
    )
    log.success(f"[PDF] Extraction complete: {len(full_text)} characters from {n_pages} page(s)")
    return full_text
