"""PDF report generator for risk assessment data.

Converts HTML reports to PDF using weasyprint when available.
Falls back gracefully to returning the HTML content if weasyprint is not installed.
"""

import base64
import os

import structlog

logger = structlog.get_logger()

try:
    import weasyprint  # type: ignore[import-untyped]

    WEASYPRINT_AVAILABLE = True
except (ImportError, OSError) as _exc:
    weasyprint = None  # type: ignore[assignment]
    WEASYPRINT_AVAILABLE = False
    logger.warning("weasyprint not available; PDF generation will fall back to HTML output", reason=str(_exc))


class PDFReportGenerator:
    """Generates PDF reports from risk assessment data or pre-built HTML."""

    def __init__(self):
        from mcp_servers.reporting.html_report import HTMLReportGenerator

        self._html_generator = HTMLReportGenerator()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, data: dict, output_path: str) -> str:
        """Generate a PDF report from risk assessment run data.

        Parameters
        ----------
        data : dict
            Same structure accepted by ``HTMLReportGenerator.generate``.
        output_path : str
            Filesystem path where the PDF will be written.

        Returns
        -------
        str
            The absolute path of the generated file.  If weasyprint is
            unavailable, the file will be an ``.html`` fallback and the
            returned path will reflect the changed extension.
        """
        logger.info("Generating PDF report", output_path=output_path)

        html_content = self._html_generator.generate(data)
        return self.generate_from_html(html_content, output_path)

    def generate_from_html(self, html: str, output_path: str) -> str:
        """Convert an existing HTML string to a PDF file.

        Parameters
        ----------
        html : str
            Complete HTML document.
        output_path : str
            Desired output path for the PDF.

        Returns
        -------
        str
            Absolute path of the written file.
        """
        if WEASYPRINT_AVAILABLE:
            return self._write_pdf(html, output_path)
        return self._fallback_html(html, output_path)

    def generate_base64(self, data: dict) -> tuple[str, str]:
        """Generate a PDF and return its content as a base64-encoded string.

        Returns
        -------
        tuple[str, str]
            (base64_content, format) where format is ``"pdf"`` or ``"html"``
            depending on weasyprint availability.
        """
        html_content = self._html_generator.generate(data)

        if WEASYPRINT_AVAILABLE:
            try:
                pdf_bytes = weasyprint.HTML(string=html_content).write_pdf()
                return base64.b64encode(pdf_bytes).decode("ascii"), "pdf"
            except Exception as e:
                logger.error("PDF generation failed, falling back to HTML", error=str(e))

        # Fallback: base64-encode the HTML itself
        return base64.b64encode(html_content.encode("utf-8")).decode("ascii"), "html"

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _write_pdf(self, html_content: str, output_path: str) -> str:
        """Write PDF using weasyprint."""
        try:
            output_path = os.path.abspath(output_path)
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            weasyprint.HTML(string=html_content).write_pdf(output_path)
            logger.info("PDF written successfully", path=output_path)
            return output_path
        except Exception as e:
            logger.error("weasyprint PDF write failed, falling back to HTML", error=str(e))
            return self._fallback_html(html_content, output_path)

    def _fallback_html(self, html_content: str, output_path: str) -> str:
        """Write HTML fallback when PDF generation is unavailable."""
        # Change extension to .html
        base, _ = os.path.splitext(output_path)
        html_path = base + ".html"
        html_path = os.path.abspath(html_path)

        os.makedirs(os.path.dirname(html_path), exist_ok=True)
        with open(html_path, "w", encoding="utf-8") as fh:
            fh.write(html_content)

        logger.warning(
            "PDF generation unavailable; wrote HTML fallback",
            path=html_path,
        )
        return html_path
