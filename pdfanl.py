#!/usr/bin/env python3
"""
PDF Analysis Tool using PyMuPDF (fitz)

This module provides backward compatibility with the original single-file
interface. For new code, prefer importing from the pdfanl package directly:

    from pdfanl import PDFAnalyzer, AnalyzerConfig

This tool analyzes PDF files and extracts:
- PDF version and basic metadata
- Links and annotations
- JavaScript code
- Form fields
- Virustotal analysis
- Resources (images, fonts, etc.)
- Security information
- Page statistics
"""

import sys
import warnings

# Re-export everything from the package for backward compatibility
from pdfanl import (
    PDFAnalyzer,
    PDFAnalysisError,
    FileTooLargeError,
    AnalyzerConfig,
    OutputFormatter,
    save_results,
    decode_stream,
    calculate_file_hashes,
    VirusTotalClient,
    VirusTotalError,
    check_virustotal,
)
from pdfanl.config import ANNOT_TYPE_NAMES
from pdfanl.cli import main

# For scripts that import REQUESTS_AVAILABLE
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Backward-compatible class with print_summary method
class PDFAnalyzerCompat(PDFAnalyzer):
    """
    Backward-compatible PDFAnalyzer with print_summary method.

    For new code, use PDFAnalyzer with OutputFormatter instead.
    """

    def print_summary(self) -> None:
        """Print analysis summary (backward compatibility)."""
        formatter = OutputFormatter(self.analysis_results)
        formatter.print_summary()

    def save_results(self, output_path: str) -> None:
        """Save results to JSON file (backward compatibility)."""
        save_results(self.analysis_results, output_path)
        print(f"\nAnalysis results saved to: {output_path}")


# Replace PDFAnalyzer with compatible version for this module
PDFAnalyzer = PDFAnalyzerCompat  # type: ignore


if __name__ == '__main__':
    sys.exit(main())
