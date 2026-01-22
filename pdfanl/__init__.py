"""
pdfanl - PDF Analysis Tool with Malware Detection

A comprehensive CLI tool for analyzing PDF files with advanced
malware detection capabilities.
"""

from .analyzer import (
    FileTooLargeError,
    PDFAnalysisError,
    PDFAnalyzer,
)
from .config import (
    AnalyzerConfig,
    get_default_config,
)
from .output import (
    OutputFormatter,
    print_detailed_results,
    save_results,
)
from .utils import (
    calculate_file_hashes,
    decode_stream,
    format_file_size,
)
from .vt_client import (
    VirusTotalClient,
    VirusTotalError,
    VirusTotalRateLimitError,
    VTScanResult,
    check_virustotal,
)

__version__ = "2.0.0"
__author__ = "pdfanl contributors"

__all__ = [
    # Analyzer
    "PDFAnalyzer",
    "PDFAnalysisError",
    "FileTooLargeError",
    # Config
    "AnalyzerConfig",
    "get_default_config",
    # Output
    "OutputFormatter",
    "save_results",
    "print_detailed_results",
    # Utils
    "decode_stream",
    "calculate_file_hashes",
    "format_file_size",
    # VirusTotal
    "VirusTotalClient",
    "VirusTotalError",
    "VirusTotalRateLimitError",
    "VTScanResult",
    "check_virustotal",
]
