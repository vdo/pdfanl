"""
Configuration constants and settings for pdfanl.

This module centralizes all magic numbers and configurable values.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import os
import json
import logging

logger = logging.getLogger(__name__)

# File size limits
DEFAULT_MAX_FILE_SIZE_MB: int = 100
DEFAULT_MAX_FILE_SIZE_BYTES: int = DEFAULT_MAX_FILE_SIZE_MB * 1024 * 1024

# Header analysis
HEADER_BUFFER_SIZE: int = 1024

# JavaScript preview limits
JS_CODE_PREVIEW_LENGTH: int = 500

# Risk scoring thresholds
RISK_LEVEL_HIGH_THRESHOLD: int = 75
RISK_LEVEL_MEDIUM_THRESHOLD: int = 41
RISK_LEVEL_LOW_THRESHOLD: int = 1
RISK_MAX_SCORE: int = 100

# Risk factor scores
RISK_SCORE_JAVASCRIPT: int = 50
RISK_SCORE_JS_AUTO_ACTION: int = 40
RISK_SCORE_AUTO_ACTION_ONLY: int = 20
RISK_SCORE_LAUNCH: int = 35
RISK_SCORE_EMBEDDED: int = 20
RISK_SCORE_JBIG2: int = 25
RISK_SCORE_REMOTE_ACTION: int = 30
RISK_SCORE_RICHMEDIA: int = 20
RISK_SCORE_XFA: int = 15
RISK_SCORE_OBJSTM: int = 10
RISK_SCORE_SINGLE_PAGE_JS: int = 15
RISK_SCORE_HEADER_HIGH: int = 20
RISK_SCORE_HEADER_MEDIUM: int = 10
RISK_SCORE_VT_MAX: int = 50

# VirusTotal settings
VT_API_URL: str = "https://www.virustotal.com/api/v3/files"
VT_DEFAULT_TIMEOUT: int = 30
VT_MAX_RETRIES: int = 3
VT_RETRY_DELAY: float = 1.0
VT_RATE_LIMIT_DELAY: float = 60.0

# Annotation type mapping for PyMuPDF 1.26+
ANNOT_TYPE_NAMES: dict[int, str] = {
    0: 'Text',
    1: 'Link',
    2: 'FreeText',
    3: 'Line',
    4: 'Square',
    5: 'Circle',
    6: 'Polygon',
    7: 'PolyLine',
    8: 'Highlight',
    9: 'Underline',
    10: 'Squiggly',
    11: 'StrikeOut',
    12: 'Stamp',
    13: 'Caret',
    14: 'Ink',
    15: 'Popup',
    16: 'FileAttachment',
    17: 'Sound',
    18: 'Movie',
    19: 'Widget',
    20: 'Screen',
    21: 'PrinterMark',
    22: 'TrapNet',
    23: 'Watermark',
    24: '3D',
    25: 'Redact',
    26: 'Projection',
    27: 'RichMedia'
}

# Suspicious keywords to scan for
SUSPICIOUS_KEYWORDS: list[str] = [
    '/JS',
    '/JavaScript',
    '/AA',
    '/OpenAction',
    '/AcroForm',
    '/JBIG2Decode',
    '/RichMedia',
    '/Launch',
    '/EmbeddedFile',
    '/XFA',
    '/Encrypt',
    '/ObjStm',
    '/GoToE',
    '/GoToR',
    '/SubmitForm',
]

# Structural keywords (non-suspicious, for analysis)
STRUCTURAL_KEYWORDS: list[str] = [
    'obj',
    'endobj',
    'stream',
    'endstream',
]


@dataclass
class AnalyzerConfig:
    """Configuration for the PDF analyzer."""

    max_file_size_bytes: int = DEFAULT_MAX_FILE_SIZE_BYTES
    js_preview_length: int = JS_CODE_PREVIEW_LENGTH
    vt_api_key: str = ""
    vt_timeout: int = VT_DEFAULT_TIMEOUT
    vt_max_retries: int = VT_MAX_RETRIES
    vt_retry_delay: float = VT_RETRY_DELAY

    # Risk score overrides (optional)
    risk_scores: dict[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Load API key from environment if not provided."""
        if not self.vt_api_key:
            self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')

    @classmethod
    def from_file(cls, config_path: Path) -> 'AnalyzerConfig':
        """Load configuration from a JSON file."""
        if not config_path.exists():
            logger.warning(f"Config file not found: {config_path}, using defaults")
            return cls()

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return cls(**data)
        except (json.JSONDecodeError, TypeError) as e:
            logger.error(f"Failed to parse config file: {e}")
            return cls()

    def get_risk_score(self, factor: str, default: int) -> int:
        """Get risk score for a factor, allowing overrides."""
        return self.risk_scores.get(factor, default)

    def to_dict(self) -> dict:
        """Convert config to dictionary."""
        return {
            'max_file_size_bytes': self.max_file_size_bytes,
            'js_preview_length': self.js_preview_length,
            'vt_timeout': self.vt_timeout,
            'vt_max_retries': self.vt_max_retries,
            'vt_retry_delay': self.vt_retry_delay,
            'risk_scores': self.risk_scores,
        }

    def save(self, config_path: Path) -> None:
        """Save configuration to a JSON file."""
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(self.to_dict(), f, indent=2)


def get_default_config() -> AnalyzerConfig:
    """Get default analyzer configuration."""
    return AnalyzerConfig()
