"""
VirusTotal API client with retry logic.

Provides hash-based scanning against VirusTotal's database.
"""

import logging
import time
from dataclasses import dataclass
from typing import Any, Optional

from .config import (
    VT_API_URL,
    VT_DEFAULT_TIMEOUT,
    VT_MAX_RETRIES,
    VT_RATE_LIMIT_DELAY,
    VT_RETRY_DELAY,
)

logger = logging.getLogger(__name__)

# Optional requests import
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    requests = None  # type: ignore
    REQUESTS_AVAILABLE = False


class VirusTotalError(Exception):
    """Base exception for VirusTotal errors."""

    pass


class VirusTotalRateLimitError(VirusTotalError):
    """Raised when rate limit is exceeded."""

    pass


class VirusTotalAPIError(VirusTotalError):
    """Raised when API returns an error."""

    def __init__(self, message: str, status_code: int):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class VTScanResult:
    """Result from VirusTotal scan."""

    found: bool
    sha256: str
    malicious: int = 0
    suspicious: int = 0
    undetected: int = 0
    harmless: int = 0
    total_engines: int = 0
    threat_name: str = ""
    names: list[str] | None = None
    tags: list[str] | None = None
    detections: list[dict[str, str]] | None = None
    first_submission: str = ""
    last_analysis: str = ""

    @property
    def is_malicious(self) -> bool:
        """Check if file is flagged as malicious."""
        return self.malicious > 0

    @property
    def detection_ratio(self) -> float:
        """Get detection ratio (0.0 to 1.0)."""
        if self.total_engines == 0:
            return 0.0
        return self.malicious / self.total_engines


class VirusTotalClient:
    """
    Client for VirusTotal API with retry support.

    Only performs hash lookups - no file uploads.
    """

    def __init__(
        self,
        api_key: str,
        timeout: int = VT_DEFAULT_TIMEOUT,
        max_retries: int = VT_MAX_RETRIES,
        retry_delay: float = VT_RETRY_DELAY,
    ):
        """
        Initialize VirusTotal client.

        Args:
            api_key: VirusTotal API key.
            timeout: Request timeout in seconds.
            max_retries: Maximum number of retry attempts.
            retry_delay: Delay between retries in seconds.

        Raises:
            VirusTotalError: If requests library is not available.
        """
        if not REQUESTS_AVAILABLE:
            raise VirusTotalError("requests library not installed")

        if not api_key:
            raise VirusTotalError("API key is required")

        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay

    def check_hash(self, sha256: str) -> VTScanResult:
        """
        Check a file hash against VirusTotal.

        Args:
            sha256: SHA256 hash of the file.

        Returns:
            VTScanResult with scan details.

        Raises:
            VirusTotalError: On API errors.
            VirusTotalRateLimitError: When rate limit is exceeded after retries.
        """
        url = f"{VT_API_URL}/{sha256}"
        headers = {'x-apikey': self.api_key}

        last_error: Optional[Exception] = None

        for attempt in range(self.max_retries + 1):
            try:
                response = requests.get(url, headers=headers, timeout=self.timeout)
                return self._parse_response(response, sha256)

            except requests.exceptions.Timeout:
                last_error = VirusTotalError("Request timed out")
                logger.warning(f"VT request timed out (attempt {attempt + 1}/{self.max_retries + 1})")

            except requests.exceptions.RequestException as e:
                last_error = VirusTotalError(f"Request failed: {e}")
                logger.warning(f"VT request failed (attempt {attempt + 1}): {e}")

            except VirusTotalRateLimitError:
                if attempt < self.max_retries:
                    logger.info(f"Rate limited, waiting {VT_RATE_LIMIT_DELAY}s before retry")
                    time.sleep(VT_RATE_LIMIT_DELAY)
                    continue
                raise

            # Wait before retry
            if attempt < self.max_retries:
                time.sleep(self.retry_delay * (attempt + 1))

        raise last_error or VirusTotalError("Unknown error after retries")

    def _parse_response(self, response: requests.Response, sha256: str) -> VTScanResult:
        """Parse VirusTotal API response."""
        if response.status_code == 200:
            return self._parse_found_response(response.json(), sha256)

        if response.status_code == 404:
            logger.info(f"File not found in VT database: {sha256}")
            return VTScanResult(found=False, sha256=sha256)

        if response.status_code == 429:
            raise VirusTotalRateLimitError("API rate limit exceeded")

        raise VirusTotalAPIError(
            f"API returned status {response.status_code}",
            response.status_code
        )

    def _parse_found_response(self, data: dict[str, Any], sha256: str) -> VTScanResult:
        """Parse successful VirusTotal response."""
        attributes = data.get('data', {}).get('attributes', {})
        stats = attributes.get('last_analysis_stats', {})
        results = attributes.get('last_analysis_results', {})

        # Extract detections
        detections = []
        if results:
            for engine, result in results.items():
                if result.get('category') in ['malicious', 'suspicious']:
                    detections.append({
                        'engine': engine,
                        'category': result.get('category', ''),
                        'result': result.get('result', 'N/A')
                    })

        threat_classification = attributes.get('popular_threat_classification', {})

        return VTScanResult(
            found=True,
            sha256=sha256,
            malicious=stats.get('malicious', 0),
            suspicious=stats.get('suspicious', 0),
            undetected=stats.get('undetected', 0),
            harmless=stats.get('harmless', 0),
            total_engines=sum(stats.values()) if stats else 0,
            threat_name=threat_classification.get('suggested_threat_label', ''),
            names=attributes.get('names', []),
            tags=attributes.get('tags', []),
            detections=detections,
            first_submission=str(attributes.get('first_submission_date', '')),
            last_analysis=str(attributes.get('last_analysis_date', '')),
        )


def check_virustotal(
    sha256: str,
    api_key: str,
    timeout: int = VT_DEFAULT_TIMEOUT,
    max_retries: int = VT_MAX_RETRIES,
) -> dict[str, Any]:
    """
    Convenience function to check a hash against VirusTotal.

    Args:
        sha256: SHA256 hash to check.
        api_key: VirusTotal API key.
        timeout: Request timeout.
        max_retries: Max retry attempts.

    Returns:
        Dictionary with scan results and metadata.
    """
    result: dict[str, Any] = {
        'checked': False,
        'api_available': REQUESTS_AVAILABLE,
        'api_key_present': bool(api_key),
        'hashes': {'sha256': sha256},
        'scan_results': {},
        'error': None
    }

    if not REQUESTS_AVAILABLE:
        result['error'] = 'requests library not installed'
        return result

    if not api_key:
        result['error'] = 'VIRUSTOTAL_API_KEY not set'
        return result

    try:
        client = VirusTotalClient(api_key, timeout=timeout, max_retries=max_retries)
        scan = client.check_hash(sha256)

        result['checked'] = True

        if not scan.found:
            result['scan_results'] = {
                'sha256': sha256,
                'message': 'File not found in VirusTotal database',
                'status': 'not_found'
            }
        else:
            result['scan_results'] = {
                'sha256': sha256,
                'first_submission': scan.first_submission,
                'last_analysis': scan.last_analysis,
                'stats': {
                    'malicious': scan.malicious,
                    'suspicious': scan.suspicious,
                    'undetected': scan.undetected,
                    'harmless': scan.harmless,
                },
                'malicious': scan.malicious,
                'suspicious': scan.suspicious,
                'undetected': scan.undetected,
                'harmless': scan.harmless,
                'total_engines': scan.total_engines,
                'popular_threat_name': scan.threat_name or 'N/A',
                'names': scan.names or [],
                'tags': scan.tags or [],
                'detections': scan.detections or [],
            }

    except VirusTotalRateLimitError:
        result['error'] = 'VirusTotal API rate limit exceeded (even after retries)'
    except VirusTotalError as e:
        result['error'] = str(e)

    return result
