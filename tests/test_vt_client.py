"""Tests for pdfanl.vt_client module."""

from unittest.mock import MagicMock, patch

import pytest

from pdfanl.vt_client import (
    REQUESTS_AVAILABLE,
    VTScanResult,
    VirusTotalAPIError,
    VirusTotalClient,
    VirusTotalError,
    VirusTotalRateLimitError,
    check_virustotal,
)


class TestVTScanResult:
    """Tests for VTScanResult dataclass."""

    def test_basic_result(self) -> None:
        """Test basic scan result."""
        result = VTScanResult(
            found=True,
            sha256='abc123',
            malicious=5,
            total_engines=70,
        )
        assert result.found
        assert result.malicious == 5
        assert result.is_malicious

    def test_clean_result(self) -> None:
        """Test clean scan result."""
        result = VTScanResult(
            found=True,
            sha256='abc123',
            malicious=0,
            total_engines=70,
        )
        assert not result.is_malicious

    def test_not_found_result(self) -> None:
        """Test not found scan result."""
        result = VTScanResult(found=False, sha256='abc123')
        assert not result.found
        assert not result.is_malicious

    def test_detection_ratio(self) -> None:
        """Test detection ratio calculation."""
        result = VTScanResult(
            found=True,
            sha256='abc123',
            malicious=10,
            total_engines=100,
        )
        assert result.detection_ratio == 0.1

    def test_detection_ratio_zero_engines(self) -> None:
        """Test detection ratio with zero engines."""
        result = VTScanResult(
            found=True,
            sha256='abc123',
            malicious=0,
            total_engines=0,
        )
        assert result.detection_ratio == 0.0


@pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
class TestVirusTotalClient:
    """Tests for VirusTotalClient."""

    def test_init_without_api_key(self) -> None:
        """Test initialization without API key raises error."""
        with pytest.raises(VirusTotalError, match="API key is required"):
            VirusTotalClient(api_key='')

    def test_init_with_api_key(self) -> None:
        """Test successful initialization."""
        client = VirusTotalClient(api_key='test_key')
        assert client.api_key == 'test_key'

    @patch('pdfanl.vt_client.requests')
    def test_check_hash_found(self, mock_requests: MagicMock) -> None:
        """Test checking hash that is found."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {
                'attributes': {
                    'last_analysis_stats': {
                        'malicious': 5,
                        'suspicious': 1,
                        'undetected': 60,
                        'harmless': 4,
                    },
                    'last_analysis_results': {
                        'AVG': {
                            'category': 'malicious',
                            'result': 'Trojan.PDF'
                        }
                    },
                    'popular_threat_classification': {
                        'suggested_threat_label': 'trojan.pdf/generic'
                    }
                }
            }
        }
        mock_requests.get.return_value = mock_response

        client = VirusTotalClient(api_key='test_key')
        result = client.check_hash('abc123def456')

        assert result.found
        assert result.malicious == 5
        assert result.suspicious == 1
        assert result.total_engines == 70
        assert len(result.detections or []) == 1

    @patch('pdfanl.vt_client.requests')
    def test_check_hash_not_found(self, mock_requests: MagicMock) -> None:
        """Test checking hash that is not found."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_requests.get.return_value = mock_response

        client = VirusTotalClient(api_key='test_key')
        result = client.check_hash('abc123def456')

        assert not result.found

    @patch('pdfanl.vt_client.requests')
    def test_check_hash_rate_limit(self, mock_requests: MagicMock) -> None:
        """Test rate limit handling."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_requests.get.return_value = mock_response

        client = VirusTotalClient(api_key='test_key', max_retries=0)

        with pytest.raises(VirusTotalRateLimitError):
            client.check_hash('abc123def456')

    @patch('pdfanl.vt_client.requests')
    def test_check_hash_api_error(self, mock_requests: MagicMock) -> None:
        """Test API error handling."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_requests.get.return_value = mock_response

        client = VirusTotalClient(api_key='test_key', max_retries=0)

        with pytest.raises(VirusTotalAPIError) as exc_info:
            client.check_hash('abc123def456')
        assert exc_info.value.status_code == 500

    @patch('pdfanl.vt_client.requests')
    def test_timeout_retry(self, mock_requests: MagicMock) -> None:
        """Test timeout triggers retry."""
        import requests as real_requests

        # First call times out, second succeeds
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'data': {'attributes': {'last_analysis_stats': {}}}
        }

        mock_requests.get.side_effect = [
            real_requests.exceptions.Timeout(),
            mock_response
        ]
        mock_requests.exceptions = real_requests.exceptions

        client = VirusTotalClient(
            api_key='test_key',
            max_retries=1,
            retry_delay=0.01
        )
        result = client.check_hash('abc123')

        assert result.found
        assert mock_requests.get.call_count == 2


class TestCheckVirusTotalFunction:
    """Tests for check_virustotal convenience function."""

    def test_no_requests_library(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test handling when requests is not available."""
        monkeypatch.setattr('pdfanl.vt_client.REQUESTS_AVAILABLE', False)
        result = check_virustotal('abc123', 'test_key')
        assert not result['checked']
        assert 'not installed' in result['error']

    def test_no_api_key(self) -> None:
        """Test handling when API key is missing."""
        result = check_virustotal('abc123', '')
        assert not result['checked']
        assert 'not set' in result['error']

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    @patch('pdfanl.vt_client.VirusTotalClient')
    def test_successful_check(self, mock_client_class: MagicMock) -> None:
        """Test successful hash check."""
        mock_client = MagicMock()
        mock_client.check_hash.return_value = VTScanResult(
            found=True,
            sha256='abc123',
            malicious=3,
            total_engines=70,
        )
        mock_client_class.return_value = mock_client

        result = check_virustotal('abc123', 'test_key')

        assert result['checked']
        assert result['scan_results']['malicious'] == 3

    @pytest.mark.skipif(not REQUESTS_AVAILABLE, reason="requests not installed")
    @patch('pdfanl.vt_client.VirusTotalClient')
    def test_not_found_check(self, mock_client_class: MagicMock) -> None:
        """Test hash not found in database."""
        mock_client = MagicMock()
        mock_client.check_hash.return_value = VTScanResult(
            found=False,
            sha256='abc123',
        )
        mock_client_class.return_value = mock_client

        result = check_virustotal('abc123', 'test_key')

        assert result['checked']
        assert result['scan_results']['status'] == 'not_found'
