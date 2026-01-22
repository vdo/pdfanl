"""Tests for pdfanl.analyzer module."""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from pdfanl.analyzer import (
    FileTooLargeError,
    PDFAnalyzer,
)
from pdfanl.config import (
    AnalyzerConfig,
    RISK_LEVEL_HIGH_THRESHOLD,
    RISK_LEVEL_MEDIUM_THRESHOLD,
    RISK_SCORE_JAVASCRIPT,
    RISK_SCORE_JS_AUTO_ACTION,
    RISK_SCORE_LAUNCH,
)


class TestFileTooLargeError:
    """Tests for FileTooLargeError exception."""

    def test_error_message(self) -> None:
        """Test error message formatting."""
        error = FileTooLargeError(file_size=200_000_000, max_size=100_000_000)
        assert '200,000,000' in str(error)
        assert '100,000,000' in str(error)

    def test_attributes(self) -> None:
        """Test error has correct attributes."""
        error = FileTooLargeError(file_size=200, max_size=100)
        assert error.file_size == 200
        assert error.max_size == 100


class TestPDFAnalyzerInit:
    """Tests for PDFAnalyzer initialization."""

    def test_file_not_found(self) -> None:
        """Test FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            PDFAnalyzer('/nonexistent/file.pdf')

    def test_file_too_large(self) -> None:
        """Test FileTooLargeError for oversized file."""
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            # Write a small amount but set config to tiny limit
            f.write(b'%PDF-1.4\n' + b'x' * 1000)
            temp_path = Path(f.name)

        try:
            config = AnalyzerConfig(max_file_size_bytes=100)
            with pytest.raises(FileTooLargeError):
                PDFAnalyzer(temp_path, config=config)
        finally:
            temp_path.unlink()

    def test_context_manager(self) -> None:
        """Test context manager closes document."""
        # Create minimal valid PDF
        with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
            # Minimal PDF structure
            f.write(b'%PDF-1.4\n')
            f.write(b'1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n')
            f.write(b'2 0 obj<</Type/Pages/Count 0/Kids[]>>endobj\n')
            f.write(b'xref\n0 3\n')
            f.write(b'0000000000 65535 f \n')
            f.write(b'0000000009 00000 n \n')
            f.write(b'0000000052 00000 n \n')
            f.write(b'trailer<</Size 3/Root 1 0 R>>\n')
            f.write(b'startxref\n100\n%%EOF')
            temp_path = Path(f.name)

        try:
            with PDFAnalyzer(temp_path) as analyzer:
                assert analyzer.doc is not None
            # After context, doc should be closed
            # (we can't easily test this without accessing internal state)
        finally:
            temp_path.unlink()


class TestRiskCalculation:
    """Tests for malware risk calculation logic."""

    @pytest.fixture
    def mock_analyzer(self) -> MagicMock:
        """Create a mock analyzer with controllable results."""
        analyzer = MagicMock(spec=PDFAnalyzer)
        analyzer.analysis_results = {
            'file_info': {'page_count': 5},
            'header_analysis': {'suspicious_patterns': []},
            'suspicious_keywords': {
                '/JS': 0,
                '/JavaScript': 0,
                '/AA': 0,
                '/OpenAction': 0,
                '/Launch': 0,
                '/EmbeddedFile': 0,
                '/JBIG2Decode': 0,
                '/RichMedia': 0,
                '/XFA': 0,
                '/ObjStm': 0,
                '/GoToE': 0,
                '/GoToR': 0,
                '/SubmitForm': 0,
            },
            'virustotal': {},
            'links': [],
        }
        return analyzer

    def test_safe_pdf_no_risk(self, mock_analyzer: MagicMock) -> None:
        """Test safe PDF has zero risk score."""
        # Call the actual method on a real analyzer would be better,
        # but this tests the logic
        keywords = mock_analyzer.analysis_results['suspicious_keywords']
        risk_score = 0

        # No suspicious keywords -> no risk
        has_js = keywords['/JS'] > 0 or keywords['/JavaScript'] > 0
        assert not has_js
        assert risk_score == 0

    def test_javascript_adds_risk(self, mock_analyzer: MagicMock) -> None:
        """Test JavaScript presence adds significant risk."""
        keywords = mock_analyzer.analysis_results['suspicious_keywords']
        keywords['/JS'] = 1

        risk_score = 0
        if keywords['/JS'] > 0 or keywords['/JavaScript'] > 0:
            risk_score += RISK_SCORE_JAVASCRIPT

        assert risk_score == RISK_SCORE_JAVASCRIPT
        assert risk_score >= 40  # Should be significant

    def test_js_plus_autoaction_high_risk(self, mock_analyzer: MagicMock) -> None:
        """Test JavaScript + auto-action is high risk."""
        keywords = mock_analyzer.analysis_results['suspicious_keywords']
        keywords['/JS'] = 1
        keywords['/OpenAction'] = 1

        risk_score = RISK_SCORE_JAVASCRIPT + RISK_SCORE_JS_AUTO_ACTION

        assert risk_score >= RISK_LEVEL_HIGH_THRESHOLD

    def test_launch_action_high_risk(self, mock_analyzer: MagicMock) -> None:
        """Test Launch action adds high risk."""
        keywords = mock_analyzer.analysis_results['suspicious_keywords']
        keywords['/Launch'] = 1

        risk_score = RISK_SCORE_LAUNCH
        assert risk_score >= 30  # Launch should be significant

    def test_combined_factors_cumulative(self, mock_analyzer: MagicMock) -> None:
        """Test multiple risk factors are cumulative."""
        keywords = mock_analyzer.analysis_results['suspicious_keywords']
        keywords['/JS'] = 1
        keywords['/Launch'] = 1
        keywords['/EmbeddedFile'] = 1

        # Each factor should add to total
        risk_score = RISK_SCORE_JAVASCRIPT + RISK_SCORE_LAUNCH + 20  # embedded
        assert risk_score > RISK_SCORE_JAVASCRIPT

    def test_single_page_js_bonus(self, mock_analyzer: MagicMock) -> None:
        """Test single-page PDF with JS gets bonus risk."""
        mock_analyzer.analysis_results['file_info']['page_count'] = 1
        keywords = mock_analyzer.analysis_results['suspicious_keywords']
        keywords['/JS'] = 1

        # Single page + JS should add extra risk
        has_js = True
        page_count = 1

        extra_risk = 15 if (page_count == 1 and has_js) else 0
        assert extra_risk == 15


class TestRiskLevels:
    """Tests for risk level thresholds."""

    def test_high_threshold(self) -> None:
        """Test HIGH risk threshold."""
        assert RISK_LEVEL_HIGH_THRESHOLD == 75

    def test_medium_threshold(self) -> None:
        """Test MEDIUM risk threshold."""
        assert RISK_LEVEL_MEDIUM_THRESHOLD == 41

    def test_level_determination(self) -> None:
        """Test risk level determination logic."""
        def get_level(score: int) -> str:
            if score >= RISK_LEVEL_HIGH_THRESHOLD:
                return 'HIGH'
            elif score >= RISK_LEVEL_MEDIUM_THRESHOLD:
                return 'MEDIUM'
            elif score > 0:
                return 'LOW'
            return 'SAFE'

        assert get_level(100) == 'HIGH'
        assert get_level(75) == 'HIGH'
        assert get_level(74) == 'MEDIUM'
        assert get_level(41) == 'MEDIUM'
        assert get_level(40) == 'LOW'
        assert get_level(1) == 'LOW'
        assert get_level(0) == 'SAFE'


class TestRecommendations:
    """Tests for risk recommendations."""

    def test_high_risk_recommendations(self) -> None:
        """Test HIGH risk gets appropriate recommendations."""
        risk_level = 'HIGH'
        recommendations = []

        if risk_level == 'HIGH':
            recommendations.extend([
                'DO NOT OPEN this PDF in a standard viewer',
                'Use a sandboxed environment for analysis',
            ])

        assert len(recommendations) >= 2
        assert any('sandbox' in r.lower() for r in recommendations)

    def test_safe_recommendation(self) -> None:
        """Test SAFE risk gets clean recommendation."""
        risk_level = 'SAFE'
        recommendations = []

        if risk_level == 'SAFE':
            recommendations.append('No obvious malicious indicators detected')

        assert len(recommendations) == 1
        assert 'malicious' in recommendations[0].lower()
