"""Tests for pdfanl.config module."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from pdfanl.config import (
    ANNOT_TYPE_NAMES,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    DEFAULT_MAX_FILE_SIZE_MB,
    HEADER_BUFFER_SIZE,
    JS_CODE_PREVIEW_LENGTH,
    RISK_LEVEL_HIGH_THRESHOLD,
    RISK_LEVEL_LOW_THRESHOLD,
    RISK_LEVEL_MEDIUM_THRESHOLD,
    RISK_MAX_SCORE,
    RISK_SCORE_JAVASCRIPT,
    SUSPICIOUS_KEYWORDS,
    AnalyzerConfig,
    get_default_config,
)


class TestConstants:
    """Tests for configuration constants."""

    def test_file_size_limits(self) -> None:
        """Test file size limit constants."""
        assert DEFAULT_MAX_FILE_SIZE_MB == 100
        assert DEFAULT_MAX_FILE_SIZE_BYTES == 100 * 1024 * 1024

    def test_header_buffer_size(self) -> None:
        """Test header buffer size is reasonable."""
        assert HEADER_BUFFER_SIZE == 1024
        assert HEADER_BUFFER_SIZE > 0

    def test_js_preview_length(self) -> None:
        """Test JavaScript preview length."""
        assert JS_CODE_PREVIEW_LENGTH == 500
        assert JS_CODE_PREVIEW_LENGTH > 0

    def test_risk_thresholds_ordered(self) -> None:
        """Test risk thresholds are in correct order."""
        assert RISK_LEVEL_HIGH_THRESHOLD > RISK_LEVEL_MEDIUM_THRESHOLD
        assert RISK_LEVEL_MEDIUM_THRESHOLD > RISK_LEVEL_LOW_THRESHOLD
        assert RISK_LEVEL_LOW_THRESHOLD >= 1
        assert RISK_MAX_SCORE == 100

    def test_risk_score_javascript_significant(self) -> None:
        """Test JavaScript risk score is significant."""
        assert RISK_SCORE_JAVASCRIPT >= 40
        assert RISK_SCORE_JAVASCRIPT <= RISK_MAX_SCORE

    def test_annot_type_names_complete(self) -> None:
        """Test annotation type mapping is complete."""
        assert len(ANNOT_TYPE_NAMES) > 20
        assert 0 in ANNOT_TYPE_NAMES  # Text
        assert 1 in ANNOT_TYPE_NAMES  # Link
        assert 19 in ANNOT_TYPE_NAMES  # Widget

    def test_suspicious_keywords_present(self) -> None:
        """Test suspicious keywords list has expected items."""
        assert '/JS' in SUSPICIOUS_KEYWORDS
        assert '/JavaScript' in SUSPICIOUS_KEYWORDS
        assert '/Launch' in SUSPICIOUS_KEYWORDS
        assert '/OpenAction' in SUSPICIOUS_KEYWORDS


class TestAnalyzerConfig:
    """Tests for AnalyzerConfig dataclass."""

    def test_default_config(self) -> None:
        """Test default configuration values."""
        config = AnalyzerConfig()
        assert config.max_file_size_bytes == DEFAULT_MAX_FILE_SIZE_BYTES
        assert config.js_preview_length == JS_CODE_PREVIEW_LENGTH
        assert config.vt_timeout > 0
        assert config.vt_max_retries >= 0

    def test_custom_config(self) -> None:
        """Test custom configuration values."""
        config = AnalyzerConfig(
            max_file_size_bytes=50 * 1024 * 1024,
            js_preview_length=1000,
            vt_timeout=60,
        )
        assert config.max_file_size_bytes == 50 * 1024 * 1024
        assert config.js_preview_length == 1000
        assert config.vt_timeout == 60

    def test_env_api_key_loaded(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test API key is loaded from environment."""
        monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'test_key_123')
        config = AnalyzerConfig()
        assert config.vt_api_key == 'test_key_123'

    def test_explicit_api_key_not_overwritten(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test explicit API key is not overwritten by env."""
        monkeypatch.setenv('VIRUSTOTAL_API_KEY', 'env_key')
        config = AnalyzerConfig(vt_api_key='explicit_key')
        assert config.vt_api_key == 'explicit_key'

    def test_risk_score_override(self) -> None:
        """Test risk score can be overridden."""
        config = AnalyzerConfig(
            risk_scores={'javascript': 30}
        )
        assert config.get_risk_score('javascript', 50) == 30
        assert config.get_risk_score('unknown', 50) == 50

    def test_to_dict(self) -> None:
        """Test config serialization."""
        config = AnalyzerConfig(max_file_size_bytes=1000)
        d = config.to_dict()
        assert isinstance(d, dict)
        assert d['max_file_size_bytes'] == 1000
        # API key should not be in dict (security)
        assert 'vt_api_key' not in d

    def test_save_and_load(self) -> None:
        """Test saving and loading config from file."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            config_path = Path(f.name)

        try:
            # Save config
            original = AnalyzerConfig(
                max_file_size_bytes=2000,
                js_preview_length=100,
            )
            original.save(config_path)

            # Load config
            loaded = AnalyzerConfig.from_file(config_path)
            assert loaded.max_file_size_bytes == 2000
            assert loaded.js_preview_length == 100

        finally:
            config_path.unlink(missing_ok=True)

    def test_load_nonexistent_file(self) -> None:
        """Test loading from nonexistent file returns defaults."""
        config = AnalyzerConfig.from_file(Path('/nonexistent/config.json'))
        assert config.max_file_size_bytes == DEFAULT_MAX_FILE_SIZE_BYTES

    def test_load_invalid_json(self) -> None:
        """Test loading invalid JSON returns defaults."""
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.json', delete=False
        ) as f:
            f.write('not valid json {{{')
            config_path = Path(f.name)

        try:
            config = AnalyzerConfig.from_file(config_path)
            assert config.max_file_size_bytes == DEFAULT_MAX_FILE_SIZE_BYTES
        finally:
            config_path.unlink(missing_ok=True)


class TestGetDefaultConfig:
    """Tests for get_default_config function."""

    def test_returns_config(self) -> None:
        """Test get_default_config returns AnalyzerConfig."""
        config = get_default_config()
        assert isinstance(config, AnalyzerConfig)

    def test_returns_defaults(self) -> None:
        """Test get_default_config returns default values."""
        config = get_default_config()
        assert config.max_file_size_bytes == DEFAULT_MAX_FILE_SIZE_BYTES
