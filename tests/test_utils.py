"""Tests for pdfanl.utils module."""

import tempfile
import zlib
from pathlib import Path

import pytest

from pdfanl.utils import (
    calculate_file_hashes,
    decode_stream,
    format_file_size,
    get_annot_type_name,
)


class TestDecodeStream:
    """Tests for decode_stream function."""

    def test_empty_data(self) -> None:
        """Test decoding empty data."""
        assert decode_stream(b'') == ''

    def test_plain_text(self) -> None:
        """Test decoding plain UTF-8 text."""
        data = b'Hello, World!'
        assert decode_stream(data) == 'Hello, World!'

    def test_flate_decode(self) -> None:
        """Test FlateDecode (zlib) decompression."""
        original = 'This is compressed text'
        compressed = zlib.compress(original.encode('utf-8'))
        assert decode_stream(compressed) == original

    def test_hex_decode(self) -> None:
        """Test hex string decoding."""
        # "Hello" in hex
        hex_data = b'48656c6c6f'
        result = decode_stream(hex_data)
        assert 'Hello' in result

    def test_hex_with_whitespace(self) -> None:
        """Test hex decoding handles whitespace."""
        # "Hi" in hex with whitespace
        hex_data = b'48 69'
        result = decode_stream(hex_data)
        assert 'Hi' in result

    def test_invalid_data_returns_string(self) -> None:
        """Test invalid data returns string representation."""
        # Random bytes that aren't valid text
        data = bytes([0x80, 0x81, 0x82])
        result = decode_stream(data)
        assert isinstance(result, str)

    def test_unicode_text(self) -> None:
        """Test Unicode text decoding."""
        data = 'Hello 世界'.encode('utf-8')
        result = decode_stream(data)
        assert '世界' in result


class TestCalculateFileHashes:
    """Tests for calculate_file_hashes function."""

    def test_hash_calculation(self) -> None:
        """Test hash calculation on known content."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'test content')
            temp_path = Path(f.name)

        try:
            hashes = calculate_file_hashes(temp_path)
            assert 'md5' in hashes
            assert 'sha1' in hashes
            assert 'sha256' in hashes
            # MD5 of 'test content'
            assert hashes['md5'] == '9a0364b9e99bb480dd25e1f0284c8555'
        finally:
            temp_path.unlink()

    def test_hash_length(self) -> None:
        """Test hash lengths are correct."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b'data')
            temp_path = Path(f.name)

        try:
            hashes = calculate_file_hashes(temp_path)
            assert len(hashes['md5']) == 32
            assert len(hashes['sha1']) == 40
            assert len(hashes['sha256']) == 64
        finally:
            temp_path.unlink()

    def test_file_not_found(self) -> None:
        """Test FileNotFoundError for missing file."""
        with pytest.raises(FileNotFoundError):
            calculate_file_hashes(Path('/nonexistent/file.txt'))

    def test_empty_file(self) -> None:
        """Test hashing empty file."""
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)

        try:
            hashes = calculate_file_hashes(temp_path)
            # Known hash of empty file
            assert hashes['md5'] == 'd41d8cd98f00b204e9800998ecf8427e'
        finally:
            temp_path.unlink()


class TestFormatFileSize:
    """Tests for format_file_size function."""

    def test_bytes(self) -> None:
        """Test formatting bytes."""
        assert format_file_size(500) == '500.0 B'

    def test_kilobytes(self) -> None:
        """Test formatting kilobytes."""
        result = format_file_size(2048)
        assert 'KB' in result
        assert '2.0' in result

    def test_megabytes(self) -> None:
        """Test formatting megabytes."""
        result = format_file_size(5 * 1024 * 1024)
        assert 'MB' in result
        assert '5.0' in result

    def test_gigabytes(self) -> None:
        """Test formatting gigabytes."""
        result = format_file_size(2 * 1024 * 1024 * 1024)
        assert 'GB' in result
        assert '2.0' in result

    def test_zero(self) -> None:
        """Test formatting zero bytes."""
        assert format_file_size(0) == '0.0 B'


class TestGetAnnotTypeName:
    """Tests for get_annot_type_name function."""

    def test_integer_type(self) -> None:
        """Test with integer annotation type (new API)."""
        type_names = {0: 'Text', 1: 'Link'}
        assert get_annot_type_name(0, type_names) == 'Text'
        assert get_annot_type_name(1, type_names) == 'Link'

    def test_tuple_type(self) -> None:
        """Test with tuple annotation type (old API)."""
        type_names = {0: 'Text'}
        result = get_annot_type_name((0, 'OldText'), type_names)
        assert result == 'OldText'

    def test_unknown_type(self) -> None:
        """Test with unknown type ID."""
        type_names = {0: 'Text'}
        result = get_annot_type_name(99, type_names)
        assert 'Unknown' in result
        assert '99' in result
