"""
Utility functions for pdfanl.

Provides stream decoding, hash calculation, and other helpers.
"""

import hashlib
import logging
import zlib
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


class StreamDecodeError(Exception):
    """Raised when stream decoding fails."""

    pass


def decode_stream(data: bytes) -> str:
    """
    Decode stream data with common PDF filters.

    Attempts multiple decoding strategies:
    1. FlateDecode (zlib compression)
    2. Hex string decoding
    3. Direct UTF-8 decoding

    Args:
        data: Raw stream bytes to decode.

    Returns:
        Decoded string content.
    """
    if not data:
        return ""

    # Try FlateDecode (zlib compression)
    decoded = _try_flate_decode(data)
    if decoded is not None:
        return decoded

    # Try hex string decoding
    decoded = _try_hex_decode(data)
    if decoded is not None:
        return decoded

    # Try direct UTF-8 decoding
    decoded = _try_utf8_decode(data)
    if decoded is not None:
        return decoded

    # Last resort: string representation
    logger.debug("All decoding strategies failed, returning string representation")
    return str(data)


def _try_flate_decode(data: bytes) -> Optional[str]:
    """Try to decode using FlateDecode (zlib)."""
    try:
        decoded = zlib.decompress(data)
        return decoded.decode('utf-8', errors='ignore')
    except zlib.error:
        logger.debug("FlateDecode failed: not zlib compressed")
        return None
    except ValueError as e:
        logger.debug(f"FlateDecode failed: {e}")
        return None


def _try_hex_decode(data: bytes) -> Optional[str]:
    """Try to decode as hex string."""
    try:
        # Check if it looks like hex
        sample = data[:100]
        hex_chars = b'0123456789abcdefABCDEF \t\n\r'
        if not all(c in hex_chars for c in sample):
            return None

        # Remove whitespace and decode
        hex_str = data.decode('ascii')
        hex_clean = hex_str.replace(' ', '').replace('\n', '').replace('\r', '').replace('\t', '')
        decoded = bytes.fromhex(hex_clean)
        return decoded.decode('utf-8', errors='ignore')
    except (ValueError, UnicodeDecodeError) as e:
        logger.debug(f"Hex decode failed: {e}")
        return None


def _try_utf8_decode(data: bytes) -> Optional[str]:
    """Try direct UTF-8 decoding."""
    try:
        return data.decode('utf-8', errors='ignore')
    except (ValueError, UnicodeDecodeError) as e:
        logger.debug(f"UTF-8 decode failed: {e}")
        return None


def calculate_file_hashes(file_path: Path) -> dict[str, str]:
    """
    Calculate MD5, SHA1, and SHA256 hashes of a file.

    Args:
        file_path: Path to the file.

    Returns:
        Dictionary with 'md5', 'sha1', 'sha256' keys.

    Raises:
        FileNotFoundError: If file doesn't exist.
        IOError: If file can't be read.
    """
    hashes = {'md5': '', 'sha1': '', 'sha256': ''}

    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
            hashes['md5'] = hashlib.md5(file_data).hexdigest()
            hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
            hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        raise
    except IOError as e:
        logger.error(f"Error reading file for hashing: {e}")
        raise

    return hashes


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes.

    Returns:
        Human-readable size string (e.g., "1.5 MB").
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if abs(size_bytes) < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def get_annot_type_name(annot_type: int | tuple, type_names: dict[int, str]) -> str:
    """
    Get annotation type name, handling both old and new PyMuPDF APIs.

    Args:
        annot_type: Annotation type (int for new API, tuple for old).
        type_names: Mapping of type IDs to names.

    Returns:
        Human-readable annotation type name.
    """
    if isinstance(annot_type, tuple):
        return annot_type[1]
    return type_names.get(annot_type, f'Unknown({annot_type})')
