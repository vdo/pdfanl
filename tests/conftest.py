"""Pytest configuration and shared fixtures."""

import tempfile
from pathlib import Path
from typing import Generator

import pytest


@pytest.fixture
def minimal_pdf() -> Generator[Path, None, None]:
    """Create a minimal valid PDF file for testing."""
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
        # Minimal PDF 1.4 structure
        content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
0000000115 00000 n
trailer
<< /Size 4 /Root 1 0 R >>
startxref
196
%%EOF"""
        f.write(content)
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def pdf_with_javascript() -> Generator[Path, None, None]:
    """Create a PDF file with JavaScript markers for testing."""
    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as f:
        # PDF with /JS and /JavaScript markers
        content = b"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R /Names << /JavaScript 4 0 R >> >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
4 0 obj
<< /JS (app.alert\\('test'\\);) >>
endobj
xref
0 5
0000000000 65535 f
0000000009 00000 n
0000000080 00000 n
0000000137 00000 n
0000000206 00000 n
trailer
<< /Size 5 /Root 1 0 R >>
startxref
260
%%EOF"""
        f.write(content)
        temp_path = Path(f.name)

    yield temp_path

    # Cleanup
    temp_path.unlink(missing_ok=True)


@pytest.fixture
def empty_temp_file() -> Generator[Path, None, None]:
    """Create an empty temporary file."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        temp_path = Path(f.name)

    yield temp_path

    temp_path.unlink(missing_ok=True)


@pytest.fixture
def temp_json_file() -> Generator[Path, None, None]:
    """Create a temporary JSON file path."""
    with tempfile.NamedTemporaryFile(suffix='.json', delete=False) as f:
        temp_path = Path(f.name)

    yield temp_path

    temp_path.unlink(missing_ok=True)
