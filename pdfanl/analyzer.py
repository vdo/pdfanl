"""
PDF Analyzer - Core analysis functionality.

Provides security-focused analysis of PDF files.
"""

import logging
import re
from pathlib import Path
from typing import Any, Optional

import fitz  # PyMuPDF

from .config import (
    ANNOT_TYPE_NAMES,
    DEFAULT_MAX_FILE_SIZE_BYTES,
    HEADER_BUFFER_SIZE,
    JS_CODE_PREVIEW_LENGTH,
    RISK_LEVEL_HIGH_THRESHOLD,
    RISK_LEVEL_LOW_THRESHOLD,
    RISK_LEVEL_MEDIUM_THRESHOLD,
    RISK_MAX_SCORE,
    RISK_SCORE_AUTO_ACTION_ONLY,
    RISK_SCORE_EMBEDDED,
    RISK_SCORE_HEADER_HIGH,
    RISK_SCORE_HEADER_MEDIUM,
    RISK_SCORE_JAVASCRIPT,
    RISK_SCORE_JBIG2,
    RISK_SCORE_JS_AUTO_ACTION,
    RISK_SCORE_LAUNCH,
    RISK_SCORE_OBJSTM,
    RISK_SCORE_REMOTE_ACTION,
    RISK_SCORE_RICHMEDIA,
    RISK_SCORE_SINGLE_PAGE_JS,
    RISK_SCORE_VT_MAX,
    RISK_SCORE_XFA,
    STRUCTURAL_KEYWORDS,
    SUSPICIOUS_KEYWORDS,
    AnalyzerConfig,
)
from .utils import calculate_file_hashes, decode_stream, get_annot_type_name
from .vt_client import check_virustotal

logger = logging.getLogger(__name__)


class FileTooLargeError(Exception):
    """Raised when file exceeds size limit."""

    def __init__(self, file_size: int, max_size: int):
        self.file_size = file_size
        self.max_size = max_size
        super().__init__(
            f"File size ({file_size:,} bytes) exceeds maximum "
            f"({max_size:,} bytes)"
        )


class PDFAnalysisError(Exception):
    """Raised when PDF analysis fails."""

    pass


class PDFAnalyzer:
    """
    PDF security analyzer.

    Extracts metadata, detects suspicious patterns, and calculates
    malware risk scores.
    """

    def __init__(
        self,
        pdf_path: str | Path,
        config: Optional[AnalyzerConfig] = None,
    ) -> None:
        """
        Initialize the PDF analyzer.

        Args:
            pdf_path: Path to the PDF file.
            config: Optional analyzer configuration.

        Raises:
            FileNotFoundError: If PDF file doesn't exist.
            FileTooLargeError: If file exceeds size limit.
        """
        self.pdf_path = Path(pdf_path)
        self.config = config or AnalyzerConfig()

        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")

        # Check file size
        file_size = self.pdf_path.stat().st_size
        if file_size > self.config.max_file_size_bytes:
            raise FileTooLargeError(file_size, self.config.max_file_size_bytes)

        self.doc: fitz.Document = fitz.open(str(self.pdf_path))
        self._init_results()

    def _init_results(self) -> None:
        """Initialize the results dictionary."""
        self.analysis_results: dict[str, Any] = {
            'file_info': {},
            'metadata': {},
            'version_info': {},
            'security': {},
            'pages': {},
            'links': [],
            'annotations': [],
            'javascript': [],
            'resources': {
                'images': [],
                'fonts': [],
                'other': []
            },
            'form_fields': [],
            'suspicious_keywords': {},
            'header_analysis': {},
            'virustotal': {},
            'malware_risk': {}
        }

    def analyze(self, check_vt: bool = False) -> dict[str, Any]:
        """
        Perform complete PDF analysis.

        Args:
            check_vt: Whether to check against VirusTotal.

        Returns:
            Dictionary containing all analysis results.
        """
        logger.info(f"Analyzing PDF: {self.pdf_path}")

        self._analyze_file_info()
        self._analyze_header()
        self._analyze_metadata()
        self._analyze_version_info()
        self._analyze_security()
        self._analyze_pages()
        self._analyze_links()
        self._analyze_annotations()
        self._analyze_suspicious_keywords()
        self._analyze_javascript()
        self._analyze_resources()
        self._analyze_form_fields()

        if check_vt:
            self._check_virustotal()

        self._calculate_malware_risk()

        return self.analysis_results

    def _analyze_file_info(self) -> None:
        """Extract basic file information."""
        self.analysis_results['file_info'] = {
            'filename': self.pdf_path.name,
            'file_size': self.pdf_path.stat().st_size,
            'page_count': self.doc.page_count,
            'is_pdf': self.doc.is_pdf,
            'is_encrypted': self.doc.is_encrypted
        }

    def _analyze_header(self) -> None:
        """Analyze PDF header for suspicious patterns."""
        with open(self.pdf_path, 'rb') as f:
            header_bytes = f.read(HEADER_BUFFER_SIZE)

        try:
            header_str = header_bytes.decode('latin-1')
        except UnicodeDecodeError:
            header_str = str(header_bytes)

        pdf_header_match = re.search(r'%PDF-(\d+\.\d+)', header_str)

        header_info: dict[str, Any] = {
            'has_valid_header': bool(pdf_header_match),
            'header_position': header_str.find('%PDF') if '%PDF' in header_str else -1,
            'is_header_at_start': header_str.startswith('%PDF'),
            'header_string': '',
            'suspicious_patterns': []
        }

        if pdf_header_match:
            header_info['header_string'] = pdf_header_match.group(0)
            header_info['pdf_version_header'] = pdf_header_match.group(1)

            if header_info['header_position'] > 0:
                header_info['suspicious_patterns'].append({
                    'type': 'header_not_at_start',
                    'description': 'PDF header not at file start (possible evasion)',
                    'severity': 'medium'
                })
        else:
            header_info['suspicious_patterns'].append({
                'type': 'invalid_header',
                'description': 'Invalid or missing PDF header',
                'severity': 'high'
            })

        if b'\x00' in header_bytes[:100]:
            header_info['suspicious_patterns'].append({
                'type': 'null_bytes_in_header',
                'description': 'Null bytes found in header region',
                'severity': 'medium'
            })

        self.analysis_results['header_analysis'] = header_info

    def _analyze_metadata(self) -> None:
        """Extract PDF metadata."""
        metadata = self.doc.metadata
        self.analysis_results['metadata'] = {
            'title': metadata.get('title', ''),
            'author': metadata.get('author', ''),
            'subject': metadata.get('subject', ''),
            'keywords': metadata.get('keywords', ''),
            'creator': metadata.get('creator', ''),
            'producer': metadata.get('producer', ''),
            'creation_date': metadata.get('creationDate', ''),
            'modification_date': metadata.get('modDate', ''),
            'encrypted': metadata.get('encrypted', '')
        }

    def _analyze_version_info(self) -> None:
        """Extract PDF version information."""
        pdf_version: Optional[str] = None

        if hasattr(self.doc, 'pdf_version'):
            try:
                pdf_version = self.doc.pdf_version()
            except (TypeError, AttributeError):
                logger.debug("pdf_version() method not callable")

        # Fallback to header analysis
        if not pdf_version and 'header_analysis' in self.analysis_results:
            pdf_version = self.analysis_results['header_analysis'].get(
                'pdf_version_header'
            )

        # Fallback to metadata format
        if not pdf_version:
            metadata = self.doc.metadata
            if metadata and 'format' in metadata:
                pdf_version = metadata['format'].replace('PDF ', '')

        self.analysis_results['version_info'] = {
            'pdf_version': pdf_version or 'Unknown',
            'pdf_catalog': (
                self.doc.pdf_catalog()
                if hasattr(self.doc, 'pdf_catalog')
                else None
            ),
            'has_outline': bool(self.doc.get_toc()),
            'outline_items': len(self.doc.get_toc()) if self.doc.get_toc() else 0
        }

    def _analyze_security(self) -> None:
        """Extract security information."""
        permissions_dict: dict[str, bool] = {}

        if hasattr(self.doc, 'permissions'):
            perms = self.doc.permissions
            if isinstance(perms, int):
                # New API: bit flags
                permissions_dict = {
                    'print': bool(perms & fitz.PDF_PERM_PRINT),
                    'copy': bool(perms & fitz.PDF_PERM_COPY),
                    'annotate': bool(perms & fitz.PDF_PERM_ANNOTATE),
                    'modify': bool(perms & fitz.PDF_PERM_MODIFY),
                    'fill_forms': bool(perms & fitz.PDF_PERM_FORM),
                    'accessibility': bool(perms & fitz.PDF_PERM_ACCESSIBILITY),
                    'assemble': bool(perms & fitz.PDF_PERM_ASSEMBLE),
                    'print_hq': bool(perms & fitz.PDF_PERM_PRINT_HQ)
                }
            elif isinstance(perms, dict):
                # Old API: dictionary
                permissions_dict = {
                    'print': perms.get('print', False),
                    'copy': perms.get('copy', False),
                    'annotate': perms.get('annotate', False),
                    'modify': perms.get('modify', False),
                    'fill_forms': perms.get('fill_forms', False)
                }

        self.analysis_results['security'] = {
            'is_encrypted': self.doc.is_encrypted,
            'permissions': permissions_dict
        }

    def _analyze_pages(self) -> None:
        """Analyze page information."""
        page_info: list[dict[str, Any]] = []

        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            page_info.append({
                'page_number': page_num + 1,
                'width': page.rect.width,
                'height': page.rect.height,
                'rotation': page.rotation,
                'text_length': len(page.get_text()),
                'image_count': len(list(page.get_images())),
                'link_count': len(list(page.get_links())),
                'annotation_count': len(list(page.annots()))
            })

        self.analysis_results['pages'] = {
            'total_pages': self.doc.page_count,
            'page_details': page_info
        }

    def _analyze_links(self) -> None:
        """Extract all links from the PDF."""
        all_links: list[dict[str, Any]] = []

        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            links = page.get_links()

            for link in links:
                link_info = {
                    'page': page_num + 1,
                    'type': link.get('type', link.get('kind', 0)),
                    'rect': link.get('rect', link.get('from', [])),
                    'uri': link.get('uri', ''),
                    'dest': link.get('dest', ''),
                    'file': link.get('file', ''),
                    'named': link.get('named', '')
                }
                all_links.append(link_info)

        self.analysis_results['links'] = all_links

    def _analyze_annotations(self) -> None:
        """Extract all annotations from the PDF."""
        all_annotations: list[dict[str, Any]] = []

        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            annots = page.annots()

            for annot in annots:
                annot_type = get_annot_type_name(annot.type, ANNOT_TYPE_NAMES)

                annot_info: dict[str, Any] = {
                    'page': page_num + 1,
                    'type': annot_type,
                    'rect': list(annot.rect),
                    'contents': annot.info.get('content', ''),
                    'author': annot.info.get('title', ''),
                    'creation_date': annot.info.get('creationDate', ''),
                    'modification_date': annot.info.get('modDate', '')
                }

                if annot_type == 'Text':
                    annot_info['text'] = annot.info.get('text', '')
                elif annot_type == 'Link':
                    annot_info['uri'] = annot.info.get('uri', '')

                all_annotations.append(annot_info)

        self.analysis_results['annotations'] = all_annotations

    def _analyze_suspicious_keywords(self) -> None:
        """Scan PDF content for suspicious keywords."""
        keywords: dict[str, int] = {}

        # Initialize all keywords
        for kw in SUSPICIOUS_KEYWORDS + STRUCTURAL_KEYWORDS:
            keywords[kw] = 0

        try:
            with open(self.pdf_path, 'rb') as f:
                content = f.read()

            content_str = content.decode('latin-1', errors='ignore')

            for keyword in keywords:
                keywords[keyword] = content_str.count(keyword)

        except IOError as e:
            logger.error(f"Error scanning for suspicious keywords: {e}")

        self.analysis_results['suspicious_keywords'] = keywords

    def _analyze_javascript(self) -> None:
        """Extract JavaScript code from the PDF."""
        javascript_code: list[dict[str, Any]] = []
        preview_len = self.config.js_preview_length

        # Document-level scripts
        self._extract_document_scripts(javascript_code, preview_len)

        # Page-level scripts
        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            self._extract_page_scripts(page, page_num, javascript_code, preview_len)
            self._extract_annotation_scripts(page, page_num, javascript_code, preview_len)
            self._extract_widget_scripts(page, page_num, javascript_code, preview_len)

        self.analysis_results['javascript'] = javascript_code

    def _extract_document_scripts(
        self,
        javascript_code: list[dict[str, Any]],
        preview_len: int
    ) -> None:
        """Extract document-level JavaScript."""
        try:
            if hasattr(self.doc, 'get_js_scripts'):
                doc_scripts = self.doc.get_js_scripts()
                if doc_scripts:
                    for script in doc_scripts:
                        code = decode_stream(
                            script.encode() if isinstance(script, str) else script
                        )
                        javascript_code.append({
                            'page': 0,
                            'type': 'document_script',
                            'code': code[:preview_len]
                        })
        except (AttributeError, RuntimeError) as e:
            logger.debug(f"Error extracting document-level JavaScript: {e}")

    def _extract_page_scripts(
        self,
        page: fitz.Page,
        page_num: int,
        javascript_code: list[dict[str, Any]],
        preview_len: int
    ) -> None:
        """Extract page-level JavaScript."""
        if hasattr(page, 'get_js_scripts'):
            try:
                page_scripts = page.get_js_scripts()
                if page_scripts:
                    for script in page_scripts:
                        code = decode_stream(
                            script.encode() if isinstance(script, str) else script
                        )
                        javascript_code.append({
                            'page': page_num + 1,
                            'type': 'page_script',
                            'code': code[:preview_len]
                        })
            except (AttributeError, RuntimeError) as e:
                logger.debug(f"Error extracting page {page_num + 1} JavaScript: {e}")

    def _extract_annotation_scripts(
        self,
        page: fitz.Page,
        page_num: int,
        javascript_code: list[dict[str, Any]],
        preview_len: int
    ) -> None:
        """Extract annotation JavaScript."""
        for annot in page.annots():
            if hasattr(annot, 'get_js_scripts'):
                try:
                    annot_scripts = annot.get_js_scripts()
                    if annot_scripts:
                        annot_type = get_annot_type_name(annot.type, ANNOT_TYPE_NAMES)
                        for script in annot_scripts:
                            code = decode_stream(
                                script.encode() if isinstance(script, str) else script
                            )
                            javascript_code.append({
                                'page': page_num + 1,
                                'type': 'annotation_script',
                                'annotation_type': annot_type,
                                'code': code[:preview_len]
                            })
                except (AttributeError, RuntimeError) as e:
                    logger.debug(f"Error extracting annotation JavaScript: {e}")

    def _extract_widget_scripts(
        self,
        page: fitz.Page,
        page_num: int,
        javascript_code: list[dict[str, Any]],
        preview_len: int
    ) -> None:
        """Extract form widget JavaScript."""
        widgets = page.widgets()
        script_attrs = [
            'script', 'script_format', 'script_calculate',
            'script_change', 'script_stroke'
        ]

        for widget in widgets:
            for script_attr in script_attrs:
                try:
                    script = getattr(widget, script_attr, None)
                    if script:
                        code = decode_stream(
                            script.encode() if isinstance(script, str) else script
                        )
                        script_type = (
                            'widget_script' if script_attr == 'script'
                            else f'widget_{script_attr}'
                        )
                        javascript_code.append({
                            'page': page_num + 1,
                            'type': script_type,
                            'field_name': widget.field_name or 'unnamed',
                            'code': code[:preview_len]
                        })
                except (AttributeError, RuntimeError):
                    # Widget doesn't have this script attribute
                    pass

    def _analyze_resources(self) -> None:
        """Analyze resources like images and fonts."""
        images: list[dict[str, Any]] = []
        fonts: set[str] = set()

        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]

            # Extract images
            page_images = page.get_images()
            for img_index, img in enumerate(page_images):
                try:
                    xref = img[0]
                    pix = fitz.Pixmap(self.doc, xref)

                    image_info: dict[str, Any] = {
                        'page': page_num + 1,
                        'xref': xref,
                        'width': pix.width,
                        'height': pix.height,
                        'colorspace': pix.colorspace.name if pix.colorspace else None,
                        'n_channels': pix.n,
                        'alpha': pix.alpha,
                        'size': len(pix.samples) if pix.samples else 0
                    }

                    if pix.n == 1:
                        image_info['format'] = 'grayscale'
                    elif pix.n == 3:
                        image_info['format'] = 'RGB'
                    elif pix.n == 4:
                        image_info['format'] = 'RGBA'

                    images.append(image_info)

                    # Free memory
                    del pix

                except (ValueError, RuntimeError) as e:
                    logger.debug(
                        f"Error extracting image {img_index} from page {page_num + 1}: {e}"
                    )

            # Extract fonts
            try:
                page_fonts = page.get_fonts()
                for font in page_fonts:
                    fonts.add(font[0])
            except (ValueError, RuntimeError) as e:
                logger.debug(f"Error extracting fonts from page {page_num + 1}: {e}")

        self.analysis_results['resources']['images'] = images
        self.analysis_results['resources']['fonts'] = list(fonts)

    def _analyze_form_fields(self) -> None:
        """Extract form field information."""
        form_fields: list[dict[str, Any]] = []

        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            widgets = page.widgets()

            for widget in widgets:
                field_info: dict[str, Any] = {
                    'page': page_num + 1,
                    'type': widget.field_type,
                    'name': widget.field_name,
                    'value': widget.field_value,
                    'rect': list(widget.rect),
                    'flags': widget.field_flags,
                    'readonly': getattr(widget, 'readonly', None),
                    'required': getattr(widget, 'required', None)
                }
                form_fields.append(field_info)

        self.analysis_results['form_fields'] = form_fields

    def _check_virustotal(self) -> None:
        """Check file hash against VirusTotal API."""
        logger.info("Calculating file hashes for VirusTotal check...")

        try:
            hashes = calculate_file_hashes(self.pdf_path)
        except (FileNotFoundError, IOError) as e:
            self.analysis_results['virustotal'] = {
                'checked': False,
                'error': f'Failed to calculate hash: {e}'
            }
            return

        vt_results = check_virustotal(
            sha256=hashes['sha256'],
            api_key=self.config.vt_api_key,
            timeout=self.config.vt_timeout,
            max_retries=self.config.vt_max_retries,
        )

        # Add all hashes to results
        vt_results['hashes'] = hashes
        self.analysis_results['virustotal'] = vt_results

        # Log result
        if vt_results.get('checked'):
            scan = vt_results.get('scan_results', {})
            if scan.get('status') == 'not_found':
                logger.info("File not found in VirusTotal database")
            elif 'malicious' in scan:
                logger.info(
                    f"VirusTotal: {scan['malicious']}/{scan['total_engines']} "
                    "engines detected as malicious"
                )
        elif vt_results.get('error'):
            logger.warning(f"VirusTotal check failed: {vt_results['error']}")

    def _calculate_malware_risk(self) -> None:
        """Calculate malware risk based on suspicious indicators."""
        risk_score = 0
        risk_factors: list[dict[str, Any]] = []
        keywords = self.analysis_results['suspicious_keywords']

        # Check indicators
        has_js = keywords.get('/JS', 0) > 0 or keywords.get('/JavaScript', 0) > 0
        has_auto_action = keywords.get('/AA', 0) > 0 or keywords.get('/OpenAction', 0) > 0
        has_jbig2 = keywords.get('/JBIG2Decode', 0) > 0
        has_richmedia = keywords.get('/RichMedia', 0) > 0
        has_launch = keywords.get('/Launch', 0) > 0
        has_embedded = keywords.get('/EmbeddedFile', 0) > 0
        has_xfa = keywords.get('/XFA', 0) > 0
        has_objstm = keywords.get('/ObjStm', 0) > 0
        has_goto = keywords.get('/GoToE', 0) > 0 or keywords.get('/GoToR', 0) > 0
        has_submitform = keywords.get('/SubmitForm', 0) > 0

        # JavaScript
        if has_js:
            score = RISK_SCORE_JAVASCRIPT
            risk_score += score
            risk_factors.append({
                'factor': 'JavaScript present',
                'severity': 'high',
                'description': (
                    f"PDF contains JavaScript "
                    f"({keywords['/JS']} /JS, {keywords['/JavaScript']} /JavaScript)"
                ),
                'score': score
            })

        # Auto-action
        if has_auto_action:
            if has_js:
                score = RISK_SCORE_JS_AUTO_ACTION
                risk_score += score
                risk_factors.append({
                    'factor': 'JavaScript + Auto-action combination',
                    'severity': 'high',
                    'description': (
                        f"Dangerous combination: JavaScript with automatic execution "
                        f"(/AA: {keywords['/AA']}, /OpenAction: {keywords['/OpenAction']})"
                    ),
                    'score': score
                })
            else:
                score = RISK_SCORE_AUTO_ACTION_ONLY
                risk_score += score
                risk_factors.append({
                    'factor': 'Automatic action (no JavaScript)',
                    'severity': 'low',
                    'description': (
                        f"PDF has automatic actions without JavaScript "
                        f"(/AA: {keywords['/AA']}, /OpenAction: {keywords['/OpenAction']})"
                    ),
                    'score': score
                })

        # Launch action
        if has_launch:
            score = RISK_SCORE_LAUNCH
            risk_score += score
            risk_factors.append({
                'factor': 'Launch action',
                'severity': 'high',
                'description': (
                    f"PDF can launch external programs "
                    f"({keywords['/Launch']} occurrences)"
                ),
                'score': score
            })

        # Embedded files
        if has_embedded:
            score = RISK_SCORE_EMBEDDED
            risk_score += score
            risk_factors.append({
                'factor': 'Embedded files',
                'severity': 'medium',
                'description': (
                    f"PDF contains embedded files "
                    f"({keywords['/EmbeddedFile']} occurrences)"
                ),
                'score': score
            })

        # JBIG2 (CVE-2009-0658)
        if has_jbig2:
            score = RISK_SCORE_JBIG2
            risk_score += score
            risk_factors.append({
                'factor': 'JBIG2 compression',
                'severity': 'medium',
                'description': 'Uses JBIG2Decode (potential CVE-2009-0658 vulnerability)',
                'score': score
            })

        # Remote actions (CVE-2023-26369)
        if has_goto or has_submitform:
            score = RISK_SCORE_REMOTE_ACTION
            risk_score += score
            risk_factors.append({
                'factor': 'Remote action (CVE-2023-26369)',
                'severity': 'high',
                'description': (
                    "Contains remote actions (GoToE/GoToR/SubmitForm) - "
                    "potential one-click exploit vulnerability"
                ),
                'score': score
            })

        # RichMedia/Flash
        if has_richmedia:
            score = RISK_SCORE_RICHMEDIA
            risk_score += score
            risk_factors.append({
                'factor': 'RichMedia/Flash',
                'severity': 'medium',
                'description': 'Contains embedded Flash/RichMedia content',
                'score': score
            })

        # XFA forms
        if has_xfa:
            score = RISK_SCORE_XFA
            risk_score += score
            risk_factors.append({
                'factor': 'XFA forms',
                'severity': 'low',
                'description': 'Uses XML Forms Architecture',
                'score': score
            })

        # Object streams
        if has_objstm:
            score = RISK_SCORE_OBJSTM
            risk_score += score
            risk_factors.append({
                'factor': 'Object streams',
                'severity': 'low',
                'description': 'Contains object streams (can be used for obfuscation)',
                'score': score
            })

        # Single page with JS
        if self.analysis_results['file_info']['page_count'] == 1 and has_js:
            score = RISK_SCORE_SINGLE_PAGE_JS
            risk_score += score
            risk_factors.append({
                'factor': 'Single page with scripts',
                'severity': 'medium',
                'description': 'Single-page PDF with JavaScript (common in malware)',
                'score': score
            })

        # Header anomalies
        header_issues = self.analysis_results['header_analysis'].get(
            'suspicious_patterns', []
        )
        if header_issues:
            header_score = 0
            for issue in header_issues:
                if issue['severity'] == 'high':
                    header_score += RISK_SCORE_HEADER_HIGH
                elif issue['severity'] == 'medium':
                    header_score += RISK_SCORE_HEADER_MEDIUM

            risk_score += header_score
            risk_factors.append({
                'factor': 'Header anomalies',
                'severity': 'medium',
                'description': f"Found {len(header_issues)} suspicious header pattern(s)",
                'score': header_score
            })

        # VirusTotal integration
        risk_score = self._add_virustotal_risk(risk_score, risk_factors)

        # Determine risk level
        if risk_score >= RISK_LEVEL_HIGH_THRESHOLD:
            risk_level = 'HIGH'
        elif risk_score >= RISK_LEVEL_MEDIUM_THRESHOLD:
            risk_level = 'MEDIUM'
        elif risk_score >= RISK_LEVEL_LOW_THRESHOLD:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'

        self.analysis_results['malware_risk'] = {
            'risk_score': min(risk_score, RISK_MAX_SCORE),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'is_suspicious': risk_score >= 50,
            'recommendations': self._get_risk_recommendations(risk_level, risk_factors)
        }

    def _add_virustotal_risk(
        self,
        risk_score: int,
        risk_factors: list[dict[str, Any]]
    ) -> int:
        """Add VirusTotal detection to risk score."""
        vt_data = self.analysis_results.get('virustotal', {})

        if not vt_data.get('checked'):
            return risk_score

        scan = vt_data.get('scan_results', {})
        if 'malicious' not in scan:
            return risk_score

        malicious_count = scan['malicious']
        total_engines = scan.get('total_engines', 0)

        if malicious_count > 0 and total_engines > 0:
            detection_ratio = malicious_count / total_engines
            vt_risk_score = min(int(detection_ratio * 100), RISK_SCORE_VT_MAX)
            risk_score += vt_risk_score

            severity = 'high' if detection_ratio > 0.1 else 'medium'

            factor: dict[str, Any] = {
                'factor': 'VirusTotal detection',
                'severity': severity,
                'description': (
                    f"{malicious_count}/{total_engines} antivirus engines "
                    "flagged as malicious"
                ),
                'score': vt_risk_score
            }

            if scan.get('popular_threat_name') and scan['popular_threat_name'] != 'N/A':
                factor['threat_name'] = scan['popular_threat_name']

            risk_factors.append(factor)

        return risk_score

    def _get_risk_recommendations(
        self,
        risk_level: str,
        risk_factors: list[dict[str, Any]]
    ) -> list[str]:
        """Get security recommendations based on risk assessment."""
        recommendations: list[str] = []

        if risk_level == 'HIGH':
            recommendations.extend([
                'DO NOT OPEN this PDF in a standard viewer',
                'Use a sandboxed environment for analysis',
                'Scan with antivirus/malware detection tools'
            ])

        if risk_level == 'MEDIUM':
            recommendations.extend([
                'Exercise caution when opening this PDF',
                'Disable JavaScript in your PDF reader'
            ])

        factor_names = {f['factor'] for f in risk_factors}

        if 'JavaScript + Auto-action combination' in factor_names:
            recommendations.append('High likelihood of automated malware execution')

        if 'Launch action' in factor_names:
            recommendations.append('PDF may attempt to launch external programs')

        if 'Embedded files' in factor_names:
            recommendations.append('Examine embedded files separately')

        # External links warning
        external_links = [
            link for link in self.analysis_results['links']
            if link.get('uri')
        ]
        if external_links:
            recommendations.append('Verify all external links before clicking')

        if risk_level == 'SAFE':
            recommendations.append('No obvious malicious indicators detected')

        return recommendations

    def close(self) -> None:
        """Close the PDF document and release resources."""
        if self.doc:
            self.doc.close()

    def __enter__(self) -> 'PDFAnalyzer':
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
