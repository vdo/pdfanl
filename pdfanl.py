#!/usr/bin/env python3
"""
PDF Analysis Tool using PyMuPDF (fitz)

This tool analyzes PDF files and extracts:
- PDF version and basic metadata
- Links and annotations
- JavaScript code
- Resources (images, fonts, etc.)
- Security information
- Page statistics
"""

import fitz  # PyMuPDF
import json
import argparse
import sys
import re
import os
import hashlib
import time
from pathlib import Path
from typing import Dict, List, Any, Optional
import base64

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


# Annotation type mapping for PyMuPDF 1.26+
ANNOT_TYPE_NAMES = {
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


class PDFAnalyzer:
    def __init__(self, pdf_path: str):
        """Initialize the PDF analyzer with a PDF file path."""
        self.pdf_path = Path(pdf_path)
        if not self.pdf_path.exists():
            raise FileNotFoundError(f"PDF file not found: {pdf_path}")
        
        self.doc = fitz.open(pdf_path)
        self.analysis_results = {
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
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    def analyze(self, check_virustotal: bool = False) -> Dict[str, Any]:
        """Perform complete PDF analysis."""
        print(f"Analyzing PDF: {self.pdf_path}")
        
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
        
        if check_virustotal:
            self._check_virustotal()
        
        self._calculate_malware_risk()
        
        return self.analysis_results
    
    def _analyze_file_info(self):
        """Extract basic file information."""
        self.analysis_results['file_info'] = {
            'filename': self.pdf_path.name,
            'file_size': self.pdf_path.stat().st_size,
            'page_count': self.doc.page_count,
            'is_pdf': self.doc.is_pdf,
            'is_encrypted': self.doc.is_encrypted
        }
    
    def _analyze_header(self):
        """Analyze PDF header for suspicious patterns."""
        with open(self.pdf_path, 'rb') as f:
            header_bytes = f.read(1024)
        
        try:
            header_str = header_bytes.decode('latin-1')
        except:
            header_str = str(header_bytes)
        
        pdf_header_match = re.search(r'%PDF-(\d+\.\d+)', header_str)
        
        header_info = {
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
    
    def _analyze_metadata(self):
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
    
    def _analyze_version_info(self):
        """Extract PDF version information."""
        # Try to get PDF version from different sources
        pdf_version = None
        if hasattr(self.doc, 'pdf_version'):
            try:
                pdf_version = self.doc.pdf_version()
            except:
                pass
        
        # Fallback to header analysis if available
        if not pdf_version and 'header_analysis' in self.analysis_results:
            pdf_version = self.analysis_results['header_analysis'].get('pdf_version_header', None)
        
        # Fallback to metadata format
        if not pdf_version:
            metadata = self.doc.metadata
            if metadata and 'format' in metadata:
                pdf_version = metadata['format'].replace('PDF ', '')
        
        self.analysis_results['version_info'] = {
            'pdf_version': pdf_version or 'Unknown',
            'pdf_catalog': self.doc.pdf_catalog() if hasattr(self.doc, 'pdf_catalog') else None,
            'has_outline': bool(self.doc.get_toc()),
            'outline_items': len(self.doc.get_toc()) if self.doc.get_toc() else 0
        }
    
    def _analyze_security(self):
        """Extract security information."""
        # In PyMuPDF 1.26+, permissions is an integer with bit flags
        permissions_dict = {}
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
                # Old API: dictionary (for backward compatibility)
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
    
    def _analyze_pages(self):
        """Analyze page information."""
        page_info = []
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
    
    def _analyze_links(self):
        """Extract all links from the PDF."""
        all_links = []
        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            links = page.get_links()
            
            for link in links:
                link_info = {
                    'page': page_num + 1,
                    'type': link.get('type', link.get('kind', 0)),  # 'kind' in newer API
                    'rect': link.get('rect', link.get('from', [])),  # 'from' in newer API
                    'uri': link.get('uri', ''),
                    'dest': link.get('dest', ''),
                    'file': link.get('file', ''),
                    'named': link.get('named', '')
                }
                all_links.append(link_info)
        
        self.analysis_results['links'] = all_links
    
    def _analyze_annotations(self):
        """Extract all annotations from the PDF."""
        all_annotations = []
        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            annots = page.annots()
            
            for annot in annots:
                # Handle both old (tuple) and new (int) API for annot.type
                if isinstance(annot.type, tuple):
                    annot_type = annot.type[1]
                else:
                    # In newer PyMuPDF, type is an int - map to string
                    annot_type = ANNOT_TYPE_NAMES.get(annot.type, f'Unknown({annot.type})')
                
                annot_info = {
                    'page': page_num + 1,
                    'type': annot_type,
                    'rect': list(annot.rect),
                    'contents': annot.info.get('content', ''),
                    'author': annot.info.get('title', ''),
                    'creation_date': annot.info.get('creationDate', ''),
                    'modification_date': annot.info.get('modDate', '')
                }
                
                # Add specific annotation details based on type
                if annot_type == 'Text':
                    annot_info['text'] = annot.info.get('text', '')
                elif annot_type == 'Link':
                    annot_info['uri'] = annot.info.get('uri', '')
                
                all_annotations.append(annot_info)
        
        self.analysis_results['annotations'] = all_annotations
    
    def _analyze_suspicious_keywords(self):
        """Scan PDF content for suspicious keywords."""
        suspicious_keywords = {
            '/JS': 0,
            '/JavaScript': 0,
            '/AA': 0,
            '/OpenAction': 0,
            '/AcroForm': 0,
            '/JBIG2Decode': 0,
            '/RichMedia': 0,
            '/Launch': 0,
            '/EmbeddedFile': 0,
            '/XFA': 0,
            '/Encrypt': 0,
            '/ObjStm': 0,
            'obj': 0,
            'endobj': 0,
            'stream': 0,
            'endstream': 0
        }
        
        try:
            with open(self.pdf_path, 'rb') as f:
                content = f.read()
            
            content_str = content.decode('latin-1', errors='ignore')
            
            for keyword in suspicious_keywords.keys():
                count = content_str.count(keyword)
                suspicious_keywords[keyword] = count
        
        except Exception as e:
            print(f"Error scanning for suspicious keywords: {e}")
        
        self.analysis_results['suspicious_keywords'] = suspicious_keywords
    
    def _analyze_javascript(self):
        """Extract JavaScript code from the PDF."""
        javascript_code = []
        
        # Check for JavaScript in document-level scripts
        try:
            if hasattr(self.doc, 'get_js_scripts'):
                doc_scripts = self.doc.get_js_scripts()
                if doc_scripts:
                    javascript_code.extend(doc_scripts)
        except Exception as e:
            print(f"Error extracting document-level JavaScript: {e}")
        
        # Check for JavaScript in page-level actions
        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            
            # Check page actions
            if hasattr(page, 'get_js_scripts'):
                try:
                    page_scripts = page.get_js_scripts()
                    if page_scripts:
                        for script in page_scripts:
                            javascript_code.append({
                                'page': page_num + 1,
                                'type': 'page_script',
                                'code': script
                            })
                except Exception as e:
                    print(f"Error extracting page {page_num + 1} JavaScript: {e}")
            
            # Check annotation JavaScript
            for annot in page.annots():
                if hasattr(annot, 'get_js_scripts'):
                    try:
                        annot_scripts = annot.get_js_scripts()
                        if annot_scripts:
                            # Handle both old (tuple) and new (int) API for annot.type
                            if isinstance(annot.type, tuple):
                                annot_type = annot.type[1]
                            else:
                                annot_type = ANNOT_TYPE_NAMES.get(annot.type, f'Unknown({annot.type})')
                            
                            for script in annot_scripts:
                                javascript_code.append({
                                    'page': page_num + 1,
                                    'type': 'annotation_script',
                                    'annotation_type': annot_type,
                                    'code': script
                                })
                    except Exception as e:
                        print(f"Error extracting annotation JavaScript: {e}")
        
        self.analysis_results['javascript'] = javascript_code
    
    def _analyze_resources(self):
        """Analyze resources like images and fonts."""
        images = []
        fonts = set()
        other_resources = []
        
        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            
            # Extract images
            page_images = page.get_images()
            for img_index, img in enumerate(page_images):
                try:
                    xref = img[0]
                    pix = fitz.Pixmap(self.doc, xref)
                    
                    image_info = {
                        'page': page_num + 1,
                        'xref': xref,
                        'width': pix.width,
                        'height': pix.height,
                        'colorspace': pix.colorspace.name if pix.colorspace else None,
                        'n_channels': pix.n,
                        'alpha': pix.alpha,
                        'size': len(pix.samples) if pix.samples else 0
                    }
                    
                    # Get image format
                    if pix.n == 1:
                        image_info['format'] = 'grayscale'
                    elif pix.n == 3:
                        image_info['format'] = 'RGB'
                    elif pix.n == 4:
                        image_info['format'] = 'RGBA'
                    
                    images.append(image_info)
                    pix = None  # Free memory
                except Exception as e:
                    print(f"Error extracting image {img_index} from page {page_num + 1}: {e}")
            
            # Extract fonts
            try:
                page_fonts = page.get_fonts()
                for font in page_fonts:
                    font_info = {
                        'page': page_num + 1,
                        'name': font[0],
                        'type': font[1],
                        'encoding': font[2],
                        'embedded': font[3],
                        'cid': font[4]
                    }
                    fonts.add(font[0])  # Add font name to set
            except Exception as e:
                print(f"Error extracting fonts from page {page_num + 1}: {e}")
        
        self.analysis_results['resources']['images'] = images
        self.analysis_results['resources']['fonts'] = list(fonts)
    
    def _analyze_form_fields(self):
        """Extract form field information."""
        form_fields = []
        
        for page_num in range(self.doc.page_count):
            page = self.doc[page_num]
            
            # Get widgets (form fields)
            widgets = page.widgets()
            for widget in widgets:
                field_info = {
                    'page': page_num + 1,
                    'type': widget.field_type,
                    'name': widget.field_name,
                    'value': widget.field_value,
                    'rect': list(widget.rect),
                    'flags': widget.field_flags,
                    'readonly': widget.readonly,
                    'required': widget.required
                }
                form_fields.append(field_info)
        
        self.analysis_results['form_fields'] = form_fields
    
    def _calculate_file_hashes(self) -> Dict[str, str]:
        """Calculate MD5, SHA1, and SHA256 hashes of the PDF file."""
        hashes = {'md5': '', 'sha1': '', 'sha256': ''}
        
        try:
            with open(self.pdf_path, 'rb') as f:
                file_data = f.read()
                hashes['md5'] = hashlib.md5(file_data).hexdigest()
                hashes['sha1'] = hashlib.sha1(file_data).hexdigest()
                hashes['sha256'] = hashlib.sha256(file_data).hexdigest()
        except Exception as e:
            print(f"Error calculating file hashes: {e}")
        
        return hashes
    
    def _check_virustotal(self):
        """Check file hash against VirusTotal API."""
        vt_results = {
            'checked': False,
            'api_available': REQUESTS_AVAILABLE,
            'api_key_present': bool(self.vt_api_key),
            'hashes': {},
            'scan_results': {},
            'error': None
        }
        
        if not REQUESTS_AVAILABLE:
            vt_results['error'] = 'requests library not installed'
            self.analysis_results['virustotal'] = vt_results
            return
        
        if not self.vt_api_key:
            vt_results['error'] = 'VIRUSTOTAL_API_KEY environment variable not set'
            self.analysis_results['virustotal'] = vt_results
            return
        
        print("Calculating file hashes...")
        hashes = self._calculate_file_hashes()
        vt_results['hashes'] = hashes
        
        if not hashes['sha256']:
            vt_results['error'] = 'Failed to calculate file hash'
            self.analysis_results['virustotal'] = vt_results
            return
        
        print(f"Checking VirusTotal for SHA256: {hashes['sha256']}")
        
        try:
            url = f"https://www.virustotal.com/api/v3/files/{hashes['sha256']}"
            headers = {
                'x-apikey': self.vt_api_key
            }
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                stats = attributes.get('last_analysis_stats', {})
                results = attributes.get('last_analysis_results', {})
                
                vt_results['checked'] = True
                vt_results['scan_results'] = {
                    'sha256': hashes['sha256'],
                    'first_submission': attributes.get('first_submission_date', ''),
                    'last_analysis': attributes.get('last_analysis_date', ''),
                    'stats': stats,
                    'malicious': stats.get('malicious', 0),
                    'suspicious': stats.get('suspicious', 0),
                    'undetected': stats.get('undetected', 0),
                    'harmless': stats.get('harmless', 0),
                    'total_engines': sum(stats.values()) if stats else 0,
                    'popular_threat_name': attributes.get('popular_threat_classification', {}).get('suggested_threat_label', 'N/A'),
                    'names': attributes.get('names', []),
                    'tags': attributes.get('tags', []),
                    'detections': []
                }
                
                # Get detection details from engines that flagged it
                if results:
                    for engine, result in results.items():
                        if result.get('category') in ['malicious', 'suspicious']:
                            vt_results['scan_results']['detections'].append({
                                'engine': engine,
                                'category': result.get('category'),
                                'result': result.get('result', 'N/A')
                            })
                
                print(f"✓ VirusTotal: {stats.get('malicious', 0)}/{vt_results['scan_results']['total_engines']} engines detected as malicious")
                
            elif response.status_code == 404:
                vt_results['checked'] = True
                vt_results['scan_results'] = {
                    'sha256': hashes['sha256'],
                    'message': 'File not found in VirusTotal database',
                    'status': 'not_found'
                }
                print("ℹ File not found in VirusTotal database (may be new/unknown)")
                
            elif response.status_code == 429:
                vt_results['error'] = 'VirusTotal API rate limit exceeded'
                print("⚠ VirusTotal API rate limit exceeded")
                
            else:
                vt_results['error'] = f"VirusTotal API returned status code {response.status_code}"
                print(f"⚠ VirusTotal check failed: {response.status_code}")
                
        except requests.exceptions.Timeout:
            vt_results['error'] = 'VirusTotal API request timed out'
            print("⚠ VirusTotal API request timed out")
        except requests.exceptions.RequestException as e:
            vt_results['error'] = f"VirusTotal API request failed: {str(e)}"
            print(f"⚠ VirusTotal API request failed: {e}")
        except Exception as e:
            vt_results['error'] = f"Unexpected error: {str(e)}"
            print(f"⚠ Unexpected error during VirusTotal check: {e}")
        
        self.analysis_results['virustotal'] = vt_results
    
    def _calculate_malware_risk(self):
        """Calculate malware risk based on suspicious indicators."""
        risk_score = 0
        risk_factors = []
        
        keywords = self.analysis_results['suspicious_keywords']
        
        has_js = keywords.get('/JS', 0) > 0 or keywords.get('/JavaScript', 0) > 0
        has_auto_action = keywords.get('/AA', 0) > 0 or keywords.get('/OpenAction', 0) > 0
        has_acroform = keywords.get('/AcroForm', 0) > 0
        has_jbig2 = keywords.get('/JBIG2Decode', 0) > 0
        has_richmedia = keywords.get('/RichMedia', 0) > 0
        has_launch = keywords.get('/Launch', 0) > 0
        has_embedded = keywords.get('/EmbeddedFile', 0) > 0
        has_xfa = keywords.get('/XFA', 0) > 0
        has_objstm = keywords.get('/ObjStm', 0) > 0
        
        if has_js:
            risk_score += 50
            risk_factors.append({
                'factor': 'JavaScript present',
                'severity': 'high',
                'description': f"PDF contains JavaScript ({keywords['/JS']} /JS, {keywords['/JavaScript']} /JavaScript)",
                'score': 50
            })
        
        if has_auto_action:
            if has_js:
                # High risk when combined with JavaScript
                risk_score += 40
                risk_factors.append({
                    'factor': 'JavaScript + Auto-action combination',
                    'severity': 'high',
                    'description': f"Dangerous combination: JavaScript with automatic execution (/AA: {keywords['/AA']}, /OpenAction: {keywords['/OpenAction']})",
                    'score': 40
                })
            else:
                # Low risk when alone (no JavaScript)
                risk_score += 20
                risk_factors.append({
                    'factor': 'Automatic action (no JavaScript)',
                    'severity': 'low',
                    'description': f"PDF has automatic actions without JavaScript (/AA: {keywords['/AA']}, /OpenAction: {keywords['/OpenAction']})",
                    'score': 20
                })
        
        if has_launch:
            risk_score += 35
            risk_factors.append({
                'factor': 'Launch action',
                'severity': 'high',
                'description': f"PDF can launch external programs ({keywords['/Launch']} occurrences)",
                'score': 35
            })
        
        if has_embedded:
            risk_score += 20
            risk_factors.append({
                'factor': 'Embedded files',
                'severity': 'medium',
                'description': f"PDF contains embedded files ({keywords['/EmbeddedFile']} occurrences)",
                'score': 20
            })
        
        if has_jbig2:
            risk_score += 25
            risk_factors.append({
                'factor': 'JBIG2 compression',
                'severity': 'medium',
                'description': 'Uses JBIG2Decode (potential CVE-2009-0658 vulnerability)',
                'score': 25
            })
        
        if has_richmedia:
            risk_score += 20
            risk_factors.append({
                'factor': 'RichMedia/Flash',
                'severity': 'medium',
                'description': 'Contains embedded Flash/RichMedia content',
                'score': 20
            })
        
        if has_xfa:
            risk_score += 15
            risk_factors.append({
                'factor': 'XFA forms',
                'severity': 'low',
                'description': 'Uses XML Forms Architecture',
                'score': 15
            })
        
        if has_objstm:
            risk_score += 10
            risk_factors.append({
                'factor': 'Object streams',
                'severity': 'low',
                'description': 'Contains object streams (can be used for obfuscation)',
                'score': 10
            })
        
        if self.analysis_results['file_info']['page_count'] == 1 and has_js:
            risk_score += 15
            risk_factors.append({
                'factor': 'Single page with scripts',
                'severity': 'medium',
                'description': 'Single-page PDF with JavaScript (common in malware)',
                'score': 15
            })
        
        header_issues = self.analysis_results['header_analysis'].get('suspicious_patterns', [])
        if header_issues:
            for issue in header_issues:
                if issue['severity'] == 'high':
                    risk_score += 20
                elif issue['severity'] == 'medium':
                    risk_score += 10
            risk_factors.append({
                'factor': 'Header anomalies',
                'severity': 'medium',
                'description': f"Found {len(header_issues)} suspicious header pattern(s)",
                'score': len(header_issues) * 10
            })
        
        # Integrate VirusTotal results
        vt_data = self.analysis_results.get('virustotal', {})
        if vt_data.get('checked') and vt_data.get('scan_results'):
            scan = vt_data['scan_results']
            if 'malicious' in scan:
                malicious_count = scan['malicious']
                total_engines = scan.get('total_engines', 0)
                
                if malicious_count > 0:
                    # Calculate VT risk score based on detection ratio
                    if total_engines > 0:
                        detection_ratio = malicious_count / total_engines
                        vt_risk_score = int(detection_ratio * 100)
                        
                        # Cap at 50 points max from VT
                        vt_risk_score = min(vt_risk_score, 50)
                        risk_score += vt_risk_score
                        
                        severity = 'high' if detection_ratio > 0.1 else 'medium'
                        
                        risk_factors.append({
                            'factor': 'VirusTotal detection',
                            'severity': severity,
                            'description': f"{malicious_count}/{total_engines} antivirus engines flagged as malicious",
                            'score': vt_risk_score
                        })
                        
                        if scan.get('popular_threat_name') and scan['popular_threat_name'] != 'N/A':
                            risk_factors[-1]['threat_name'] = scan['popular_threat_name']
        
        if risk_score >= 75:
            risk_level = 'HIGH'
        elif risk_score > 40:
            risk_level = 'MEDIUM'
        elif risk_score > 0:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'
        
        self.analysis_results['malware_risk'] = {
            'risk_score': min(risk_score, 100),
            'risk_level': risk_level,
            'risk_factors': risk_factors,
            'is_suspicious': risk_score >= 50,
            'recommendations': self._get_risk_recommendations(risk_level, risk_factors)
        }
    
    def _get_risk_recommendations(self, risk_level: str, risk_factors: List[Dict]) -> List[str]:
        """Get security recommendations based on risk assessment."""
        recommendations = []
        
        if risk_level == 'HIGH':
            recommendations.append('⚠️ DO NOT OPEN this PDF in a standard viewer')
            recommendations.append('Use a sandboxed environment for analysis')
            recommendations.append('Scan with antivirus/malware detection tools')
        
        if risk_level == 'MEDIUM':
            recommendations.append('⚠️ Exercise caution when opening this PDF')
            recommendations.append('Disable JavaScript in your PDF reader')
        
        if any(f['factor'] == 'JavaScript + Auto-action combination' for f in risk_factors):
            recommendations.append('High likelihood of automated malware execution')
        
        if any(f['factor'] == 'Launch action' for f in risk_factors):
            recommendations.append('PDF may attempt to launch external programs')
        
        if any(f['factor'] == 'Embedded files' for f in risk_factors):
            recommendations.append('Examine embedded files separately')
        
        if risk_level == 'SAFE':
            recommendations.append('✓ No obvious malicious indicators detected')
        
        return recommendations
    
    def print_summary(self):
        """Print a summary of the analysis results."""
        results = self.analysis_results
        
        print("\n" + "="*60)
        print("PDF ANALYSIS SUMMARY")
        print("="*60)
        
        # File Info
        print(f"\n📄 File Information:")
        print(f"   Name: {results['file_info']['filename']}")
        print(f"   Size: {results['file_info']['file_size']:,} bytes")
        print(f"   Pages: {results['file_info']['page_count']}")
        print(f"   Encrypted: {results['file_info']['is_encrypted']}")
        
        # PDF Version
        print(f"\n📋 PDF Version: {results['version_info']['pdf_version']}")
        print(f"   Has Outline: {results['version_info']['has_outline']}")
        print(f"   Outline Items: {results['version_info']['outline_items']}")
        
        # Metadata
        if any(results['metadata'].values()):
            print(f"\n📝 Metadata:")
            for key, value in results['metadata'].items():
                if value:
                    print(f"   {key.title()}: {value}")
        
        # Links
        print(f"\n🔗 Links: {len(results['links'])} found")
        if results['links']:
            external_links = [link for link in results['links'] if link['uri']]
            internal_links = [link for link in results['links'] if link['dest']]
            print(f"   External: {len(external_links)}")
            print(f"   Internal: {len(internal_links)}")
            
            # Display all external links with destinations
            if external_links:
                print(f"\n   📌 External Links Found:")
                for i, link in enumerate(external_links, 1):
                    page = link.get('page', '?')
                    uri = link.get('uri', 'N/A')
                    print(f"      {i}. Page {page}: {uri}")
        
        # JavaScript
        print(f"\n⚡ JavaScript: {len(results['javascript'])} scripts found")
        for i, js in enumerate(results['javascript'][:3]):  # Show first 3
            print(f"   {i+1}. {js.get('type', 'unknown')} on page {js.get('page', 'N/A')}")
        if len(results['javascript']) > 3:
            print(f"   ... and {len(results['javascript']) - 3} more")
        
        # Resources
        print(f"\n🎨 Resources:")
        print(f"   Images: {len(results['resources']['images'])}")
        print(f"   Fonts: {len(results['resources']['fonts'])}")
        
        # Form Fields
        print(f"\n📝 Form Fields: {len(results['form_fields'])} found")
        if results['form_fields']:
            field_types = {}
            for field in results['form_fields']:
                field_type = field['type']
                field_types[field_type] = field_types.get(field_type, 0) + 1
            for field_type, count in field_types.items():
                print(f"   {field_type}: {count}")
        
        # Header Analysis
        print(f"\n📋 Header Analysis:")
        header = results['header_analysis']
        print(f"   Valid Header: {'✓' if header['has_valid_header'] else '✗'}")
        if header['has_valid_header']:
            print(f"   Header: {header['header_string']}")
            print(f"   At Start: {'✓' if header['is_header_at_start'] else '✗'}")
        if header['suspicious_patterns']:
            print(f"   ⚠️  Suspicious Patterns Found: {len(header['suspicious_patterns'])}")
            for pattern in header['suspicious_patterns'][:3]:
                print(f"      - {pattern['description']}")
        
        # Suspicious Keywords
        print(f"\n🔍 Suspicious Keywords:")
        keywords = results['suspicious_keywords']
        suspicious_found = False
        for key in ['/JS', '/JavaScript', '/AA', '/OpenAction', '/Launch', '/EmbeddedFile', 
                    '/JBIG2Decode', '/RichMedia', '/XFA', '/AcroForm']:
            if keywords.get(key, 0) > 0:
                suspicious_found = True
                print(f"   {key}: {keywords[key]}")
        if not suspicious_found:
            print(f"   None detected")
        
        # VirusTotal Results
        vt = results.get('virustotal', {})
        if vt.get('checked'):
            print(f"\n🛡️  VirusTotal Analysis:")
            scan = vt.get('scan_results', {})
            
            if scan.get('status') == 'not_found':
                print(f"   Status: File not in VirusTotal database")
                print(f"   SHA256: {scan.get('sha256', 'N/A')}")
            elif 'malicious' in scan:
                malicious = scan.get('malicious', 0)
                total = scan.get('total_engines', 0)
                
                if malicious > 0:
                    detection_icon = '🔴' if malicious > total * 0.3 else '🟠' if malicious > total * 0.1 else '🟡'
                    print(f"   {detection_icon} Detections: {malicious}/{total} engines flagged as malicious")
                else:
                    print(f"   ✅ Detections: 0/{total} engines (clean)")
                
                if scan.get('popular_threat_name') and scan['popular_threat_name'] != 'N/A':
                    print(f"   Threat Name: {scan['popular_threat_name']}")
                
                if scan.get('suspicious', 0) > 0:
                    print(f"   Suspicious: {scan['suspicious']}")
                
                if scan.get('detections'):
                    print(f"   Top Detections:")
                    for det in scan['detections'][:5]:
                        print(f"      • {det['engine']}: {det['result']}")
                
                print(f"   SHA256: {scan.get('sha256', 'N/A')}")
        elif vt.get('error'):
            print(f"\n🛡️  VirusTotal: {vt['error']}")
        
        # Malware Risk Assessment
        risk = results['malware_risk']
        risk_colors = {
            'HIGH': '🔴',
            'MEDIUM': '🟠',
            'LOW': '🟢',
            'SAFE': '✅'
        }
        print(f"\n{risk_colors.get(risk['risk_level'], '❓')} MALWARE RISK ASSESSMENT:")
        print(f"   Risk Level: {risk['risk_level']}")
        print(f"   Risk Score: {risk['risk_score']}/100")
        
        if risk['risk_factors']:
            print(f"\n   Risk Factors Detected:")
            for factor in risk['risk_factors']:
                severity_icon = {'high': '🔴', 'medium': '🟠', 'low': '🟢'}
                icon = severity_icon.get(factor['severity'], '•')
                print(f"      {icon} {factor['factor']} (+{factor['score']} points)")
                print(f"         {factor['description']}")
        
        if risk['recommendations']:
            print(f"\n   Recommendations:")
            for rec in risk['recommendations']:
                print(f"      • {rec}")
        
        # Security
        print(f"\n🔒 Security:")
        print(f"   Encrypted: {results['security']['is_encrypted']}")
        if results['security'].get('permissions'):
            perms = results['security']['permissions']
            print(f"   Print: {'✓' if perms['print'] else '✗'}")
            print(f"   Copy: {'✓' if perms['copy'] else '✗'}")
            print(f"   Modify: {'✓' if perms['modify'] else '✗'}")
        
        print("\n" + "="*60)
    
    def save_results(self, output_path: str):
        """Save analysis results to a JSON file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.analysis_results, f, indent=2, default=str)
        print(f"\n📊 Analysis results saved to: {output_path}")
    
    def close(self):
        """Close the PDF document."""
        if self.doc:
            self.doc.close()


def main():
    parser = argparse.ArgumentParser(
        description='PDF Analysis Tool with Malware Detection',
        epilog='Set VIRUSTOTAL_API_KEY environment variable to enable VirusTotal scanning'
    )
    parser.add_argument('pdf_file', help='Path to the PDF file to analyze')
    parser.add_argument('-o', '--output', help='Output JSON file path')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--virustotal', action='store_true', 
                       help='Check file hash against VirusTotal (requires API key)')
    
    args = parser.parse_args()
    
    try:
        analyzer = PDFAnalyzer(args.pdf_file)
        results = analyzer.analyze(check_virustotal=args.virustotal)
        
        # Print summary
        analyzer.print_summary()
        
        # Save results if output path specified
        if args.output:
            analyzer.save_results(args.output)
        
        # Verbose mode - print detailed results
        if args.verbose:
            print("\n" + "="*60)
            print("DETAILED ANALYSIS RESULTS")
            print("="*60)
            print(json.dumps(results, indent=2, default=str))
        
        analyzer.close()
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
