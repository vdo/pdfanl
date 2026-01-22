"""
Output formatting for pdfanl.

Provides console output and JSON export functionality.
"""

import json
import logging
from pathlib import Path
from typing import Any, TextIO
import sys

logger = logging.getLogger(__name__)


class OutputFormatter:
    """Formats analysis results for display."""

    def __init__(self, results: dict[str, Any], output: TextIO = sys.stdout) -> None:
        """
        Initialize formatter.

        Args:
            results: Analysis results dictionary.
            output: Output stream (default: stdout).
        """
        self.results = results
        self.output = output

    def print(self, *args: Any, **kwargs: Any) -> None:
        """Print to output stream."""
        print(*args, file=self.output, **kwargs)

    def print_summary(self) -> None:
        """Print a formatted summary of the analysis results."""
        self.print("\n" + "=" * 60)
        self.print("PDF ANALYSIS SUMMARY")
        self.print("=" * 60)

        self._print_file_info()
        self._print_version_info()
        self._print_metadata()
        self._print_links()
        self._print_javascript()
        self._print_resources()
        self._print_form_fields()
        self._print_header_analysis()
        self._print_suspicious_keywords()
        self._print_virustotal()
        self._print_malware_risk()
        self._print_security()

        self.print("\n" + "=" * 60)

    def _print_file_info(self) -> None:
        """Print file information."""
        info = self.results['file_info']
        self.print(f"\nFile Information:")
        self.print(f"   Name: {info['filename']}")
        self.print(f"   Size: {info['file_size']:,} bytes")
        self.print(f"   Pages: {info['page_count']}")
        self.print(f"   Encrypted: {info['is_encrypted']}")

    def _print_version_info(self) -> None:
        """Print PDF version information."""
        version = self.results['version_info']
        self.print(f"\nPDF Version: {version['pdf_version']}")
        self.print(f"   Has Outline: {version['has_outline']}")
        self.print(f"   Outline Items: {version['outline_items']}")

    def _print_metadata(self) -> None:
        """Print metadata if present."""
        metadata = self.results['metadata']
        if any(metadata.values()):
            self.print(f"\nMetadata:")
            for key, value in metadata.items():
                if value:
                    self.print(f"   {key.replace('_', ' ').title()}: {value}")

    def _print_links(self) -> None:
        """Print link information."""
        links = self.results['links']
        self.print(f"\nLinks: {len(links)} found")

        if links:
            external_links = [link for link in links if link['uri']]
            internal_links = [link for link in links if link['dest']]
            self.print(f"   External: {len(external_links)}")
            self.print(f"   Internal: {len(internal_links)}")

            if external_links:
                self.print(f"\n   External Links Found:")
                for i, link in enumerate(external_links, 1):
                    page = link.get('page', '?')
                    uri = link.get('uri', 'N/A')
                    self.print(f"      {i}. Page {page}: {uri}")

    def _print_javascript(self) -> None:
        """Print JavaScript information."""
        js_code = self.results['javascript']
        standalone = [js for js in js_code if 'widget' not in js.get('type', '')]
        widgets = [js for js in js_code if 'widget' in js.get('type', '')]

        self.print(f"\nJavaScript: {len(js_code)} scripts found")

        if standalone:
            self.print(f"   Standalone: {len(standalone)}")
            for i, js in enumerate(standalone[:2]):
                page_info = (
                    f"page {js.get('page', 'N/A')}"
                    if js.get('page', 0) > 0
                    else "document-level"
                )
                self.print(f"      {i + 1}. {js.get('type', 'unknown')} on {page_info}")
                if js.get('code'):
                    preview = js['code'][:80].replace('\n', ' ').replace('\r', '')
                    self.print(f"         Code: {preview}...")
            if len(standalone) > 2:
                self.print(f"      ... and {len(standalone) - 2} more")

        if widgets:
            self.print(f"   Widget actions: {len(widgets)}")
            for i, js in enumerate(widgets[:2]):
                field = js.get('field_name', 'unnamed')
                script_type = js.get('type', 'unknown').replace('widget_', '')
                self.print(f"      {i + 1}. Field '{field}' ({script_type})")
                if js.get('code'):
                    preview = js['code'][:80].replace('\n', ' ').replace('\r', '')
                    self.print(f"         Code: {preview}...")
            if len(widgets) > 2:
                self.print(f"      ... and {len(widgets) - 2} more")

    def _print_resources(self) -> None:
        """Print resource information."""
        resources = self.results['resources']
        self.print(f"\nResources:")
        self.print(f"   Images: {len(resources['images'])}")
        self.print(f"   Fonts: {len(resources['fonts'])}")

    def _print_form_fields(self) -> None:
        """Print form field information."""
        fields = self.results['form_fields']
        self.print(f"\nForm Fields: {len(fields)} found")

        if fields:
            field_types: dict[str, int] = {}
            for field in fields:
                ft = field['type']
                field_types[ft] = field_types.get(ft, 0) + 1
            for ft, count in field_types.items():
                self.print(f"   {ft}: {count}")

    def _print_header_analysis(self) -> None:
        """Print header analysis."""
        header = self.results['header_analysis']
        valid = header['has_valid_header']

        self.print(f"\nHeader Analysis:")
        self.print(f"   Valid Header: {'Yes' if valid else 'No'}")

        if valid:
            self.print(f"   Header: {header['header_string']}")
            self.print(f"   At Start: {'Yes' if header['is_header_at_start'] else 'No'}")

        patterns = header.get('suspicious_patterns', [])
        if patterns:
            self.print(f"   WARNING: Suspicious Patterns Found: {len(patterns)}")
            for pattern in patterns[:3]:
                self.print(f"      - {pattern['description']}")

    def _print_suspicious_keywords(self) -> None:
        """Print suspicious keyword counts."""
        keywords = self.results['suspicious_keywords']
        suspicious_keys = [
            '/JS', '/JavaScript', '/AA', '/OpenAction', '/Launch',
            '/EmbeddedFile', '/JBIG2Decode', '/RichMedia', '/XFA',
            '/AcroForm', '/ObjStm', '/GoToE', '/GoToR', '/SubmitForm'
        ]

        self.print(f"\nSuspicious Keywords:")

        found = False
        for key in suspicious_keys:
            if keywords.get(key, 0) > 0:
                found = True
                self.print(f"   {key}: {keywords[key]}")

        if not found:
            self.print(f"   None detected")

    def _print_virustotal(self) -> None:
        """Print VirusTotal results."""
        vt = self.results.get('virustotal', {})

        if vt.get('checked'):
            self.print(f"\nVirusTotal Analysis:")
            scan = vt.get('scan_results', {})

            if scan.get('status') == 'not_found':
                self.print(f"   Status: File not in VirusTotal database")
                self.print(f"   SHA256: {scan.get('sha256', 'N/A')}")

            elif 'malicious' in scan:
                malicious = scan.get('malicious', 0)
                total = scan.get('total_engines', 0)

                if malicious > 0:
                    ratio = malicious / total if total > 0 else 0
                    icon = 'HIGH' if ratio > 0.3 else 'MEDIUM' if ratio > 0.1 else 'LOW'
                    self.print(
                        f"   [{icon}] Detections: {malicious}/{total} "
                        "engines flagged as malicious"
                    )
                else:
                    self.print(f"   [CLEAN] Detections: 0/{total} engines")

                threat = scan.get('popular_threat_name', '')
                if threat and threat != 'N/A':
                    self.print(f"   Threat Name: {threat}")

                suspicious = scan.get('suspicious', 0)
                if suspicious > 0:
                    self.print(f"   Suspicious: {suspicious}")

                detections = scan.get('detections', [])
                if detections:
                    self.print(f"   Top Detections:")
                    for det in detections[:5]:
                        self.print(f"      - {det['engine']}: {det['result']}")

                self.print(f"   SHA256: {scan.get('sha256', 'N/A')}")

        elif vt.get('error'):
            self.print(f"\nVirusTotal: {vt['error']}")

    def _print_malware_risk(self) -> None:
        """Print malware risk assessment."""
        risk = self.results['malware_risk']
        level = risk['risk_level']

        level_markers = {
            'HIGH': '[!!!]',
            'MEDIUM': '[!!]',
            'LOW': '[!]',
            'SAFE': '[OK]'
        }

        self.print(f"\n{level_markers.get(level, '[?]')} MALWARE RISK ASSESSMENT:")
        self.print(f"   Risk Level: {level}")
        self.print(f"   Risk Score: {risk['risk_score']}/100")

        factors = risk.get('risk_factors', [])
        if factors:
            self.print(f"\n   Risk Factors Detected:")
            for factor in factors:
                severity = factor.get('severity', 'unknown').upper()
                self.print(
                    f"      [{severity}] {factor['factor']} "
                    f"(+{factor['score']} points)"
                )
                self.print(f"         {factor['description']}")

        recommendations = risk.get('recommendations', [])
        if recommendations:
            self.print(f"\n   Recommendations:")
            for rec in recommendations:
                self.print(f"      - {rec}")

    def _print_security(self) -> None:
        """Print security information."""
        security = self.results['security']

        self.print(f"\nSecurity:")
        self.print(f"   Encrypted: {security['is_encrypted']}")

        perms = security.get('permissions', {})
        if perms:
            self.print(f"   Print: {'Yes' if perms.get('print') else 'No'}")
            self.print(f"   Copy: {'Yes' if perms.get('copy') else 'No'}")
            self.print(f"   Modify: {'Yes' if perms.get('modify') else 'No'}")


def save_results(results: dict[str, Any], output_path: str | Path) -> None:
    """
    Save analysis results to a JSON file.

    Args:
        results: Analysis results dictionary.
        output_path: Path to output file.
    """
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2, default=str)
    logger.info(f"Analysis results saved to: {output_path}")


def print_detailed_results(results: dict[str, Any], output: TextIO = sys.stdout) -> None:
    """
    Print detailed JSON results.

    Args:
        results: Analysis results dictionary.
        output: Output stream.
    """
    print("\n" + "=" * 60, file=output)
    print("DETAILED ANALYSIS RESULTS", file=output)
    print("=" * 60, file=output)
    print(json.dumps(results, indent=2, default=str), file=output)
