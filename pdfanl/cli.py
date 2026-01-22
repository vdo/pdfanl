"""
Command-line interface for pdfanl.
"""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .analyzer import FileTooLargeError, PDFAnalyzer
from .config import AnalyzerConfig, DEFAULT_MAX_FILE_SIZE_MB
from .output import OutputFormatter, print_detailed_results, save_results


def setup_logging(verbose: bool = False, debug: bool = False) -> None:
    """Configure logging based on verbosity."""
    if debug:
        level = logging.DEBUG
        fmt = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    elif verbose:
        level = logging.INFO
        fmt = '%(levelname)s: %(message)s'
    else:
        level = logging.WARNING
        fmt = '%(message)s'

    logging.basicConfig(level=level, format=fmt)


def parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        prog='pdfanl',
        description='PDF Analysis Tool with Malware Detection',
        epilog=(
            'Set VIRUSTOTAL_API_KEY environment variable to enable '
            'VirusTotal scanning.\n\n'
            'Examples:\n'
            '  pdfanl document.pdf                    # Basic analysis\n'
            '  pdfanl document.pdf -o results.json   # Save to JSON\n'
            '  pdfanl document.pdf --virustotal      # Check VirusTotal\n'
            '  pdfanl document.pdf -v                # Verbose output'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        'pdf_file',
        help='Path to the PDF file to analyze'
    )

    parser.add_argument(
        '-o', '--output',
        metavar='FILE',
        help='Output JSON file path'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed results in JSON format'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    parser.add_argument(
        '--virustotal',
        action='store_true',
        help='Check file hash against VirusTotal (requires API key)'
    )

    parser.add_argument(
        '--config',
        metavar='FILE',
        help='Path to configuration file (JSON)'
    )

    parser.add_argument(
        '--max-size',
        type=int,
        default=DEFAULT_MAX_FILE_SIZE_MB,
        metavar='MB',
        help=f'Maximum file size in MB (default: {DEFAULT_MAX_FILE_SIZE_MB})'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )

    return parser.parse_args(args)


def main(args: Optional[list[str]] = None) -> int:
    """
    Main entry point for CLI.

    Args:
        args: Command-line arguments (uses sys.argv if None).

    Returns:
        Exit code (0 for success, non-zero for error).
    """
    parsed = parse_args(args)
    setup_logging(verbose=parsed.verbose, debug=parsed.debug)

    logger = logging.getLogger(__name__)

    # Load or create config
    if parsed.config:
        config = AnalyzerConfig.from_file(Path(parsed.config))
    else:
        config = AnalyzerConfig()

    # Override max file size if specified
    config.max_file_size_bytes = parsed.max_size * 1024 * 1024

    try:
        with PDFAnalyzer(parsed.pdf_file, config=config) as analyzer:
            print(f"Analyzing PDF: {parsed.pdf_file}")
            results = analyzer.analyze(check_vt=parsed.virustotal)

            # Print summary
            formatter = OutputFormatter(results)
            formatter.print_summary()

            # Save to file if requested
            if parsed.output:
                save_results(results, parsed.output)
                print(f"\nResults saved to: {parsed.output}")

            # Verbose mode - print detailed JSON
            if parsed.verbose:
                print_detailed_results(results)

        return 0

    except FileNotFoundError as e:
        logger.error(f"File not found: {e}")
        return 1

    except FileTooLargeError as e:
        logger.error(str(e))
        logger.error(f"Use --max-size to increase the limit if needed")
        return 1

    except KeyboardInterrupt:
        logger.info("\nAnalysis interrupted by user")
        return 130

    except Exception as e:
        logger.exception(f"Unexpected error: {e}")
        return 1


if __name__ == '__main__':
    sys.exit(main())
