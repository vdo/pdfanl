# pdfanl - PDF Analysis Tool

A comprehensive Python tool for analyzing PDF files using PyMuPDF (fitz) with advanced malware detection capabilities. This tool extracts detailed information about PDF documents and performs security analysis based on malware research methodologies.

## Features

### Core Analysis
- **PDF Version & Metadata**: Extract PDF version, creation/modification dates, author, title, etc.
- **Links Analysis**: Identify and categorize external and internal links
- **JavaScript Detection**: Find and extract JavaScript code embedded in PDFs
- **Resource Analysis**: Analyze images, fonts, and other embedded resources
- **Security Information**: Check encryption status and document permissions
- **Form Fields**: Identify and analyze form fields and their properties
- **Annotations**: Extract all annotations with their properties
- **Page Statistics**: Detailed information about each page

### 🔒 Advanced Security Analysis
- **Header Validation**: Detect suspicious PDF headers and anomalies
- **Suspicious Keyword Detection**: Scan for malicious indicators like `/JS`, `/JavaScript`, `/AA`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/JBIG2Decode`, `/RichMedia`, `/XFA`
- **Automatic Malware Risk Assessment**: Calculate risk scores based on dangerous combinations
- **CVE Detection**: Identify potential vulnerabilities (e.g., JBIG2Decode CVE-2009-0658)
- **Auto-Action Detection**: Flag PDFs with automatic JavaScript execution
- **VirusTotal Integration**: Check file hash against 70+ antivirus engines
- **Threat Recommendations**: Actionable security advice based on risk level

## Installation

1. Install the required package:
```bash
pip install -r requirements.txt
```

Or install dependencies separately:
```bash
pip install PyMuPDF>=1.23.0
pip install requests>=2.31.0
```

## Configuration

### VirusTotal API (Optional)

To enable VirusTotal malware scanning, you need a free API key:

1. Sign up at [VirusTotal](https://www.virustotal.com/)
2. Get your API key from your account settings
3. Set the environment variable:

```bash
# Linux/Mac
export VIRUSTOTAL_API_KEY="your-api-key-here"

# Windows (PowerShell)
$env:VIRUSTOTAL_API_KEY="your-api-key-here"

# Windows (CMD)
set VIRUSTOTAL_API_KEY=your-api-key-here
```

**Note**: Free API has rate limits (4 requests/minute). The tool works without VirusTotal integration.

## Usage

### Basic Usage
```bash
python pdfanl.py path/to/your/document.pdf
```

### Save Results to JSON
```bash
python pdfanl.py path/to/your/document.pdf -o analysis_results.json
```

### With VirusTotal Scanning
```bash
python pdfanl.py path/to/your/document.pdf --virustotal
```

### Verbose Output
```bash
python pdfanl.py path/to/your/document.pdf -v
```

### Full Analysis (All Options)
```bash
python pdfanl.py path/to/your/document.pdf --virustotal -o results.json -v
```

## Output

The tool provides:

1. **Console Summary**: A formatted summary of key findings
2. **JSON Export** (optional): Complete analysis results in JSON format

### Example Console Output
```
============================================================
PDF ANALYSIS SUMMARY
============================================================

📄 File Information:
   Name: sample.pdf
   Size: 1,234,567 bytes
   Pages: 15
   Encrypted: False

📋 PDF Version: 1.7
   Has Outline: True
   Outline Items: 8

🔗 Links: 3 found
   External: 3
   Internal: 0

   📌 External Links Found:
      1. Page 1: https://example.com/contact
      2. Page 3: mailto:info@example.com
      3. Page 5: https://example.com/support

⚡ JavaScript: 2 scripts found
   1. page_script on page 1
   2. annotation_script on page 3

🎨 Resources:
   Images: 25
   Fonts: 6

📝 Form Fields: 8 found
   text: 5
   button: 3

📋 Header Analysis:
   Valid Header: ✓
   Header: %PDF-1.7
   At Start: ✓

🔍 Suspicious Keywords:
   /JavaScript: 2
   /OpenAction: 1
   /AcroForm: 1

🛡️  VirusTotal Analysis:
   ✅ Detections: 0/73 engines (clean)
   SHA256: a1b2c3d4e5f6...

� MALWARE RISK ASSESSMENT:
   Risk Level: HIGH
   Risk Score: 90/100

   Risk Factors Detected:
      � JavaScript present (+50 points)
         PDF contains JavaScript (0 /JS, 2 /JavaScript)
      � JavaScript + Auto-action combination (+40 points)
         Dangerous combination: JavaScript with automatic execution (/AA: 0, /OpenAction: 1)

   Recommendations:
      • ⚠️ DO NOT OPEN this PDF in a standard viewer
      • Use a sandboxed environment for analysis
      • Scan with antivirus/malware detection tools
      • High likelihood of automated malware execution

🔒 Security:
   Encrypted: False
   Print: ✓
   Copy: ✓
   Modify: ✓
============================================================
```

## JSON Output Structure

The JSON output contains the following sections:

```json
{
  "file_info": {
    "filename": "document.pdf",
    "file_size": 1234567,
    "page_count": 15,
    "is_pdf": true,
    "is_encrypted": false
  },
  "metadata": {
    "title": "Document Title",
    "author": "Author Name",
    "subject": "Document Subject",
    "keywords": "keyword1, keyword2",
    "creator": "Application Name",
    "producer": "PDF Producer",
    "creation_date": "D:20240101000000+00'00'",
    "modification_date": "D:20240101000000+00'00'"
  },
  "version_info": {
    "pdf_version": "1.7",
    "has_outline": true,
    "outline_items": 8
  },
  "security": {
    "is_encrypted": false,
    "permissions": {
      "print": true,
      "copy": true,
      "annotate": true,
      "modify": true,
      "fill_forms": true
    }
  },
  "pages": {
    "total_pages": 15,
    "page_details": [...]
  },
  "links": [...],
  "annotations": [...],
  "javascript": [...],
  "resources": {
    "images": [...],
    "fonts": [...],
    "other": []
  },
  "form_fields": [...]
}
```

## Security Analysis

The tool implements comprehensive malware detection based on malware analysis research:

### Risk Scoring System

The analyzer calculates a risk score (0-100) based on the presence of suspicious indicators:

- **JavaScript (/JS, /JavaScript)**: +50 points - HIGH RISK: Scripts can exploit vulnerabilities
- **Auto-Actions without JavaScript (/AA, /OpenAction)**: +20 points - Low risk when alone
- **JS + Auto-Action Combination**: +40 points (additional) - **HIGH RISK**: Dangerous combination common in malware
- **Launch Actions (/Launch)**: +35 points - Can execute external programs
- **Embedded Files (/EmbeddedFile)**: +20 points - May contain malicious payloads
- **JBIG2 Compression (/JBIG2Decode)**: +25 points - Known CVE-2009-0658 vulnerability
- **RichMedia/Flash (/RichMedia)**: +20 points - Legacy Flash exploits
- **XFA Forms (/XFA)**: +15 points - Complex form structure
- **Object Streams (/ObjStm)**: +10 points - Can be used for obfuscation
- **Single-page PDFs with JavaScript**: +15 points - Common malware pattern
- **Header anomalies**: +10-20 points - Evasion techniques

### Risk Levels

- **HIGH** (75-100): Do not open, highly suspicious - use sandboxed environment
- **MEDIUM** (41-74): Exercise caution, disable JavaScript in PDF reader
- **LOW** (1-40): Minor concerns, generally safe
- **SAFE** (0): No malicious indicators detected

### Key Indicators

The combination of `/JavaScript` or `/AA` with `/OpenAction` is extremely suspicious. Almost all malicious PDFs exhibit:

1. JavaScript code for exploitation
2. Automatic actions to trigger without user interaction
3. Often single-page documents to reduce file size

## VirusTotal Integration

When enabled with `--virustotal` flag, the tool:

1. **Calculates file hashes** (MD5, SHA1, SHA256)
2. **Queries VirusTotal API** using SHA256 hash
3. **Retrieves scan results** from 70+ antivirus engines
4. **Displays detection statistics**:
   - Malicious detections
   - Suspicious flags
   - Threat classification
   - Individual engine results
5. **Integrates with risk scoring**: VT detections add up to 50 points to risk score

### How VT Risk Scoring Works

- **>30% detection rate**: +50 points (CRITICAL)
- **10-30% detection rate**: +30-50 points (HIGH)
- **<10% detection rate**: Proportional points (MEDIUM)

### Privacy & Security

- **Hash-based lookup**: Only file hash is sent to VirusTotal, not the actual file
- **No file upload**: Tool performs read-only lookups
- **Rate limiting**: Free API limited to 4 requests/minute
- **Optional feature**: Only runs when `--virustotal` flag is used

## Requirements

- Python 3.7+
- PyMuPDF 1.23.0 or higher
- requests 2.31.0 or higher (for VirusTotal integration)

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Feel free to:
- Report bugs or issues
- Suggest new features or improvements
- Submit pull requests

## Acknowledgments

- Built with [PyMuPDF](https://pymupdf.readthedocs.io/)
- Malware detection techniques from [Filipi Pires' MalwareAnalysis-in-PDF](https://github.com/filipi86/MalwareAnalysis-in-PDF)
- VirusTotal API integration for malware detection
