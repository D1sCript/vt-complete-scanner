# VirusTotal Complete Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A powerful Python tool for SOC analysts to check files, hashes, URLs, and IP addresses using VirusTotal API.

## Features

- **File Scanning**: Calculate and check file hashes (MD5, SHA1, SHA256)
- **Hash Verification**: Verify single or batch hashes against VirusTotal
- **URL Checking**: Analyze URLs for malicious content
- **IP Reputation**: Check IP addresses for threats
- **Flexible Input**: Scan folders recursively or check lists from files
- **CSV Export**: Generate detailed reports with threat analysis
- **Color-coded Output**: Visual risk indicators (🔴 malicious, 🟡 suspicious, 🟢 clean)

## Prerequisites

- Python 3.8+
- VirusTotal API key (free tier available at https://www.virustotal.com)

## Installation

1. Clone the repository:

git clone https://github.com/D1sCript/vt-complete-scanner.git
cd vt-complete-scanner

2. Install dependencies:

pip install -r requirements.txt

3. Configure API key:
   - Open `vt_scanner.py`
   - Find line: `API_KEY = "INSERT_YOUR_API_KEY_HERE"`
   - Replace with your actual VirusTotal API key

## Usage

### Check IP addresses

python vt_scanner.py --check-ips ips.txt -o report.csv

### Check file hashes

python vt_scanner.py --check-hashes hashes.txt -o report.csv

### Check URLs

python vt_scanner.py --check-urls urls.txt -o report.csv

### Scan folder recursively

python vt_scanner.py --scan-folder ./suspicious_files/ -o report.csv

### Combined scan

python vt_scanner.py --scan-folder ./files/ --check-ips ips.txt --check-urls urls.txt -o full_report.csv

### View help

python vt_scanner.py --help

## Input File Format

**IPs file (ips.txt):**

8.8.8.8
1.1.1.1
185.220.101.1

**Hashes file (hashes.txt):**

5d41402abc4b2a76b9719d911017c592
098f6bcd4621d373cade4e832627b4f6

**URLs file (urls.txt):**
http://example.com
https://suspicious-site.xyz

undefined

## Risk Levels

- 🔴 **MALICIOUS** - 10+ detections (immediate action required)
- 🟡 **SUSPICIOUS** - 3-9 detections (further investigation needed)
- 🟢 **CLEAN** - 0-2 detections (likely safe)

## Use Cases

- **Incident Response**: Quickly check reputation of indicators during incidents
- **Threat Hunting**: Batch analyze indicators of compromise (IOCs)
- **Malware Analysis**: Verify file hashes against threat intelligence
- **Phishing Investigation**: Check URLs and domains from suspicious emails
- **Security Research**: Analyze infrastructure associated with threats

## Output

Results are exported to CSV with the following columns:
- Type (HASH, URL, IP)
- Value (indicator)
- Risk (MALICIOUS, SUSPICIOUS, CLEAN)
- Detections (number of AV vendors detecting threat)
- Total (total number of vendors analyzed)
- Category (threat classification)
- Last Analysis (when last analyzed)

## Disclaimer

These tools are provided for educational and professional security purposes only. Always ensure you have proper authorization before checking indicators or analyzing systems.

## License

MIT License - See [LICENSE](LICENSE) for details

## Author

**D1sCript**
- GitHub: [@D1sCript](https://github.com/D1sCript)
- Telegram: [@D1sCript](https://t.me/D1sCript)

## Support

For issues, suggestions, or questions, please open an issue on GitHub.

---

⭐ If you find this tool useful, please consider giving it a star!

