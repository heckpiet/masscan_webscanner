# masscan_webscanner

Tool to perform parallel Masscan scans and take website screenshots.

## Requirements

- Python 3.8+
- masscan
- Chromium + chromedriver
- `pip install mechanicalsoup selenium beautifulsoup4 urllib3`

## Usage

```bash
python3 Masscan_Webscanner.py --ranges ranges.txt --ports 80,443
