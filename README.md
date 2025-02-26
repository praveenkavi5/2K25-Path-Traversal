# Path Traversal Vulnerability Scanner (2025 Edition)

A lightweight, Python-based tool designed to test web applications for path traversal vulnerabilities. This script sends crafted payloads to a target URL, analyzes responses, and identifies potential security weaknesses that could allow unauthorized file access.

## Features
- **Extensive Payloads**: Includes a default wordlist with common traversal patterns (e.g., `../`, `%2e%2e%2f`) and supports custom wordlists.
- **Double-Encoding Support**: Automatically tests both raw and double-encoded payloads to bypass filters.
- **Randomized User-Agents**: Mimics legitimate traffic with a variety of browser signatures.
- **Response Analysis**: Detects potential vulnerabilities based on status codes, content length, and keyword matching (e.g., `root`, `passwd`, `config`).
- **Customizable**: Easily configure target URL, parameter, and wordlist via user input.

## Usage
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/path-traversal-scanner.git
   cd path-traversal-scanner
   ```
2. Install dependencies:
   ```bash
   pip install requests
   ```
3. Run the script:
   ```bash
   python path_traversal_scanner.py
   ```
4. Follow the prompts to enter the target URL, parameter, and optional custom wordlist path.

### Example
```plaintext
Enter the base URL: http://example.com/download
Enter the parameter to test: file
Enter custom wordlist file path (leave blank for default): 
```

## Sample Output
```
[*] Starting Path Traversal Test...
[*] Target: http://example.com/download
[*] Parameter: file
[*] Total payloads: 60
-
[>] http://example.com/download?file=../ | Status: 200 | Length: 123 | <!doctype html><html...
[>] http://example.com/download?file=%2e%2e%2f | Status: 403 | Length: 45 | Access denied
-
[!] Potential Vulnerabilities Found:
  - URL: http://example.com/download?file=../../etc/passwd
    Status: 200, Length: 512, Snippet: root:x:0:0:root...
```

## Requirements
- Python 3.x
- `requests` library (`pip install requests`)

## Warning
This tool is for **educational purposes only**. Use it only on systems you own or have explicit permission to test. Unauthorized scanning of systems is illegal and unethical.

## Contributing
Feel free to submit issues or pull requests to enhance functionality, add payloads, or improve detection logic.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
