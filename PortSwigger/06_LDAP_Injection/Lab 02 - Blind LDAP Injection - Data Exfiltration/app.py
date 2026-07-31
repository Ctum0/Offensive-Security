from flask import Flask, request, render_template_string
from ldap3 import Server, Connection, ALL

app = Flask(__name__)

# CONFIGURATION
LDAP_HOST = 'ldap-target' 
LDAP_USER = 'cn=admin,dc=cmd,dc=com'
LDAP_PASS = 'admin'
BASE_DN = 'ou=people,dc=cmd,dc=com'

@app.route('/', methods=['GET', 'POST'])
def login():
    status = "Enter Credentials"
    
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        
        # VULNERABLE FILTER
        search_filter = f"(&(cn={user})(userPassword={pw}))"
        
        try:
            server = Server(LDAP_HOST, get_info=ALL)
            conn = Connection(server, LDAP_USER, LDAP_PASS, auto_bind=True)
            conn.search(BASE_DN, search_filter, attributes=['cn'])
            
            # THE ORACLE LOGIC: 
            # We no longer display the data. We only return a Boolean status.
            if conn.entries:
                status = "SUCCESS"
            else:
                status = "FAILURE"
        except Exception as e:
            status = "SYSTEM ERROR"

    return render_template_string('''
        <html>
        <style>body{font-family:monospace; background:#111; color:#0f0; padding:50px;}</style>
        <h1>COMMAND CENTER - SECURE AUTH</h1>
        <form method="post">
            User: <input type="text" name="username"><br><br>
            Pass: <input type="password" name="password"><br><br>
            <input type="submit" value="LOGIN">
        </form>
        <h2>STATUS: {{ s }}</h2>
        </html>
    ''', s=status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
