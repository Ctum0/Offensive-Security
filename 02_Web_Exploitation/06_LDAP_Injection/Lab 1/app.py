from flask import Flask, request, render_template_string
from ldap3 import Server, Connection, ALL

app = Flask(__name__)

# CONFIGURATION (Referencing our Docker Infrastructure)
# We use the container name 'ldap-target' defined in our docker run command
LDAP_HOST = 'ldap-target' 
LDAP_USER = 'cn=admin,dc=cmd,dc=com'
LDAP_PASS = 'admin'
BASE_DN = 'ou=people,dc=cmd,dc=com'

@app.route('/', methods=['GET', 'POST'])
def login():
    status = "Waiting for credentials..."
    
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        
        # --- THE VULNERABILITY ---
        # We are inserting your inputs directly into the filter string.
        # Filter Logic: (&(cn=USER)(userPassword=PASS))
        search_filter = f"(&(cn={user})(userPassword={pw}))"
        
        try:
            # Connect to the Docker LDAP Server
            server = Server(LDAP_HOST, get_info=ALL)
            conn = Connection(server, LDAP_USER, LDAP_PASS, auto_bind=True)
            
            # Execute the search
            # We fetch 'cn' (Common Name), 'mail', 'telephoneNumber', and 'description'
            conn.search(BASE_DN, search_filter, attributes=['cn', 'mail', 'telephoneNumber', 'description'])
            
            if conn.entries:
                # If we found a user, Login is Successful!
                user_data = conn.entries[0]
                status = f"LOGIN SUCCESS: Welcome, {user_data.cn}!"
                status += f" <br> Phone: {user_data.telephoneNumber}"
                status += f" <br> Desc: {user_data.description}"
            else:
                status = "LOGIN FAILED: Invalid credentials."
        except Exception as e:
            status = f"SYSTEM ERROR: {str(e)}"

    return render_template_string('''
        <html>
        <style>
            body{font-family:monospace; background:#000; color:#00ff00; padding:20px;}
            input{background:#333; color:#fff; border:1px solid #00ff00;}
            .box{border: 1px solid #00ff00; padding: 20px; width: 400px;}
        </style>
        <div class="box">
            <h1>COMMAND CENTER LOGIN</h1>
            <form method="post">
                User: <input type="text" name="username"><br><br>
                Pass: <input type="password" name="password"><br><br>
                <input type="submit" value="AUTHENTICATE">
            </form>
            <h3>STATUS: {{ s|safe }}</h3>
        </div>
        </html>
    ''', s=status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
