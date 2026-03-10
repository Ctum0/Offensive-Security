from flask import Flask, request, render_template_string
from ldap3 import Server, Connection, ALL

app = Flask(__name__)

LDAP_HOST = 'ldap-target' 
LDAP_USER = 'cn=admin,dc=cmd,dc=com'
LDAP_PASS = 'admin'
BASE_DN = 'ou=people,dc=cmd,dc=com'

@app.route('/', methods=['GET', 'POST'])
def login():
    status = "Waiting..."
    
    if request.method == 'POST':
        user = request.form.get('username')
        pw = request.form.get('password')
        
        # RESTRICTIVE FILTER
        # It forces the object to be a 'person'
        search_filter = f"(&(objectClass=person)(cn={user})(userPassword={pw}))"
        
        server = Server(LDAP_HOST, get_info=ALL)
        conn = Connection(server, LDAP_USER, LDAP_PASS, auto_bind=True)
        
        # We use a broader search to see if we can find ANY user
        conn.search(BASE_DN, search_filter, attributes=['cn'])
        
        if conn.entries:
            status = f"SUCCESS: {conn.entries[0].cn}"
        else:
            status = "FAILURE"

    return render_template_string('''
        <h1>LDAP LEVEL 3</h1>
        <form method="post">
            User: <input type="text" name="username"><br>
            Pass: <input type="password" name="password"><br>
            <input type="submit">
        </form>
        <h2>{{ s }}</h2>
    ''', s=status)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

