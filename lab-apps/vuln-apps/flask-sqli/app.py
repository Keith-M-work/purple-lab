import os
from flask import Flask, request, render_template_string
import sqlite3

app = Flask(__name__)

@app.route('/')
def index():
    return '''
    <h1>Vulnerable SQL Injection Demo</h1>
    <form action="/search" method="get">
        <input name="q" placeholder="Search users...">
        <button type="submit">Search</button>
    </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('q', '')
    # VULNERABLE: Direct string concatenation
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    
    conn = sqlite3.connect(':memory:')
    conn.execute('CREATE TABLE users (id INT, name TEXT)')
    conn.execute("INSERT INTO users VALUES (1, 'admin')")
    conn.execute("INSERT INTO users VALUES (2, 'user')")
    
    try:
        results = conn.execute(sql).fetchall()
        return f"<h2>Results for '{query}':</h2><pre>{results}</pre>"
    except Exception as e:
        return f"<h2>Error:</h2><pre>{e}</pre>"

if __name__ == '__main__':
    # Safe defaults: localhost only, debugger off. The SQLi/XSS above are the intentional lesson;
    # an exposed Werkzeug debugger is not (it is an interactive Python console = RCE).
    # Docker sets HOST=0.0.0.0 inside the container; publish it with -p 127.0.0.1:5000:5000.
    app.run(host=os.environ.get('HOST', '127.0.0.1'), port=5000,
            debug=os.environ.get('FLASK_DEBUG') == '1')
