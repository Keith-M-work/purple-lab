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
    app.run(host='0.0.0.0', port=5000, debug=True)
