from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
import os
import subprocess
import re
from database import init_db, get_db
from werkzeug.utils import secure_filename
from prometheus_flask_exporter import PrometheusMetrics

app = Flask(__name__)
metrics = PrometheusMetrics(app)

# ─────────────────────────────────────────────
# FIXED: Hardcoded secret
# ─────────────────────────────────────────────
app.secret_key = os.getenv("SECRET_KEY", "fallback_dev_key")

# (Leaving other secrets as-is intentionally for lab)
DB_PASSWORD     = "admin123"
API_SECRET      = "sk-prod-9a8b7c6d5e4f3g2h1i"
AWS_ACCESS_KEY  = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET      = "jwt_secret_hardcoded_never_do_this"

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Still vulnerable (as per lab scope)
app.config['DEBUG'] = True

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email    = request.form['email']
        conn = get_db()
        try:
            conn.execute(
                "INSERT INTO users (username, password, email, balance) VALUES (?, ?, ?, ?)",
                (username, password, email, 1000.0)
            )
            conn.commit()
            return redirect(url_for('login'))
        except Exception as e:
            error = "Username already exists."
        finally:
            conn.close()
    return render_template('register.html', error=error)

# ─────────────────────────────────────────────
# FIXED: SQL Injection (login)
# ─────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        try:
            query = "SELECT * FROM users WHERE username=? AND password=?"
            user = conn.execute(query, (username, password)).fetchone()

            if user:
                session['user_id']  = user['id']
                session['username'] = user['username']
                session['role']     = user['role']
                return redirect(url_for('dashboard'))
            else:
                error = "Invalid credentials."
        except Exception as e:
            error = f"Error: {e}"
        finally:
            conn.close()
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
    txns = conn.execute('''
        SELECT t.*,  
               s.username as sender_name,  
               r.username as receiver_name
        FROM transactions t
        LEFT JOIN users s ON t.sender_id = s.id
        LEFT JOIN users r ON t.receiver_id = r.id
        WHERE t.sender_id=? OR t.receiver_id=?
        ORDER BY t.timestamp DESC LIMIT 5
    ''', (session['user_id'], session['user_id'])).fetchall()
    conn.close()
    return render_template('dashboard.html', user=user, transactions=txns)

# (UNCHANGED PARTS OMITTED FOR BREVITY — SAME AS YOUR ORIGINAL)

# ─────────────────────────────────────────────
# FIXED: Command Injection (ping)
# ─────────────────────────────────────────────
@app.route('/ping')
def ping():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    host   = request.args.get('host', '')
    output = ''

    if host:
        # Input validation
        if not re.match(r'^[a-zA-Z0-9.-]+$', host):
            return "Invalid host"

        # Safe execution
        result = subprocess.run(
            ["ping", "-c", "2", host],
            capture_output=True,
            text=True
        )
        output = result.stdout

    return render_template('ping.html', host=host, output=output)

# ─────────────────────────────────────────────
# INIT + RUN
# ─────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
