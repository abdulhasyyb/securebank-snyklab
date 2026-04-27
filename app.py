from flask import Flask, request, render_template, redirect, url_for, session, jsonify
import sqlite3
import os
import subprocess
from database import init_db, get_db
from werkzeug.utils import secure_filename
from prometheus_flask_exporter import PrometheusMetrics

app = Flask(__name__)
metrics = PrometheusMetrics(app)
# ─────────────────────────────────────────────
# VULNERABILITY 1: Hardcoded secrets
# Gitleaks will detect these
# ─────────────────────────────────────────────
app.secret_key = "super_secret_key_12345"
DB_PASSWORD     = "admin123"
API_SECRET      = "sk-prod-9a8b7c6d5e4f3g2h1i"
AWS_ACCESS_KEY  = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY  = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
JWT_SECRET      = "jwt_secret_hardcoded_never_do_this"

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# VULNERABILITY 2: Debug mode on in production
app.config['DEBUG'] = True

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ─────────────────────────────────────────────
# HOME
# ─────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('home.html')

# ─────────────────────────────────────────────
# REGISTER
# ─────────────────────────────────────────────
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email    = request.form['email']
        conn = get_db()
        try:
            # Passwords stored as plaintext — vulnerability
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
# LOGIN — VULNERABILITY: SQL Injection
# ─────────────────────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        try:
            # VULNERABLE: Raw string formatting — SQL Injection possible
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            user = conn.execute(query).fetchone()
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

# ─────────────────────────────────────────────
# LOGOUT
# ─────────────────────────────────────────────
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ─────────────────────────────────────────────
# DASHBOARD
# ─────────────────────────────────────────────
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

# ─────────────────────────────────────────────
# TRANSFER
# ─────────────────────────────────────────────
@app.route('/transfer', methods=['GET', 'POST'])
def transfer():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = None
    error   = None
    conn    = get_db()
    users   = conn.execute("SELECT id, username FROM users WHERE id != ?", (session['user_id'],)).fetchall()

    if request.method == 'POST':
        receiver_id = request.form['receiver_id']
        amount      = float(request.form['amount'])
        description = request.form['description']
        sender      = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()

        if amount <= 0:
            error = "Amount must be greater than zero."
        elif sender['balance'] < amount:
            error = "Insufficient balance."
        else:
            conn.execute("UPDATE users SET balance=balance-? WHERE id=?", (amount, session['user_id']))
            conn.execute("UPDATE users SET balance=balance+? WHERE id=?", (amount, receiver_id))
            conn.execute(
                "INSERT INTO transactions (sender_id, receiver_id, amount, description) VALUES (?,?,?,?)",
                (session['user_id'], receiver_id, amount, description)
            )
            conn.commit()
            message = f"Successfully transferred Rs. {amount:.2f}"
    conn.close()
    return render_template('transfer.html', users=users, message=message, error=error)

# ─────────────────────────────────────────────
# TRANSACTIONS
# ─────────────────────────────────────────────
@app.route('/transactions')
def transactions():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db()
    txns = conn.execute('''
        SELECT t.*,
               s.username as sender_name,
               r.username as receiver_name
        FROM transactions t
        LEFT JOIN users s ON t.sender_id = s.id
        LEFT JOIN users r ON t.receiver_id = r.id
        WHERE t.sender_id=? OR t.receiver_id=?
        ORDER BY t.timestamp DESC
    ''', (session['user_id'], session['user_id'])).fetchall()
    conn.close()
    return render_template('transactions.html', transactions=txns)

# ─────────────────────────────────────────────
# PROFILE — VULNERABILITY: IDOR + Stored XSS
# ─────────────────────────────────────────────
@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = request.args.get('id', session['user_id'])
    conn    = get_db()
    user    = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    msgs    = conn.execute("SELECT * FROM messages WHERE user_id=?", (user_id,)).fetchall()
    conn.close()
    return render_template('profile.html', user=user, messages=msgs)

@app.route('/profile/update', methods=['POST'])
def update_profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    full_name = request.form['full_name']
    phone     = request.form['phone']
    address   = request.form['address']
    conn = get_db()
    conn.execute(
        "UPDATE users SET full_name=?, phone=?, address=? WHERE id=?",
        (full_name, phone, address, session['user_id'])
    )
    conn.commit()
    conn.close()
    return redirect(url_for('profile'))

# ─────────────────────────────────────────────
# MESSAGES — VULNERABILITY: Stored XSS
# ─────────────────────────────────────────────
@app.route('/message', methods=['POST'])
def message():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    content = request.form['content']
    conn    = get_db()
    conn.execute(
        "INSERT INTO messages (user_id, content) VALUES (?, ?)",
        (session['user_id'], content)
    )
    conn.commit()
    conn.close()
    return redirect(url_for('profile'))

# ─────────────────────────────────────────────
# SEARCH — VULNERABILITY: Reflected XSS + SQL Injection
# ─────────────────────────────────────────────
@app.route('/search')
def search():
    query   = request.args.get('q', '')
    results = []
    if query:
        conn = get_db()
        try:
            # VULNERABLE: SQL Injection in search
            sql     = f"SELECT id, username, email, full_name FROM users WHERE username LIKE '%{query}%' OR full_name LIKE '%{query}%'"
            results = conn.execute(sql).fetchall()
        except Exception as e:
            results = []
        finally:
            conn.close()
    return render_template('search.html', query=query, results=results)

# ─────────────────────────────────────────────
# FILE UPLOAD — VULNERABILITY: Unrestricted Upload
# ─────────────────────────────────────────────
@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    message = None
    error   = None
    if request.method == 'POST':
        if 'file' not in request.files:
            error = "No file selected."
        else:
            file = request.files['file']
            if file.filename == '':
                error = "No file selected."
            else:
                # VULNERABLE: No file type validation
                filename = file.filename
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(filepath)
                message = f"File '{filename}' uploaded successfully."
    return render_template('upload.html', message=message, error=error)

# ─────────────────────────────────────────────
# PING — VULNERABILITY: Command Injection
# ─────────────────────────────────────────────
@app.route('/ping')
def ping():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    host   = request.args.get('host', '')
    output = ''
    if host:
        # VULNERABLE: Direct OS command execution with user input
        output = os.popen(f"ping -c 2 {host}").read()
    return render_template('ping.html', host=host, output=output)

# ─────────────────────────────────────────────
# ADMIN — VULNERABILITY: Broken Access Control
# ─────────────────────────────────────────────
@app.route('/admin')
def admin():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    # VULNERABLE: Only checks if logged in, not if user is admin
    conn  = get_db()
    users = conn.execute("SELECT * FROM users").fetchall()
    txns  = conn.execute('''
        SELECT t.*, s.username as sender_name, r.username as receiver_name
        FROM transactions t
        LEFT JOIN users s ON t.sender_id = s.id
        LEFT JOIN users r ON t.receiver_id = r.id
        ORDER BY t.timestamp DESC
    ''').fetchall()
    conn.close()
    return render_template('admin.html', users=users, transactions=txns)

# ─────────────────────────────────────────────
# API — VULNERABILITY: No Authentication
# ─────────────────────────────────────────────
@app.route('/api/users')
def api_users():
    conn  = get_db()
    users = conn.execute("SELECT id, username, email, balance, role, full_name, phone, address FROM users").fetchall()
    conn.close()
    return jsonify([dict(u) for u in users])

@app.route('/api/transactions')
def api_transactions():
    conn  = get_db()
    txns  = conn.execute("SELECT * FROM transactions").fetchall()
    conn.close()
    return jsonify([dict(t) for t in txns])

@app.route('/api/user/<int:user_id>')
def api_user(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    conn.close()
    if user:
        return jsonify(dict(user))
    return jsonify({'error': 'User not found'}), 404

# ─────────────────────────────────────────────
# INIT + RUN
# ─────────────────────────────────────────────
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
