import sqlite3
import os

DB_PATH = 'securebank.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            email TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 0.0,
            full_name TEXT,
            phone TEXT,
            address TEXT
        )
    ''')

    # Transactions table
    c.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER,
            receiver_id INTEGER,
            amount REAL,
            description TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Messages table (for stored XSS)
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            content TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Seed users (passwords stored as plaintext — intentional vulnerability)
    users = [
        ('admin', 'admin123', 'admin@securebank.com', 'admin', 50000.00, 'Admin User', '03001234567', '123 Admin St'),
        ('john', 'password123', 'john@email.com', 'user', 15000.00, 'John Doe', '03009876543', '456 Main St'),
        ('alice', 'alice2024', 'alice@email.com', 'user', 8500.00, 'Alice Smith', '03001112233', '789 Oak Ave'),
        ('bob', 'bob1234', 'bob@email.com', 'user', 22000.00, 'Bob Johnson', '03004445566', '321 Pine Rd'),
    ]

    for user in users:
        try:
            c.execute('''
                INSERT INTO users (username, password, email, role, balance, full_name, phone, address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', user)
        except:
            pass

    # Seed transactions
    transactions = [
        (2, 3, 500.00, 'Rent payment'),
        (3, 2, 200.00, 'Dinner split'),
        (4, 2, 1000.00, 'Loan repayment'),
        (2, 4, 750.00, 'Freelance payment'),
    ]

    for txn in transactions:
        try:
            c.execute('''
                INSERT INTO transactions (sender_id, receiver_id, amount, description)
                VALUES (?, ?, ?, ?)
            ''', txn)
        except:
            pass

    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn
