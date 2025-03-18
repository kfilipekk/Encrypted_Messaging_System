from flask import Flask, request, jsonify, render_template
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta
import os
import requests

app = Flask(__name__)

@app.route('/')
def serve_index():
    return app.send_static_file('index.html')

# Configuration
SECRET_KEY = os.urandom(32)  # Secure random key for JWT
AES_KEY = b'Sixteen byte key'  # WARNING: Use secure key management in production
DB_FILE = 'messages.db'

# Database Initialization
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        iv TEXT NOT NULL,
        ciphertext TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    conn.commit()
    conn.close()

init_db()

# Encryption/Decryption Functions
def encrypt_message(message):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return {'iv': iv, 'ciphertext': ct}

def decrypt_message(iv, ciphertext):
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ciphertext)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
    return pt

# Authentication Middleware
def verify_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.InvalidTokenError:
        return None

# Routes
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        user_id = c.lastrowid
        token = jwt.encode({'user_id': user_id, 'exp': datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY)
        return jsonify({'token': token})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
    user = c.fetchone()
    conn.close()
    
    if user:
        token = jwt.encode({'user_id': user[0], 'exp': datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY)
        return jsonify({'token': token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/send', methods=['POST'])
def send_message():
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    data = request.json
    message = data.get('message')
    if not message:
        return jsonify({'error': 'No message provided'}), 400
    
    encrypted = encrypt_message(message)
    timestamp = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO messages (user_id, iv, ciphertext, timestamp) VALUES (?, ?, ?, ?)', 
              (user_id, encrypted['iv'], encrypted['ciphertext'], timestamp))
    conn.commit()
    conn.close()
    return jsonify({'status': 'Message sent'})

@app.route('/messages', methods=['GET'])
def get_messages():
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT iv, ciphertext, timestamp FROM messages WHERE user_id = ?', (user_id,))
    rows = c.fetchall()
    conn.close()
    
    messages = [{'text': decrypt_message(row[0], row[1]), 'timestamp': row[2]} for row in rows]
    return jsonify({'messages': messages})

##Function to skip ngrok warning when making requests
def skip_ngrok_warning(url):
    headers = {"ngrok-skip-browser-warning": "true"}
    response = requests.get(url, headers=headers)
    return response.text

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)