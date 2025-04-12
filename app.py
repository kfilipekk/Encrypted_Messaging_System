from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
import base64
import sqlite3
import hashlib
import jwt
from datetime import datetime, timedelta, timezone
import os
from werkzeug.utils import secure_filename 
import logging

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)
logging.basicConfig(level=logging.DEBUG)

SECRET_KEY = os.environ.get('SECRET_KEY', os.urandom(32))
AES_KEY = os.environ.get('AES_KEY', os.urandom(16))
DB_FILE = 'messages.db'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'webm', 'mp3', 'wav'}

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        status TEXT DEFAULT 'offline'
    )''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        iv TEXT NOT NULL,
        ciphertext TEXT,
        media_url TEXT,
        sender TEXT,
        timestamp TEXT NOT NULL,
        edited INTEGER DEFAULT 0,
        read INTEGER DEFAULT 0,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')
    
    c.execute("PRAGMA table_info(messages)")
    columns = [col[1] for col in c.fetchall()]
    if 'edited' not in columns:
        c.execute('ALTER TABLE messages ADD COLUMN edited INTEGER DEFAULT 0')
    if 'read' not in columns:
        c.execute('ALTER TABLE messages ADD COLUMN read INTEGER DEFAULT 0')
    
    conn.commit()
    conn.close()

def encrypt_message(message):
    cipher = AES.new(AES_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return {'iv': iv, 'ciphertext': ct}

def decrypt_message(iv, ciphertext):
    if not ciphertext:
        return ""
    try:
        iv = base64.b64decode(iv)
        ct = base64.b64decode(ciphertext)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, iv=iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size).decode('utf-8')
        return pt
    except Exception as e:
        app.logger.error(f"Decryption error: {e}")
        return ""

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def verify_token():
    auth_header = request.headers.get('Authorisation')
    if not auth_header or not auth_header.startswith('Bearer '):
        return None
    token = auth_header.split(' ')[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return payload['user_id']
    except jwt.InvalidTokenError as e:
        app.logger.error(f"Token verification failed: {e}")
        return None

@app.route('/')
def serve_index():
    return send_from_directory('static', 'index.html')

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash) VALUES (?, ?)', (username, password_hash))
        conn.commit()
        user_id = c.lastrowid
        token = jwt.encode({
            'user_id': user_id,
            'exp': datetime.now(timezone.utc) + timedelta(hours=24)
        }, SECRET_KEY, algorithm='HS256')
        return jsonify({'token': token})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username already exists'}), 400
    finally:
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': 'Username and password required'}), 400
    
    username = data['username']
    password = data['password']
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('SELECT id FROM users WHERE username = ? AND password_hash = ?', (username, password_hash))
        user = c.fetchone()
        if user:
            c.execute('UPDATE users SET status = ? WHERE id = ?', ('online', user[0]))
            conn.commit()
            token = jwt.encode({
                'user_id': user[0],
                'exp': datetime.now(timezone.utc) + timedelta(hours=24)
            }, SECRET_KEY, algorithm='HS256')
            return jsonify({'token': token})
        return jsonify({'error': 'Invalid credentials'}), 401
    finally:
        conn.close()

@app.route('/logout', methods=['POST'])
def logout():
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorised'}), 401
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('UPDATE users SET status = ? WHERE id = ?', ('offline', user_id))
    conn.commit()
    conn.close()
    return jsonify({'status': 'Logged out'})

@app.route('/send', methods=['POST'])
def send_message():
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorised'}), 401
    
    data = request.get_json()
    if not data or 'message' not in data or 'sender' not in data:
        return jsonify({'error': 'Message and sender required'}), 400
    
    message = data['message']
    sender = data['sender']
    encrypted = encrypt_message(message)
    timestamp = datetime.now(timezone.utc).isoformat()
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO messages (user_id, iv, ciphertext, sender, timestamp) VALUES (?, ?, ?, ?, ?)',
                 (user_id, encrypted['iv'], encrypted['ciphertext'], sender, timestamp))
        conn.commit()
        return jsonify({'status': 'Message sent'})
    finally:
        conn.close()

@app.route('/upload', methods=['POST'])
def upload_file():
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorised'}), 401
    
    if 'media' not in request.files or 'sender' not in request.form:
        return jsonify({'error': 'Media file and sender required'}), 400
    
    file = request.files['media']
    sender = request.form['sender']
    
    if file and allowed_file(file.filename):
        filename = secure_filename(f"{datetime.now(timezone.utc).timestamp()}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        timestamp = datetime.now(timezone.utc).isoformat()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute('INSERT INTO messages (user_id, iv, media_url, sender, timestamp) VALUES (?, ?, ?, ?, ?)',
                     (user_id, base64.b64encode(os.urandom(16)).decode('utf-8'), f'/{UPLOAD_FOLDER}/{filename}', sender, timestamp))
            conn.commit()
            return jsonify({'status': 'Media uploaded'})
        finally:
            conn.close()
    return jsonify({'error': 'Invalid file type'}), 400

@app.route('/edit/<int:message_id>', methods=['PUT'])
def edit_message(message_id):
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorised'}), 401
    
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({'error': 'Message required'}), 400
    
    message = data['message']
    encrypted = encrypt_message(message)
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('UPDATE messages SET ciphertext = ?, iv = ?, edited = 1 WHERE id = ? AND user_id = ?',
                 (encrypted['ciphertext'], encrypted['iv'], message_id, user_id))
        if c.rowcount == 0:
            return jsonify({'error': 'Message not found or unauthorised'}), 403
        conn.commit()
        return jsonify({'status': 'Message edited'})
    finally:
        conn.close()

@app.route('/mark_read/<int:message_id>', methods=['POST'])
def mark_read(message_id):
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorised'}), 401
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('UPDATE messages SET read = 1 WHERE id = ? AND user_id = ?', (message_id, user_id))
        conn.commit()
        return jsonify({'status': 'Message marked as read'})
    finally:
        conn.close()

@app.route('/messages', methods=['GET'])
def get_messages():
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorised'}), 401
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('SELECT id, iv, ciphertext, media_url, sender, timestamp, edited, read FROM messages WHERE user_id = ?', (user_id,))
        rows = c.fetchall()
        messages = [{
            'id': row[0],
            'text': decrypt_message(row[1], row[2]) if row[2] else None,
            'mediaUrl': row[3],
            'sender': row[4],
            'timestamp': row[5],
            'edited': bool(row[6]),
            'read': bool(row[7])
        } for row in rows]
        return jsonify({'messages': messages})
    finally:
        conn.close()

@app.route('/delete/<int:message_id>', methods=['DELETE'])
def delete_message(message_id):
    user_id = verify_token()
    if not user_id:
        return jsonify({'error': 'Unauthorised'}), 401

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('SELECT media_url, user_id FROM messages WHERE id = ?', (message_id,))
        message = c.fetchone()
        if not message or message[1] != user_id:
            return jsonify({'error': 'Message not found or unauthorised'}), 403

        if message[0]:
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], message[0].lstrip('/uploads/')))
            except OSError:
                pass

        c.execute('DELETE FROM messages WHERE id = ? AND user_id = ?', (message_id, user_id))
        conn.commit()
        return jsonify({'status': 'Message deleted'})
    finally:
        conn.close()

@app.route(f'/{UPLOAD_FOLDER}/<filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)