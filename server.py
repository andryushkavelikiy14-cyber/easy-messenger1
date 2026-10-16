import os
import re
import sqlite3
import secrets
import time
import base64
import random
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from flask import Flask, request, jsonify, send_from_directory, g
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS

# ==================================================
# КОНФИГ
# ==================================================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'uploads')
DATABASE = os.path.join(BASE_DIR, 'messenger.db')
INDEX_HTML = os.path.join(BASE_DIR, 'index.html')
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20 MB

ALLOWED_EXTENSIONS = {
    'png','jpg','jpeg','gif','webp','svg','bmp',
    'mp4','webm','mov','avi','mkv',
    'mp3','wav','ogg','m4a',
    'pdf','doc','docx','xls','xlsx','ppt','pptx','txt','rtf',
    'zip','rar','7z','tar','gz',
    'crx','apk','exe','json','xml','csv'
}

USERNAME_REGEX = re.compile(r'^[a-zA-Z0-9]+$')
USERNAME_MIN = 2
USERNAME_MAX = 20
PASSWORD_MIN = 4
PASSWORD_MAX = 8

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
CORS(app)

# Универсальный режим — работает и на Windows (threading), и на Linux/Render
# Если на Render с eventlet возникнут проблемы — оставь threading (он работает везде)
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading',
                    max_http_buffer_size=MAX_FILE_SIZE,
                    ping_timeout=60, ping_interval=25)

# Хранилища
active_sessions = {}   # token -> username
online_users = {}      # username -> sid


# ==================================================
# БАЗА ДАННЫХ
# ==================================================
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        avatar TEXT,
        created_at REAL
    )''')
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender TEXT NOT NULL,
        receiver TEXT NOT NULL,
        type TEXT NOT NULL,
        content TEXT,
        file_name TEXT,
        file_size INTEGER,
        duration REAL,
        timestamp REAL,
        read INTEGER DEFAULT 0
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_msg_pair ON messages(sender, receiver)')
    c.execute('CREATE INDEX IF NOT EXISTS idx_msg_time ON messages(timestamp)')
    conn.commit()
    conn.close()


def user_exists(username):
    return get_db().execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone() is not None


def create_user(username, password, avatar):
    db = get_db()
    db.execute('INSERT INTO users (username, password_hash, avatar, created_at) VALUES (?, ?, ?, ?)',
               (username, generate_password_hash(password), avatar, time.time()))
    db.commit()


def get_user(username):
    return get_db().execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()


def get_all_users(exclude=None):
    db = get_db()
    if exclude:
        rows = db.execute('SELECT username, avatar FROM users WHERE username != ? ORDER BY username',
                          (exclude,)).fetchall()
    else:
        rows = db.execute('SELECT username, avatar FROM users ORDER BY username').fetchall()
    return [dict(r) for r in rows]


def save_message(sender, receiver, msg_type, content, file_name=None, file_size=None, duration=None):
    db = get_db()
    ts = time.time()
    cur = db.execute('''INSERT INTO messages
        (sender, receiver, type, content, file_name, file_size, duration, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
        (sender, receiver, msg_type, content, file_name, file_size, duration, ts))
    db.commit()
    return {'id': cur.lastrowid, 'sender': sender, 'receiver': receiver,
            'type': msg_type, 'content': content, 'file_name': file_name,
            'file_size': file_size, 'duration': duration, 'timestamp': ts, 'read': 0}


def get_messages(u1, u2, limit=200):
    rows = get_db().execute('''SELECT * FROM messages
        WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?)
        ORDER BY timestamp ASC LIMIT ?''', (u1, u2, u2, u1, limit)).fetchall()
    return [dict(r) for r in rows]


def mark_as_read(sender, receiver):
    db = get_db()
    db.execute('UPDATE messages SET read = 1 WHERE sender = ? AND receiver = ? AND read = 0',
               (sender, receiver))
    db.commit()


# ==================================================
# ДЕКОРАТОРЫ / УТИЛИТЫ
# ==================================================
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        if not token or token not in active_sessions:
            return jsonify({'error': 'Не авторизован'}), 401
        g.current_user = active_sessions[token]
        return f(*args, **kwargs)
    return decorated


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def generate_default_avatar(letter):
    colors = ['#7f5af0', '#ef4565', '#4dabf7', '#2cb67d', '#ffd43b', '#ff922b']
    color = random.choice(colors)
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="100" height="100">
        <rect width="100" height="100" fill="{color}"/>
        <text x="50" y="68" font-size="50" text-anchor="middle" fill="#fff"
              font-family="Arial" font-weight="bold">{letter}</text>
    </svg>'''
    return 'data:image/svg+xml;base64,' + base64.b64encode(svg.encode()).decode()


# ==================================================
# HTTP API
# ==================================================
@app.route('/')
def index():
    with open(INDEX_HTML, 'r', encoding='utf-8') as f:
        return f.read()


@app.route('/api/check_username', methods=['POST'])
def check_username():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    if not username:
        return jsonify({'error': 'Введите логин'}), 400
    if not USERNAME_REGEX.match(username):
        return jsonify({'available': False, 'error': 'Только a-z, A-Z и 0-9'}), 400
    return jsonify({'available': not user_exists(username)})


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    avatar = data.get('avatar') or ''

    if len(username) < USERNAME_MIN:
        return jsonify({'error': f'Логин мин. {USERNAME_MIN} символа'}), 400
    if len(username) > USERNAME_MAX:
        return jsonify({'error': f'Логин макс. {USERNAME_MAX} символов'}), 400
    if not USERNAME_REGEX.match(username):
        return jsonify({'error': 'Только a-z, A-Z и 0-9 (без пробелов)'}), 400

    if len(password) < PASSWORD_MIN:
        return jsonify({'error': f'Пароль мин. {PASSWORD_MIN} символа'}), 400
    if len(password) > PASSWORD_MAX:
        return jsonify({'error': f'Пароль макс. {PASSWORD_MAX} символов'}), 400

    if user_exists(username):
        return jsonify({'error': 'Такой логин занят'}), 400

    if not avatar or len(avatar) > 500_000:
        avatar = generate_default_avatar(username[0].upper())

    create_user(username, password, avatar)
    return jsonify({'ok': True})


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not username or not password:
        return jsonify({'error': 'Введите логин и пароль'}), 400

    user = get_user(username)
    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 401
    if not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Неверный пароль'}), 401

    token = secrets.token_urlsafe(32)
    active_sessions[token] = username
    return jsonify({
        'ok': True,
        'token': token,
        'user': {
            'username': user['username'],
            'avatar': user['avatar']
        }
    })


@app.route('/api/me', methods=['GET'])
@token_required
def me():
    user = get_user(g.current_user)
    return jsonify({'username': user['username'], 'avatar': user['avatar']})


@app.route('/api/users', methods=['GET'])
@token_required
def users():
    return jsonify(get_all_users(exclude=g.current_user))


@app.route('/api/messages/<other>', methods=['GET'])
@token_required
def messages(other):
    msgs = get_messages(g.current_user, other)
    mark_as_read(other, g.current_user)
    return jsonify(msgs)


@app.route('/api/upload', methods=['POST'])
@token_required
def upload():
    if 'file' not in request.files:
        return jsonify({'error': 'Нет файла'}), 400
    file = request.files['file']
    if not file.filename:
        return jsonify({'error': 'Пустое имя файла'}), 400
    if not allowed_file(file.filename):
        return jsonify({'error': 'Тип файла не разрешён'}), 400

    ext = file.filename.rsplit('.', 1)[1].lower()
    unique = f"{secrets.token_hex(16)}.{ext}"
    filepath = os.path.join(UPLOAD_FOLDER, unique)
    file.save(filepath)
    size = os.path.getsize(filepath)

    return jsonify({
        'url': f'/uploads/{unique}',
        'file_name': secure_filename(file.filename),
        'file_size': size
    })


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(UPLOAD_FOLDER, filename)


@app.route('/health')
def health():
    return jsonify({'status': 'ok', 'time': time.time()})


# ==================================================
# SOCKET.IO
# ==================================================
@socketio.on('connect')
def handle_connect():
    token = request.args.get('token', '')
    if token not in active_sessions:
        return False
    username = active_sessions[token]
    online_users[username] = request.sid
    join_room(f'user_{username}')
    emit('user_online', {'username': username}, broadcast=True)
    emit('online_list', list(online_users.keys()), broadcast=True)
    print(f'[+] {username} подключился')


@socketio.on('disconnect')
def handle_disconnect():
    username = None
    for uname, sid in list(online_users.items()):
        if sid == request.sid:
            username = uname
            del online_users[uname]
            break
    if username:
        emit('user_offline', {'username': username}, broadcast=True)
        emit('online_list', list(online_users.keys()), broadcast=True)
        print(f'[-] {username} отключился')


@socketio.on('send_message')
def handle_send_message(data):
    token = data.get('token', '')
    if token not in active_sessions:
        return
    sender = active_sessions[token]
    receiver = data.get('to')
    msg_type = data.get('type', 'text')
    content = data.get('content', '')
    file_name = data.get('file_name')
    file_size = data.get('file_size')
    duration = data.get('duration')

    if not receiver:
        return

    msg = save_message(sender, receiver, msg_type, content,
                       file_name, file_size, duration)

    # Отправляем обоим: получателю и отправителю
    emit('new_message', msg, room=f'user_{receiver}')
    emit('new_message', msg, room=f'user_{sender}')


@socketio.on('typing')
def handle_typing(data):
    token = data.get('token', '')
    if token not in active_sessions:
        return
    sender = active_sessions[token]
    receiver = data.get('to')
    if receiver:
        emit('user_typing', {'from': sender}, room=f'user_{receiver}')


@socketio.on('stop_typing')
def handle_stop_typing(data):
    token = data.get('token', '')
    if token not in active_sessions:
        return
    sender = active_sessions[token]
    receiver = data.get('to')
    if receiver:
        emit('user_stop_typing', {'from': sender}, room=f'user_{receiver}')


# ==================================================
# ИНИЦИАЛИЗАЦИЯ (важно для Render — вызывается при импорте)
# ==================================================
init_db()


# ==================================================
# ЗАПУСК
# ==================================================
if __name__ == '__main__':
    # Порт: локально 5000, на Render — из переменной PORT
    port = int(os.environ.get('PORT', 5000))

    # Красивый баннер (только для локального запуска)
    if 'PORT' not in os.environ:
        print('=' * 55)
        print('  🚀 МЕССЕНДЖЕР ЗАПУЩЕН')
        print('=' * 55)
        import socket as _s
        try:
            s = _s.socket(_s.AF_INET, _s.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            s.close()
        except Exception:
            local_ip = '127.0.0.1'
        print(f'  💻 Локально:   http://127.0.0.1:{port}')
        print(f'  🌐 По сети:    http://{local_ip}:{port}')
        print()
        print('  (друзья должны быть в одной Wi-Fi сети)')
        print('=' * 55)

    socketio.run(app, host='0.0.0.0', port=port,
                 debug=False, allow_unsafe_werkzeug=True)