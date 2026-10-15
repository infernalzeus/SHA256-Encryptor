import os
import csv
import hashlib
import secrets
from datetime import timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)
app.permanent_session_lifetime = timedelta(hours=8)

KEY_FILE     = os.getenv('KEY_FILE',      r'C:\Users\yash2\OneDrive\Code\SHA_Passkey\encryption_key.key')
DATA_PATH    = os.getenv('DATA_PATH',     r'C:\Users\yash2\OneDrive\Code\SHA_Passkey\data.csv')
PASSBOOK_PATH = os.getenv('PASSBOOK_PATH', r'C:\Users\yash2\OneDrive\Code\SHA_Passkey\passbook.csv')
MASTER_HASH  = os.getenv('MASTER_PASSWORD_HASH', '')


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------

def load_csv(path):
    try:
        with open(path, 'r', newline='', encoding='utf-8') as f:
            return list(csv.DictReader(f))
    except FileNotFoundError:
        return []


def save_csv(path, data, fieldnames):
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(data)


# ---------------------------------------------------------------------------
# Encryption helpers
# ---------------------------------------------------------------------------

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    key = Fernet.generate_key()
    os.makedirs(os.path.dirname(KEY_FILE), exist_ok=True)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key


def encrypt(value, key):
    return Fernet(key).encrypt(value.encode()).decode()


def decrypt(value, key):
    try:
        return Fernet(key).decrypt(value.encode()).decode()
    except Exception:
        return None


def make_sha_key(user, acc, info):
    return hashlib.sha256(f"{user}{acc}{info}".encode()).hexdigest()


# ---------------------------------------------------------------------------
# Entry helpers
# ---------------------------------------------------------------------------

def get_all_entries(enc_key):
    entries = []
    for row in load_csv(DATA_PATH):
        user = decrypt(row['user'], enc_key)
        acc  = decrypt(row['acc#'], enc_key)
        info = decrypt(row['info'], enc_key)
        if user and acc and info:
            entries.append({'user': user, 'acc': acc, 'info': info,
                            'key': make_sha_key(user, acc, info)})
    return sorted(entries, key=lambda x: x['info'].lower())


def get_password(sha_key, enc_key):
    for entry in load_csv(PASSBOOK_PATH):
        if entry['key'] == sha_key:
            return decrypt(entry['pass'], enc_key)
    return None


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def check_password(password):
    if not MASTER_HASH:
        return False
    return hashlib.sha256(password.encode()).hexdigest() == MASTER_HASH


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('authenticated'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        if check_password(request.form.get('password', '')):
            session.permanent = True
            session['authenticated'] = True
            return redirect(url_for('index'))
        flash('Invalid password.')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    enc_key = load_key()
    entries = get_all_entries(enc_key)
    q = request.args.get('q', '').strip().lower()
    if q:
        entries = [e for e in entries if q in e['info'].lower() or q in e['user'].lower()]
    return render_template('index.html', entries=entries, q=q)


@app.route('/entry/<sha_key>')
@login_required
def detail(sha_key):
    enc_key = load_key()
    entry = next((e for e in get_all_entries(enc_key) if e['key'] == sha_key), None)
    if not entry:
        flash('Entry not found.')
        return redirect(url_for('index'))
    password = get_password(sha_key, enc_key)
    return render_template('detail.html', entry=entry, password=password)


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add():
    if request.method == 'POST':
        user     = request.form.get('user', '').strip()
        acc      = request.form.get('acc', '').strip()
        info     = request.form.get('info', '').strip()
        password = request.form.get('password', '').strip()

        if not all([user, acc, info, password]):
            flash('All fields are required.')
            return render_template('add.html', form=request.form)

        enc_key = load_key()

        data = load_csv(DATA_PATH)
        data.append({'user': encrypt(user, enc_key),
                     'acc#': encrypt(acc, enc_key),
                     'info': encrypt(info, enc_key)})
        save_csv(DATA_PATH, data, ['user', 'acc#', 'info'])

        sha_k = make_sha_key(user, acc, info)
        passbook = load_csv(PASSBOOK_PATH)
        passbook.append({'key': sha_k, 'pass': encrypt(password, enc_key)})
        save_csv(PASSBOOK_PATH, passbook, ['key', 'pass'])

        flash('Entry added.')
        return redirect(url_for('detail', sha_key=sha_k))

    return render_template('add.html', form={})


@app.route('/edit/<sha_key>', methods=['GET', 'POST'])
@login_required
def edit(sha_key):
    enc_key = load_key()
    entry = next((e for e in get_all_entries(enc_key) if e['key'] == sha_key), None)
    if not entry:
        flash('Entry not found.')
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_user = request.form.get('user', '').strip()
        new_acc  = request.form.get('acc', '').strip()
        new_info = request.form.get('info', '').strip()
        new_pass = request.form.get('password', '').strip()

        if not all([new_user, new_acc, new_info]):
            flash('User, account, and info are required.')
            return render_template('edit.html', entry=entry, sha_key=sha_key)

        # Update data.csv
        data = load_csv(DATA_PATH)
        for row in data:
            if (decrypt(row['user'], enc_key) == entry['user'] and
                    decrypt(row['acc#'], enc_key) == entry['acc'] and
                    decrypt(row['info'], enc_key) == entry['info']):
                row['user'] = encrypt(new_user, enc_key)
                row['acc#'] = encrypt(new_acc, enc_key)
                row['info'] = encrypt(new_info, enc_key)
                break
        save_csv(DATA_PATH, data, ['user', 'acc#', 'info'])

        # Update passbook (re-key + optionally new password)
        new_sha = make_sha_key(new_user, new_acc, new_info)
        passbook = load_csv(PASSBOOK_PATH)
        for pb in passbook:
            if pb['key'] == sha_key:
                pb['key'] = new_sha
                if new_pass:
                    pb['pass'] = encrypt(new_pass, enc_key)
                break
        save_csv(PASSBOOK_PATH, passbook, ['key', 'pass'])

        flash('Entry updated.')
        return redirect(url_for('detail', sha_key=new_sha))

    return render_template('edit.html', entry=entry, sha_key=sha_key)


@app.route('/delete/<sha_key>', methods=['POST'])
@login_required
def delete(sha_key):
    enc_key = load_key()
    entry = next((e for e in get_all_entries(enc_key) if e['key'] == sha_key), None)
    if not entry:
        flash('Entry not found.')
        return redirect(url_for('index'))

    data = load_csv(DATA_PATH)
    data = [row for row in data if not (
        decrypt(row['user'], enc_key) == entry['user'] and
        decrypt(row['acc#'], enc_key) == entry['acc'] and
        decrypt(row['info'], enc_key) == entry['info']
    )]
    save_csv(DATA_PATH, data, ['user', 'acc#', 'info'])

    passbook = [pb for pb in load_csv(PASSBOOK_PATH) if pb['key'] != sha_key]
    save_csv(PASSBOOK_PATH, passbook, ['key', 'pass'])

    flash('Entry deleted.')
    return redirect(url_for('index'))


if __name__ == '__main__':
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('PORT', 5000))
    app.run(host=host, port=port, debug=False)
