from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_login import LoginManager, login_user, login_required
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter.util import get_remote_address
from flask_limiter import Limiter
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from flask_socketio import SocketIO
from database import User, db
from forms import LoginForm
from network_scanner import update_database_with_devices, scan_local_network
from flask_sslify import SSLify
from wtforms import SelectField
from flask_wtf import FlaskForm
import settings
import version
import asyncio
import threading
import platform
import socket
import sqlite3
import os
import signal


app = Flask(__name__)
socketio = SocketIO(app)
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///access_control.db'

login_manager = LoginManager(app)

users_db = {'test': {'password_hash': generate_password_hash('test', method='pbkdf2:sha256', salt_length=8)}}

limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
)

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.context_processor
def inject_version():
    return dict(version=version.__version__)

@app.route('/system_info')
#@login_required
def system_info():
    os_info = platform.system()  
    os_version = platform.version()  
    hostname = socket.gethostname()  
    ip_address = socket.gethostbyname(hostname)

    system_details = {
        'os_info': os_info,
        'os_version': os_version,
        'hostname': hostname,
        'ip_address': ip_address,
    }

    return render_template('system_info.html', system_details=system_details)

@app.route('/', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user_id = form.user_id.data
        password = form.password.data

        if user_id in users_db and check_password_hash(users_db[user_id]['password_hash'], password):
            user = User(user_id)
            login_user(user)
            return redirect(url_for('users'))
        else:
            flash('Неправильный логин или пароль', 'error')

    return render_template('login.html', form=form)

@app.errorhandler(401)
def unauthorized_error(error):
    return redirect(url_for('login'))

@app.route('/index')
#@login_required
def users():
    try:
        conn = sqlite3.connect('access_control.db')
        conn.row_factory = sqlite3.Row  # Позволяет обращаться к колонкам по имени
        cursor = conn.cursor()
        cursor.execute('''
            SELECT ip_address, mac_address, hostname, last_seen, username, department, number_cabinet, access_allowed 
            FROM users
        ''')
        rows = cursor.fetchall()
        conn.close()

        users = []
        now = datetime.now()
        for row in rows:
            # Предполагается, что last_seen хранится в формате 'YYYY-MM-DD HH:MM:SS'
            try:
                last_seen = datetime.strptime(row['last_seen'], '%Y-%m-%d %H:%M:%S')
                is_online = (now - last_seen) <= timedelta(minutes=5)  # Настройте интервал по необходимости
            except (ValueError, TypeError):
                is_online = False  # Если парсинг не удался, считаем оффлайн

            users.append({
                'is_online': is_online,
                'ip': row['ip_address'],
                'mac': row['mac_address'],
                'hostname': row['hostname'],
                'last_seen': row['last_seen'],
                'username': row['username'],
                'department': row['department'],
                'number_cabinet': row['number_cabinet'],
                'access_allowed': row['access_allowed']
                
            })

        return render_template('index.html', users=users)

    except Exception as e:
        print(f"Ошибка при получении пользователей: {e}")
        return render_template('index.html', users=[])

@app.template_filter('format_uptime')
def format_uptime(uptime):
    uptime_delta = timedelta(seconds=uptime)

    formatted_uptime = str(uptime_delta).split('.')[0]
    return formatted_uptime


app.jinja_env.filters['format_uptime'] = format_uptime


@app.route('/update_user', methods=['POST'])
#@login_required
def update_user():
    try:
        data = request.get_json()

        users_data = data.get('users')

        with sqlite3.connect('access_control.db') as conn:
            cursor = conn.cursor()

            for user_data in users_data:
                ip = user_data.get('ip')
                mac = user_data.get('mac')
                username = user_data.get('username')
                department = user_data.get('department')
                cabinet = user_data.get('cabinet')

                cursor.execute('SELECT * FROM users WHERE mac_address = ?', (mac,))
                existing_user = cursor.fetchone()

                if existing_user:
                    cursor.execute(
                        'UPDATE users SET username = ?, department = ?, number_cabinet = ? WHERE mac_address = ?',
                        (username, department, cabinet, mac))
                else:
                    cursor.execute(
                        'INSERT INTO users (ip_address, mac_address, username, department, number_cabinet) VALUES (?, ?, ?, ?, ?)',
                        (ip, mac, username, department, cabinet))

            conn.commit()

        return jsonify({'status': 'success'})
    except Exception as e:
        print(e)
        return jsonify({'status': 'error'})


@app.route('/confirm_access', methods=['POST'])
#@login_required
def confirm_access():
    try:
        conn = sqlite3.connect('access_control.db')
        cursor = conn.cursor()

        cursor.execute('SELECT * FROM new_users')
        new_users = cursor.fetchall()

        for user in new_users:
            cursor.execute(
                'INSERT INTO users (ip_address, mac_address, username, department, number_cabinet) VALUES (?, ?, ?, ?, ?)',
                user[1:]
            )

        cursor.execute('DELETE FROM new_users')
        conn.commit()
        conn.close()

        return jsonify({'status': 'success'})

    except Exception as e:
        print(e)
        return jsonify({'status': 'error', 'message': 'Failed to confirm access'})

@app.route('/toggle_access', methods=['POST'])
#@login_required
def toggle_access():
    mac_address = request.form.get('macAddress')

    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT access_allowed FROM users WHERE mac_address = ?', (mac_address,))
    current_status = cursor.fetchone()

    if current_status is not None:
        current_status = not bool(current_status[0])
        cursor.execute('UPDATE users SET access_allowed = ? WHERE mac_address = ?', (current_status, mac_address))
        conn.commit()
        print(f"New status {cursor.rowcount}")
    else:
        current_status = True
        cursor.execute('INSERT INTO users (mac_address, access_allowed) VALUES (?, ?)', (mac_address, current_status))
        conn.commit()
        print(f"New user added with mac_address: {mac_address}")

    conn.close()

    # Возвращаем новый статус в формате JSON
    return jsonify({'newStatus': current_status})

def run_periodic_scan():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    while True:
        loop.run_until_complete(update_database_with_devices()) # Задержка 0 секунд перед следующим сканированием  


if __name__ == '__main__':
    scan_thread = threading.Thread(target=run_periodic_scan)
    scan_thread.daemon = True
    scan_thread.start()
    app.run(host=settings.host, port=settings.port,)