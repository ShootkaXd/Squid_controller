import aiosqlite
import socket
import asyncio
import version
import platform
import os
import sqlite3
import threading
import csv
import settings
import logging
import json
from flask import Flask, render_template, redirect, url_for, request, jsonify, flash, Response
from flask_login import LoginManager, login_user, login_required
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter.util import get_remote_address
from io import StringIO
from flask_limiter import Limiter
from flask_socketio import SocketIO
from database import User, db
from forms import LoginForm
from network_scanner import update_database_with_devices

# Настройка логирования
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("app.log"),
                        logging.StreamHandler()
                    ])
logger = logging.getLogger(__name__)

app = Flask(__name__)
# Инициализация SocketIO с async_mode='threading'
socketio = SocketIO(app, async_mode='threading')
app.secret_key = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///access_control.db'

login_manager = LoginManager(app)

# Настройка Flask-Limiter
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Пользователи (должны быть вынесены в отдельную таблицу базы данных)
users_db = {'test': {'password_hash': generate_password_hash('test', method='pbkdf2:sha256', salt_length=8)}}

@login_manager.user_loader
def load_user(user_id):
    return User(user_id)

@app.context_processor
def inject_version():
    return dict(version=version.__version__)

@app.route('/system_info')
@login_required
def system_info():
    try:
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
    except Exception as e:
        logger.error(f"Ошибка при получении системной информации: {e}")
        return render_template('system_info.html', system_details={})

@app.route('/logs')
@login_required
def logs():
    try:
        def tail(file_path, lines=100):
            """Читает последние `lines` строк из файла `file_path`."""
            with open(file_path, 'rb') as f:
                f.seek(0, os.SEEK_END)
                buffer = bytearray()
                pointer = f.tell() - 1
                line_count = 0

                while pointer >= 0 and line_count < lines:
                    f.seek(pointer)
                    char = f.read(1)
                    if char == b'\n':
                        line_count += 1
                        if line_count == lines:
                            break
                    buffer.extend(char)
                    pointer -= 1

                buffer = buffer[::-1]  # Разворачиваем буфер
                return buffer.decode('utf-8', errors='replace')

        log_file_path = 'app.log'  # Убедитесь, что путь к файлу логов правильный
        log_content = tail(log_file_path, lines=100)

        return render_template('logs.html', log_content=log_content)
    except Exception as e:
        logger.error(f"Ошибка при получении логов: {e}")
        flash('Не удалось загрузить логи.', 'error')
        return render_template('logs.html', log_content="")

@app.route('/export/csv')
@login_required
def export_csv():
    try:
        # Асинхронное извлечение пользователей из базы данных
        async def fetch_users():
            async with aiosqlite.connect('access_control.db') as conn:
                conn.row_factory = aiosqlite.Row
                cursor = await conn.cursor()
                await cursor.execute('''
                    SELECT ip_address, mac_address, hostname, last_seen, username, department, number_cabinet, access_allowed 
                    FROM users
                ''')
                rows = await cursor.fetchall()
                return rows

        # Запуск события для асинхронной работы
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        rows = loop.run_until_complete(fetch_users())
        loop.close()

        # Создание CSV с использованием модуля csv и добавлением BOM
        si = StringIO(newline='')  # Обязательно указываем newline=''
        writer = csv.writer(si, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        # Запись заголовков
        writer.writerow(['ip_address', 'mac_address', 'hostname', 'last_seen', 'username', 'department', 'number_cabinet', 'access_allowed'])

        # Запись данных
        for row in rows:
            writer.writerow([
                row['ip_address'],
                row['mac_address'],
                row['hostname'],
                row['last_seen'],
                row['username'],
                row['department'],
                row['number_cabinet'],
                row['access_allowed']
            ])

        output = si.getvalue()
        si.close()

        # Добавление BOM (Byte Order Mark) для корректного отображения в Excel
        bom = '\ufeff'
        csv_data = bom + output

        # Возвращение ответа с правильной кодировкой
        return Response(
            csv_data,
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=users.csv'}
        )
    except Exception as e:
        logger.error(f"Ошибка при экспорте CSV: {e}")
        flash('Не удалось экспортировать данные в CSV.', 'error')
        return redirect(url_for('users'))

@app.route('/export/json')
@login_required
def export_json():
    try:
        async def fetch_users():
            async with aiosqlite.connect('access_control.db') as conn:
                conn.row_factory = aiosqlite.Row
                cursor = await conn.cursor()
                await cursor.execute('''
                    SELECT ip_address, mac_address, hostname, last_seen, username, department, number_cabinet, access_allowed 
                    FROM users
                ''')
                rows = await cursor.fetchall()
                return rows

        # Запуск события для асинхронной работы
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        rows = loop.run_until_complete(fetch_users())
        loop.close()

        # Преобразование данных в список словарей
        users_data = [dict(row) for row in rows]

        # Конвертация списка в JSON
        json_data = json.dumps(users_data, ensure_ascii=False)  # ensure_ascii=False для поддержки русских символов

        # Возвращение ответа с правильной кодировкой
        return Response(
            json_data,
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment;filename=users.json'}
        )
    except Exception as e:
        logger.error(f"Ошибка при экспорте JSON: {e}")
        flash('Не удалось экспортировать данные в JSON.', 'error')
        return redirect(url_for('users'))

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
@login_required
def users():
    try:
        async def fetch_users():
            async with aiosqlite.connect('access_control.db') as conn:
                conn.row_factory = aiosqlite.Row
                cursor = await conn.cursor()
                await cursor.execute('''
                    SELECT ip_address, mac_address, hostname, last_seen, username, department, number_cabinet, access_allowed 
                    FROM users
                ''')
                rows = await cursor.fetchall()

                users = []
                now = datetime.now()
                for row in rows:
                    try:
                        last_seen = datetime.strptime(row['last_seen'], '%Y-%m-%d %H:%M:%S')
                        is_online = (now - last_seen) <= timedelta(minutes=5)
                    except (ValueError, TypeError):
                        is_online = False

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
                return users

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        users = loop.run_until_complete(fetch_users())
        loop.close()

        return render_template('index.html', users=users)

    except Exception as e:
        logger.error(f"Ошибка при получении пользователей: {e}")
        return render_template('index.html', users=[])

@app.template_filter('format_uptime')
def format_uptime(uptime):
    try:
        uptime_delta = timedelta(seconds=int(uptime))
        formatted_uptime = str(uptime_delta).split('.')[0]
        return formatted_uptime
    except Exception as e:
        logger.error(f"Ошибка при форматировании аптайма: {e}")
        return "Неизвестно"

app.jinja_env.filters['format_uptime'] = format_uptime

"""Рабочий код"""
@app.route('/update_user', methods=['POST'])
@login_required
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
        logger.error(f"Ошибка при обновлении пользователя: {e}")
        return jsonify({'status': 'error'})

@app.route('/confirm_access', methods=['POST'])
@login_required
def confirm_access():
    try:
        async def confirm():
            async with aiosqlite.connect('access_control.db') as conn:
                cursor = await conn.cursor()
                await cursor.execute('SELECT ip_address, mac_address, username, department, number_cabinet FROM new_users')
                new_users = await cursor.fetchall()

                for user in new_users:
                    await cursor.execute('''
                        INSERT INTO users (ip_address, mac_address, username, department, number_cabinet)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(mac_address) DO NOTHING
                    ''', user)

                await cursor.execute('DELETE FROM new_users')
                await conn.commit()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(confirm())
        loop.close()

        return jsonify({'status': 'success'})
    except Exception as e:
        logger.error(f"Ошибка при подтверждении доступа: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to confirm access'})

@app.route('/toggle_access', methods=['POST'])
@login_required
def toggle_access():
    try:
        mac_address = request.form.get('macAddress')
        if not mac_address:
            return jsonify({'status': 'error', 'message': 'MAC address is required'}), 400

        async def toggle():
            async with aiosqlite.connect('access_control.db') as conn:
                cursor = await conn.cursor()
                await cursor.execute('SELECT access_allowed FROM users WHERE mac_address = ?', (mac_address,))
                current_status = await cursor.fetchone()

                if current_status is not None:
                    new_status = not bool(current_status[0])
                    await cursor.execute('UPDATE users SET access_allowed = ? WHERE mac_address = ?', (new_status, mac_address))
                else:
                    new_status = True
                    await cursor.execute('INSERT INTO users (mac_address, access_allowed) VALUES (?, ?)', (mac_address, new_status))
                await conn.commit()
                return new_status

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        new_status = loop.run_until_complete(toggle())
        loop.close()

        return jsonify({'newStatus': new_status})

    except Exception as e:
        logger.error(f"Ошибка при переключении доступа: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to toggle access'})

async def periodic_scan(interval=0):
    """Периодическое сканирование сети с заданным интервалом (в секундах)."""
    while True:
        try:
            await update_database_with_devices()
        except Exception as e:
            logger.error(f"Ошибка в периодическом сканировании: {e}")
        await asyncio.sleep(interval)  # Задержка между сканированиями

def start_periodic_scan():
    """Запуск периодического сканирования в отдельном потоке."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(periodic_scan())

if __name__ == '__main__':
    # Запуск периодического сканирования в отдельном потоке
    scan_thread = threading.Thread(target=start_periodic_scan, daemon=True)
    scan_thread.start()
    logger.info(f"Запуск веб-приложения на {settings.host}:{settings.port}")
    socketio.run(app, host=settings.host, port=settings.port, debug=False, allow_unsafe_werkzeug=True)
