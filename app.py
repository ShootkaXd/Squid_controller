import asyncio
from flask import Flask, render_template, redirect, url_for, request, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_socketio import SocketIO
from forms import LoginForm
from network_scanner import update_database_with_devices, scan_local_network, get_mac_address
from SIEM import SIEM
from database import User
import psutil
import socket
from datetime import timedelta
import sqlite3
import subprocess
import json
import requests
from datetime import datetime

app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

socketio = SocketIO(app)


async def main():
    await update_database_with_devices()


local_network_ip = "192.168.118.0/24"
devices = scan_local_network(local_network_ip)

login_manager = LoginManager(app)
asyncio.run(main())

siem_system = SIEM()


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


users_db = {'test': {'password': 'test'}}


@socketio.on('connect')
def handle_connect():
    print('Client connected')
    emit_system_info()


def emit_system_info():
    cpu_percent = psutil.cpu_percent()
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')

    network_info = psutil.net_io_counters(pernic=True)
    network_traffic = network_info[list(network_info.keys())[0]]
    sent_bytes, received_bytes = network_traffic.bytes_sent, network_traffic.bytes_recv

    system_info = {
        'cpu_percent': cpu_percent,
        'memory_percent': memory_info.percent,
        'disk_percent': disk_info.percent,
        'sent_bytes': sent_bytes,
        'received_bytes': received_bytes
    }

    socketio.emit('system_info', system_info)


@app.route('/monitoring_realtime')
def monitor():
    return render_template('monitoring_realtime.html')


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_id = form.user_id.data
        password = form.password.data
        if user_id in users_db and users_db[user_id]['password'] == password:
            user = User(user_id)
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html', form=form)


@app.route('/index')
@login_required
def index():
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip_address, mac_address, username, department, number_cabinet, access_allowed FROM users')
    users = cursor.fetchall()
    conn.close()
    return render_template('index.html', users=users)


@app.route('/block_site', methods=['POST'])
@login_required
def block_site():
    site_url = request.form.get('site_url')

    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO blocked_sites (site_url) VALUES (?)', (site_url,))
    conn.commit()
    conn.close()

    # blocked_sites = fetch_blocked_sites_from_db()

    # update_squid_config([], blocked_sites)  # Раскомментируй эту строку
    # restart_squid()  # Если необходимо перезапустить Squid, раскомментируй эту строку

    return redirect(url_for('blocked_sites'))


@app.route('/blocked_sites')
@login_required
def blocked_sites():
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM blocked_sites')
    blocked_sites = cursor.fetchall()
    conn.close()

    return render_template('blocked_sites.html', blocked_sites=blocked_sites)


# Извлекает список сайтов из базы данных
def fetch_blocked_sites_from_db():
    try:
        conn = sqlite3.connect('access_control.db')
        cursor = conn.cursor()

        cursor.execute('SELECT site_url FROM blocked_sites')
        blocked_sites = [row[0] for row in cursor.fetchall()]

        conn.close()
        return blocked_sites
    except Exception as e:
        print(f"Error fetching blocked sites from the database: {e}")
        return []


@app.route('/users')
@login_required
def users():
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT ip_address, mac_address, username, department, number_cabinet, access_allowed FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('users.html', users=users)


def restart_squid():
    try:
        subprocess.run(['systemctl', 'restart', 'squid'], check=True)
        print("Squid restarted successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error restarting Squid: {e}")


@app.route('/monitoring')
@login_required
def monitoring():
    cpu_percent = psutil.cpu_percent()
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')

    network_info = psutil.net_io_counters(pernic=True)

    network_traffic = network_info[list(network_info.keys())[0]]
    sent_bytes = network_traffic.bytes_sent
    received_bytes = network_traffic.bytes_recv

    return render_template('system_info.html', cpu_percent=cpu_percent, memory_info=memory_info,
                           disk_info=disk_info, sent_bytes=sent_bytes, received_bytes=received_bytes)


@app.template_filter('format_uptime')
def format_uptime(uptime):
    uptime_delta = timedelta(seconds=uptime)

    formatted_uptime = str(uptime_delta).split('.')[0]
    return formatted_uptime


def get_system_info():
    ip_address = socket.gethostbyname(socket.gethostname())
    hostname = socket.gethostname()
    uptime = psutil.boot_time()

    return ip_address, hostname, uptime


app.jinja_env.filters['format_uptime'] = format_uptime


@app.route('/system')
@login_required
def system():
    ip_address, hostname, uptime = get_system_info()

    sent_bytes = 1000000
    received_bytes = 2000000

    return render_template('system.html', ip_address=ip_address, hostname=hostname, uptime=uptime,
                           cpu_percent=psutil.cpu_percent(), memory_info=psutil.virtual_memory(),
                           disk_info=psutil.disk_usage('/'), sent_bytes=sent_bytes, received_bytes=received_bytes)


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
        return jsonify({'status': 'error'})


@app.route('/confirm_access', methods=['POST'])
@login_required
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


@app.route('/get_new_users')
def get_new_users():
    try:
        conn = sqlite3.connect('access_control.db')
        cursor = conn.cursor()

        cursor.execute('SELECT ip_address, mac_address, username, department, number_cabinet FROM new_users')
        new_users = cursor.fetchall()

        conn.close()

        new_user_data = [
            {'ip': user[0], 'mac': user[1], 'username': user[2], 'department': user[3], 'number_cabinet': user[4]} for
            user in new_users]

        return jsonify(new_user_data)
    except Exception as e:
        print(e)
        return jsonify({'error': 'Failed to fetch new users'})


@app.route('/toggle_access', methods=['POST'])
def toggle_access():
    mac_address = request.form.get('macAddress')

    # Ваш код для получения текущего статуса из базы данных
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT access_allowed FROM users WHERE mac_address = ?', (mac_address,))
    current_status = cursor.fetchone()

    if current_status is not None:
        # Распаковываем кортеж и инвертируем текущий статус
        current_status = not bool(current_status[0])

        # Обновляем статус в базе данных
        cursor.execute('UPDATE users SET access_allowed = ? WHERE mac_address = ?', (current_status, mac_address))
        conn.commit()
        print(f"Rows affected: {cursor.rowcount}")
    else:
        # Если запись не найдена, можно создать новую запись с заданным статусом
        current_status = True  # Или любой другой статус по умолчанию
        cursor.execute('INSERT INTO users (mac_address, access_allowed) VALUES (?, ?)', (mac_address, current_status))
        conn.commit()
        print(f"New user added with mac_address: {mac_address}")

    conn.close()

    # Возвращаем новый статус в формате JSON
    return jsonify({'newStatus': current_status})


# def update_squid_config(allowed_sites, blocked_sites):
#     config_lines = []
#
#     for site in allowed_sites:
#         config_lines.append(f'acl allowed_sites dstdomain {site}\n')
#
#     for site in blocked_sites:
#         config_lines.append(f'acl blocked_sites dstdomain {site}\n')
#
#     config_lines.append('http_access allow allowed_sites\n')
#     config_lines.append('http_access deny blocked_sites\n')
#
#     with open('/etc/squid/squid.conf', 'w') as f:
#         f.writelines(config_lines)
#
#     restart_squid()


@app.route('/siem_system')
def index_siem():
    return render_template('siem_system.html')


@app.route('/send_event', methods=['POST'])
def send_event():
    try:
        siem_url = "https://your-siem-url/api/events"
        current_time = datetime.now().isoformat()

        event_data = {
            "event_type": request.form['eventType'],
            "timestamp": current_time,
            "source_ip": request.form['sourceIp'],
            "username": request.form['username'],
            "description": request.form['description']
        }

        headers = {"Content-Type": "application/json"}
        response = requests.post(siem_url, data=json.dumps(event_data), headers=headers)

        if response.status_code == 200:
            print("Event sent to SIEM successfully.")
            return jsonify({"status": "success"})
        else:
            print(f"Failed to send event to SIEM. Status code: {response.status_code}")
            return jsonify({"status": "error"})

    except Exception as e:
        print(f"Error during SIEM event sending: {e}")
        return jsonify({"status": "error"})


################### Удалить ###################


@app.route('/remove_site/<site_id>')
@login_required
def remove_site(site_id):
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM blocked_sites WHERE id = ?', (site_id,))
    conn.commit()
    conn.close()

    # blocked_sites = fetch_blocked_sites_from_db()
    #
    # update_squid_config([], blocked_sites)
    # restart_squid()

    return redirect(url_for('blocked_sites'))


@app.route('/remove_user', methods=['POST'])
@login_required
def allow_access():
    username = request.form.get('username')
    ip_address = request.form.get('ip_address')
    mac_address = get_mac_address(ip_address)
    department = request.form.get('department')
    number_cabinet = request.form.get('number_cabinet')

    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO users (username, ip_address, mac_address, department, number_cabinet) VALUES (?, ?, ?, ?, ?)',
        (username, ip_address, mac_address, department, number_cabinet))
    conn.commit()

    # with open('allowed_ips.txt', 'a') as f:
    #     f.write(ip_address + '\n')
    # run(['systemctl', 'restart', 'squid'])

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='192.168.118.13', port=5000)
