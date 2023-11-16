import socket
from datetime import timedelta
from scapy.all import srp
from scapy.layers.l2 import ARP, Ether, srp
from database import *
from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
import psutil

app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'


def scan_local_network(ip):
    arp_request = ARP(pdst=ip)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")  # Broadcast MAC address

    packet = ether_frame / arp_request
    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc.upper()})

    return devices


def update_database_with_devices():
    # Сканируем локальную сеть
    local_network_ip = "192.168.118.0/24"
    devices = scan_local_network(local_network_ip)

    # Добавляем устройства в базу данных
    for device in devices:
        ip_address = device['ip']
        mac_address = device['mac']
        username = "default"  # Замените это на логику получения имени пользователя, если возможно
        department = "default"  # Замените это на логику получения отдела, если возможно
        number_cabinet = "default"  # Замените это на логику получения номера кабинета, если возможно

        # Проверяем, что устройство еще не добавлено
        conn = sqlite3.connect('access_control.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE mac_address = ?', (mac_address,))
        existing_device = cursor.fetchone()

        if not existing_device:
            # Добавляем устройство в базу данных
            cursor.execute(
                'INSERT INTO users (username, ip_address, mac_address, department, number_cabinet) VALUES (?, ?, ?, ?, ?)',
                (username, ip_address, mac_address, department, number_cabinet))
            conn.commit()

        conn.close()


# Пример использования
local_network_ip = "192.168.118.0/24"
devices = scan_local_network(local_network_ip)

login_manager = LoginManager(app)
update_database_with_devices()


class LoginForm(FlaskForm):
    user_id = StringField('User ID', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


users_db = {'test': {'password': 'test'}}


@login_manager.user_loader
def load_user(user_id):
    return User(user_id)


@app.route('/', methods=['GET', 'POST'])
def login():
    form = LoginForm()  # Create an instance of the form
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
    return render_template('index.html')


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


def get_mac_address(ip_address):
    arp = ARP(pdst=ip_address)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    if result:
        mac_address = result[0][1].hwsrc.upper()
        return mac_address
    else:
        return None


@app.route('/block_site', methods=['POST'])
@login_required
def block_site():
    site_url = request.form.get('site_url')

    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('INSERT INTO blocked_sites (site_url) VALUES (?)', (site_url,))
    conn.commit()
    conn.close()

    # with open ('/etc/squid/squid.conf', 'a') as f:
    # f.write('acl blocked_sites dstdomain {0}\nhttp_access deny blocked_sites\n'.format(site_url))

    return redirect(url_for('index'))


@app.route('/users')
@login_required
def users():
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('users.html', users=users)


@app.route('/blocked_sites')
@login_required
def blocked_sites():
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM blocked_sites')
    blocked_sites = cursor.fetchall()
    conn.close()

    return render_template('blocked_sites.html', blocked_sites=blocked_sites)


@app.route('/monitoring')
@login_required
def monitoring():
    # Get system information using psutil
    cpu_percent = psutil.cpu_percent()
    memory_info = psutil.virtual_memory()
    disk_info = psutil.disk_usage('/')

    # Get network traffic information
    network_info = psutil.net_io_counters(pernic=True)

    # Extract data for the first network interface (you may need to adjust this based on your requirements)
    network_traffic = network_info[list(network_info.keys())[0]]
    sent_bytes = network_traffic.bytes_sent
    received_bytes = network_traffic.bytes_recv

    # Render the monitoring template with the collected information
    return render_template('monitoring.html', cpu_percent=cpu_percent, memory_info=memory_info,
                           disk_info=disk_info, sent_bytes=sent_bytes, received_bytes=received_bytes)


@app.template_filter('format_uptime')
def format_uptime(uptime):
    # Convert uptime to timedelta object
    uptime_delta = timedelta(seconds=uptime)

    # Format the timedelta as hh:mm:ss
    formatted_uptime = str(uptime_delta).split('.')[0]
    return formatted_uptime


def get_system_info():
    # Get system information using psutil
    ip_address = socket.gethostbyname(socket.gethostname())
    hostname = socket.gethostname()
    uptime = psutil.boot_time()

    return ip_address, hostname, uptime


app.jinja_env.filters['format_uptime'] = format_uptime


@app.route('/system')
@login_required
def system():
    # Get system information
    ip_address, hostname, uptime = get_system_info()

    # Additional system information (replace with actual values)
    sent_bytes = 1000000
    received_bytes = 2000000

    # Render the monitoring template with the collected information
    return render_template('system.html', ip_address=ip_address, hostname=hostname, uptime=uptime,
                           cpu_percent=psutil.cpu_percent(), memory_info=psutil.virtual_memory(),
                           disk_info=psutil.disk_usage('/'), sent_bytes=sent_bytes, received_bytes=received_bytes)


################### Удалить ###################


@app.route('/remove_user/<user_id>')
@login_required
def remove_user(user_id):
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('index'))


@app.route('/remove_site/<site_id>')
@login_required
def remove_site(site_id):
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM blocked_sites WHERE id = ?', site_id)
    conn.commit()
    conn.close()

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(host='192.168.118.13', port=5000)
