from scapy.all import srp
from scapy.layers.l2 import ARP, Ether
from database import *
from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, login_required
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired
from flask_wtf.csrf import CSRFProtect

app = Flask(__name__)

app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'

login_manager = LoginManager(app)


class LoginForm(FlaskForm):
    user_id = StringField('User ID', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


users_db = {'root': {'password': 'formula912'}}


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
        mac_address = result[0][1].hwsrc.upper()  # Convert to uppercase
        return mac_address
    else:
        return None


@app.route('/block_site', methods=['POST'])
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
def users():
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()

    return render_template('users.html', users=users)


@app.route('/blocked_sites')
def blocked_sites():
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM blocked_sites')
    blocked_sites = cursor.fetchall()
    conn.close()

    return render_template('blocked_sites.html', blocked_sites=blocked_sites)


################### Удалить ###################


@app.route('/remove_user/<user_id>')
def remove_user(user_id):
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('index'))


@app.route('/remove_site/<site_id>')
def remove_site(site_id):
    conn = sqlite3.connect('access_control.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM blocked_sites WHERE id = ?', site_id)
    conn.commit()
    conn.close()

    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)
