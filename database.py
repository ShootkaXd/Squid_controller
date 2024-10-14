from flask_login import UserMixin
import sqlite3
from flask_sqlalchemy import SQLAlchemy


db = SQLAlchemy()


class User(db.Model, UserMixin):
    def __init__(self, user_id):
        self.id = user_id

    status = db.Column(db.String(20))
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(15), unique=True)
    mac_address = db.Column(db.String(17), unique=True)
    hostname = db.Column(db.String(255))
    last_seen = db.Column(db.String(255))
    username = db.Column(db.String(255))
    department = db.Column(db.String(255))
    number_cabinet = db.Column(db.String(255))
    access_allowed = db.Column(db.Boolean, default=False)


conn = sqlite3.connect('access_control.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        status TEXT DEFAULT "offline",
        ip_address TEXT ,
        mac_address TEXT UNIQUE,
        hostname TEXT,
        last_seen TEXT,
        username TEXT,
        department TEXT,
        number_cabinet TEXT,
        access_allowed BOOLEAN DEFAULT FALSE
    )
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS blocked_sites(
               id INTEGER PRIMARY KEY,
               site_url TEXT NOT NULL
)''')

cursor.execute('''
    CREATE TABLE IF NOT EXISTS new_users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        mac_address TEXT,
        username TEXT,
        department TEXT,
        number_cabinet TEXT
    )
''')

conn.commit()
conn.close()
