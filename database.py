from flask_login import UserMixin
import sqlite3


class User(UserMixin):
    def __init__(self, user_id):
        self.id = user_id


conn = sqlite3.connect('access_control.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        mac_address TEXT,
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
