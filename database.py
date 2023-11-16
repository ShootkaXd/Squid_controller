import sqlite3


conn = sqlite3.connect('access_control.db')
cursor = conn.cursor()
cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT,
        mac_address TEXT,
        username TEXT,
        department TEXT,
        number_cabinet TEXT
    )
''')


cursor.execute('''
CREATE TABLE IF NOT EXISTS blocked_sites(
               id INTEGER PRIMARY KEY,
               site_url TEXT NOT NULL
)''')


conn.commit()
conn.close()