import sqlite3


conn = sqlite3.connect('access_control.db')
cursor = conn.cursor()
cursor.execute(
    '''CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY, 
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    mac_address TEXT, 
    department TEXT NOT NULL,
    number_cabinet TEXT NOT NULL
    )''')


cursor.execute('''
CREATE TABLE IF NOT EXISTS blocked_sites(
               id INTEGER PRIMARY KEY,
               site_url TEXT NOT NULL
)''')


conn.commit()
conn.close()