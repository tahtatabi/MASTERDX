import sqlite3

conn = sqlite3.connect('database/masterdx.db')
cursor = conn.cursor()

# Kullanıcılar tablosunu oluştur
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL
)
''')

conn.commit()
conn.close()
print("Users table created successfully.")
