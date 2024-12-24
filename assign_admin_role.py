import sqlite3

# Veritabanına bağlan
conn = sqlite3.connect('database/masterdx.db')
cursor = conn.cursor()

# Kullanıcıya admin rolü ata
username = 'yavuz.dincer'
role = 'Admin'

# Kullanıcı zaten varsa rolü güncelle, yoksa ekle
try:
    cursor.execute('INSERT INTO users (username, role) VALUES (?, ?)', (username, role))
except sqlite3.IntegrityError:
    cursor.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))

conn.commit()
conn.close()

print(f"{username} kullanıcısına {role} rolü atandı.")
