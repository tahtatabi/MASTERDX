import sqlite3

conn = sqlite3.connect('database/masterdx.db')
cursor = conn.cursor()

# Material requests table
cursor.execute('''
CREATE TABLE IF NOT EXISTS material_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    material_type TEXT,
    material_name TEXT,
    base_unit TEXT,
    notes TEXT,
    requester TEXT
)
''')

conn.commit()
conn.close()
print("Database and table created successfully.")
