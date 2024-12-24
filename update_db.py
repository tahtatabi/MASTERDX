import sqlite3

conn = sqlite3.connect('database/masterdx.db')
cursor = conn.cursor()

# Add status and rejection_reason columns
cursor.execute('''
ALTER TABLE material_requests ADD COLUMN status TEXT DEFAULT 'Pending';
''')
cursor.execute('''
ALTER TABLE material_requests ADD COLUMN rejection_reason TEXT;
''')

conn.commit()
conn.close()
print("Database updated successfully.")
