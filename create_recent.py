import sqlite3

def add_timestamps_to_material_requests():
    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    try:
        # created_at sütununu ekle
        cursor.execute("ALTER TABLE material_requests ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        print("`created_at` sütunu başarıyla eklendi.")
    except sqlite3.OperationalError as e:
        print(f"`created_at` sütunu zaten mevcut: {e}")

    try:
        # updated_at sütununu ekle
        cursor.execute("ALTER TABLE material_requests ADD COLUMN updated_at DATETIME DEFAULT CURRENT_TIMESTAMP")
        print("`updated_at` sütunu başarıyla eklendi.")
    except sqlite3.OperationalError as e:
        print(f"`updated_at` sütunu zaten mevcut: {e}")

    conn.commit()
    conn.close()

# Fonksiyonu çalıştır
add_timestamps_to_material_requests()
