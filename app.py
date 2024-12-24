from flask import Flask, render_template, request, redirect, url_for, session
from ldap3 import Server, Connection, ALL
import sqlite3
from hdbcli import dbapi

app = Flask(__name__)
app.secret_key = 's3cr3t_k3y_M4st3rDX'

# Mock database
users = {'testuser': 'password123'}

SAP_HOST = "10.184.0.17"
SAP_PORT = 30241
SAP_USER = "POWERBI1"
SAP_PASSWORD = "OC#41GeKT"

def get_sap_connection():
    try:
        conn = dbapi.connect(
            address=SAP_HOST,
            port=SAP_PORT,
            user=SAP_USER,
            password=SAP_PASSWORD
        )
        return conn
    except Exception as e:
        print(f"Failed to connect to SAP: {e}")
        return None
    
# SAP'den veri çekme fonksiyonu
def fetch_sap_data(query):
    conn = get_sap_connection()
    if conn:
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        return results
    return []

LDAP_URL = 'ldap://192.168.16.44'
LDAP_BIND_DN = 'CN=LDAP-Widgetx,OU=Service Accounts,OU=IST,OU=EMEA,OU=_New,DC=farmasidom,DC=net'
LDAP_BIND_PASSWORD = 'gD7MBv7hxkUvg935@^c7tQFo*sE'
LDAP_BASE_DN = 'DC=farmasidom,DC=net'

def authenticate(username, password):
    try:
        server = Server(LDAP_URL, get_info=ALL)
        conn = Connection(server, user=f"{LDAP_BIND_DN}", password=LDAP_BIND_PASSWORD, auto_bind=True)
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter=f"(sAMAccountName={username})",
            attributes=['cn']
        )
        if conn.entries:
            user_dn = conn.entries[0].entry_dn
            user_conn = Connection(server, user=user_dn, password=password)
            if user_conn.bind():
                return True
        return False
    except Exception as e:
        print(f"LDAP authentication failed: {e}")
        return False

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = request.form.get('remember', False)  # Checkbox durumu

        if authenticate(username, password):  # LDAP doğrulama
            session['user'] = username
            print(f"DEBUG: User {username} authenticated successfully.")

            conn = sqlite3.connect('database/masterdx.db')
            cursor = conn.cursor()
            cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
            user_role = cursor.fetchone()

            session['role'] = user_role[0] if user_role else 'Talep Edici'
            print(f"DEBUG: User role set to {session['role']}")

            # Remember Me için çerez oluştur
            response = redirect(url_for('dashboard' if session['role'] in ['Admin', 'Ana Veri Uzmanı'] else 'user_reports'))
            if remember:
                response.set_cookie('remember_me', username, max_age=60 * 60 * 24 * 30, secure=False, httponly=True)  # 30 gün
                response.set_cookie('remember_password', password, max_age=60 * 60 * 24 * 7, secure=True, httponly=True)  # Şifreyi 7 gün sakla
                print(f"DEBUG: Remember Me cookie set for user {username}")
            return response

        else:
            print("DEBUG: Authentication failed.")
            return render_template('login.html', error="Invalid credentials")

    # Eğer 'remember_me' çerezi varsa oturum aç
    if 'user' not in session:
        username = request.cookies.get('remember_me')
        if username:
            session['user'] = username
            print(f"DEBUG: Auto-login using Remember Me for user {username}")
            conn = sqlite3.connect('database/masterdx.db')
            cursor = conn.cursor()
            cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
            user_role = cursor.fetchone()
            session['role'] = user_role[0] if user_role else 'Talep Edici'
            conn.close()
            return redirect(url_for('dashboard' if session['role'] in ['Admin', 'Ana Veri Uzmanı'] else 'user_reports'))

    return render_template('login.html')

@app.after_request
def disable_caching(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

@app.before_request
def auto_login_from_cookie():
    if 'user' not in session:
        username = request.cookies.get('remember_me')
        if username:
            print(f"DEBUG: Auto-login from cookie for {username}")
            conn = sqlite3.connect('database/masterdx.db')
            cursor = conn.cursor()
            cursor.execute('SELECT role FROM users WHERE username = ?', (username,))
            user_role = cursor.fetchone()
            session['user'] = username
            session['role'] = user_role[0] if user_role else 'Talep Edici'
            conn.close()
            print(f"DEBUG: Session re-established for {username}")

@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    response = redirect(url_for('login'))
    # Sadece oturum bilgilerini sıfırla, şifre çerezine dokunma
    print("DEBUG: User logged out, session cleared.")
    return response


@app.route('/request-lifecycle/<int:request_id>')
def request_lifecycle(request_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # İstek detaylarını al
    cursor.execute('''
        SELECT id, material_type, material_name, base_unit, requester, status, created_at, updated_at
        FROM material_requests
        WHERE id = ?
    ''', (request_id,))
    request_details = cursor.fetchone()

    if not request_details:
        return render_template('error.html', message="Request not found.")

    # Talep bazlı etkinlikleri al
    cursor.execute('''
        SELECT message, timestamp
        FROM recent_activities
        WHERE request_id = ?
        ORDER BY timestamp ASC
    ''', (request_id,))
    activities = cursor.fetchall()

    conn.close()

    # Veri dönüştürme
    request_details_dict = {
        "id": request_details[0],
        "material_type": request_details[1],
        "material_name": request_details[2],
        "base_unit": request_details[3],
        "requester": request_details[4],
        "status": request_details[5],
        "created_at": request_details[6],
        "updated_at": request_details[7]
    }

    activities_list = [{"message": act[0], "timestamp": act[1]} for act in activities]

    return render_template(
        'request_lifecycle.html',
        request_details=request_details_dict,
        activities=activities_list
    )

@app.route('/reject/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    rejection_reason = request.form['rejection_reason']

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # Talebi reddet ve zaman damgasını güncelle
    cursor.execute('''
        UPDATE material_requests
        SET status = 'Rejected', rejection_reason = ?, updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (rejection_reason, request_id))

    # Aktivite kaydını ekle
    cursor.execute('''
        INSERT INTO recent_activities (message, timestamp, request_id)
        VALUES (?, CURRENT_TIMESTAMP, ?)
    ''', ('Request rejected', request_id))

    conn.commit()
    conn.close()

    return redirect(url_for('view_requests', action='rejected'))

@app.route('/approve/<int:request_id>')
def approve_request(request_id):
    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # Talebi onayla ve zaman damgasını güncelle
    cursor.execute('''
        UPDATE material_requests
        SET status = 'Approved', updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (request_id,))

    # Aktivite kaydını ekle
    cursor.execute('''
        INSERT INTO recent_activities (message, timestamp, request_id)
        VALUES (?, CURRENT_TIMESTAMP, ?)
    ''', ('Request approved', request_id))

    conn.commit()
    conn.close()

    return redirect(url_for('view_requests', action='approved'))

@app.route('/view_requests')
def view_requests():
    # Örnek veri tabanı bağlantısı
    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # Tüm talepleri çek
    cursor.execute('SELECT id, material_type, material_name, base_unit, requester, status FROM material_requests')
    requests = cursor.fetchall()
    conn.close()

    return render_template('view_requests.html', requests=requests)

@app.route('/requests')
def view_all_requests():
    if 'user' not in session or session.get('role') != 'Admin':
        return render_template('error.html', message="You do not have permission to access this page.")

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM material_requests')
    requests = cursor.fetchall()

    conn.close()

    return render_template('view_requests.html', requests=requests)

@app.route('/material-request', methods=['GET', 'POST'])
def material_request():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        material_type = request.form['material_type']
        material_name = request.form['material_name']
        base_unit = request.form['base_unit']
        notes = request.form['notes']
        requester = session['user']

        conn = sqlite3.connect('database/masterdx.db')
        cursor = conn.cursor()

        # Malzeme talebini veritabanına ekle
        cursor.execute('''
            INSERT INTO material_requests (material_type, material_name, base_unit, notes, requester, status)
            VALUES (?, ?, ?, ?, ?, 'Pending')
        ''', (material_type, material_name, base_unit, notes, requester))

        # Recent Activities tablosuna etkinliği ekle
        cursor.execute('''
            INSERT INTO recent_activities (message)
            VALUES (?)
        ''', (f"User {requester} created a material request for '{material_name}'.",))

        conn.commit()
        conn.close()

        return redirect(url_for('user_reports', success=True))

    # SAP'den malzeme türleri ve temel ölçü birimlerini çek
    material_types = fetch_sap_data("SELECT MTART, MTBEZ FROM SAPHANADB.T134T WHERE SPRAS = 'T'")
    base_units = fetch_sap_data("SELECT MSEHI, MSEHT FROM SAPHANADB.T006A")

    return render_template('material_request.html', material_types=material_types, base_units=base_units)

@app.route('/sap/material-types')
def get_material_types():
    query = "SELECT MTART, MTBEZ FROM T134"  # SAP tablosundan malzeme türleri
    material_types = fetch_sap_data(query)
    return {"material_types": material_types}

@app.route('/approved-requests')
def approved_requests():
    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM material_requests WHERE status IN ("Approved", "Rejected")')
    approved = cursor.fetchall()

    conn.close()

    return render_template('approved_requests.html', approved=approved)

@app.route('/dashboard')
def dashboard():
    if 'user' not in session or session.get('role') not in ['Admin', 'Ana Veri Uzmanı']:
        return render_template('error.html', message="You do not have permission to access the Dashboard.")

    # Veritabanından istatistikleri al
    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # Talep durumlarına göre sayılar
    cursor.execute('SELECT status, COUNT(*) FROM material_requests GROUP BY status')
    status_counts = cursor.fetchall()
    status_data = [0, 0, 0]  # Pending, Approved, Rejected
    for status, count in status_counts:
        if status == 'Pending':
            status_data[0] = count
        elif status == 'Approved':
            status_data[1] = count
        elif status == 'Rejected':
            status_data[2] = count

    # Onay tamamlama yüzdesi
    cursor.execute('SELECT COUNT(*) FROM material_requests')
    total_requests = cursor.fetchone()[0]
    cursor.execute('SELECT COUNT(*) FROM material_requests WHERE status = "Approved"')
    approved_requests = cursor.fetchone()[0]
    completion_percentage = (approved_requests / total_requests * 100) if total_requests > 0 else 0

    # Son etkinlikler
    cursor.execute('SELECT message, timestamp FROM recent_activities ORDER BY timestamp DESC LIMIT 5')
    recent_activities = [{'message': row[0], 'timestamp': row[1]} for row in cursor.fetchall()]

    conn.close()

    return render_template(
        'dashboard.html',
        user=session['user'],
        status_data=status_data,
        completion_percentage=completion_percentage,
        recent_activities=recent_activities,
    )


def fetch_ldap_users():
    ldap_users = []
    try:
        server = Server(LDAP_URL, get_info=ALL)
        conn = Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)
        conn.search(
            search_base=LDAP_BASE_DN,
            search_filter='(memberOf=CN=widgetxusers,OU=Groups,DC=farmasidom,DC=net)',
            attributes=['sAMAccountName']
        )
        for entry in conn.entries:
            ldap_users.append(entry.sAMAccountName.value)
    except Exception as e:
        print(f"Failed to fetch LDAP users: {e}")
    return ldap_users

def fetch_group_members(group_dn):
    try:
        server = Server(LDAP_URL, get_info=ALL)
        conn = Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)
        conn.search(
            search_base=group_dn,
            search_filter='(objectClass=*)',
            attributes=['member']
        )
        members = []
        for entry in conn.entries:
            if 'member' in entry:
                members.extend(entry.member)
        return members
    except Exception as e:
        print(f"Failed to fetch group members: {e}")
        return []

def fetch_usernames_from_members(member_dns):
    usernames = []
    try:
        server = Server(LDAP_URL, get_info=ALL)
        conn = Connection(server, user=LDAP_BIND_DN, password=LDAP_BIND_PASSWORD, auto_bind=True)
        for member_dn in member_dns:
            conn.search(
                search_base=member_dn,
                search_filter='(objectClass=person)',
                attributes=['sAMAccountName']
            )
            for entry in conn.entries:
                usernames.append(entry.sAMAccountName.value)
    except Exception as e:
        print(f"Failed to fetch usernames: {e}")
    return usernames

@app.route('/user-management', methods=['GET', 'POST'])
def user_management():
    if 'user' not in session:
        return redirect(url_for('login'))

    # Yetkisiz erişim kontrolü
    if session.get('role') != 'Admin':
        return render_template('error.html', message="You do not have permission to access the User Management page.")

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # POST işlemi: Rol atama
    if request.method == 'POST':
        username = request.form['username']
        role = request.form['role']
        try:
            cursor.execute('INSERT INTO users (username, role) VALUES (?, ?)', (username, role))
            conn.commit()
        except sqlite3.IntegrityError:
            cursor.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
            conn.commit()

    # LDAP'den widgetx grubundaki kullanıcıları çek
    group_dn = "CN=widgetxusers,OU=\\#AccessRights_Group,DC=farmasidom,DC=net"
    members = fetch_group_members(group_dn)
    ldap_users = fetch_usernames_from_members(members)

    # Var olan kullanıcıları çek
    cursor.execute('SELECT username, role FROM users')
    users = cursor.fetchall()

    conn.close()

    return render_template('user_management.html', ldap_users=ldap_users, users=users)

@app.route('/edit-role/<username>', methods=['GET', 'POST'])
def edit_role(username):
    if 'user' not in session or session.get('role') != 'Admin':
        return render_template('error.html', message="You do not have permission to edit roles.")

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    if request.method == 'POST':
        new_role = request.form['role']
        cursor.execute('UPDATE users SET role = ? WHERE username = ?', (new_role, username))
        conn.commit()
        conn.close()
        return redirect(url_for('user_management'))

    # Kullanıcıyı al
    cursor.execute('SELECT username, role FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()

    return render_template('edit_role.html', user=user)

@app.route('/delete-user/<username>', methods=['POST'])
def delete_user(username):
    if 'user' not in session or session.get('role') != 'Admin':
        return render_template('error.html', message="You do not have permission to delete users.")

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

    return redirect(url_for('user_management'))

@app.route('/user-reports')
def user_reports():
    if 'user' not in session or session.get('role') != 'Talep Edici':
        return render_template('error.html', message="You do not have permission to access this page.")

    success = request.args.get('success', None)  # Başarı mesajı için URL parametresini al

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # Kullanıcının kendi taleplerini al
    cursor.execute('''
        SELECT id, material_name, material_type, base_unit, status 
        FROM material_requests 
        WHERE requester = ?
    ''', (session['user'],))
    user_requests = cursor.fetchall()

    conn.close()

    return render_template('user_reports.html', user_requests=user_requests, success=success)

@app.route('/search', methods=['GET'])
def search():
    query = request.args.get('query', '').strip()
    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, material_name 
        FROM material_requests 
        WHERE material_name LIKE ? OR CAST(id AS TEXT) LIKE ?
    ''', (f'%{query}%', f'%{query}%'))
    
    results = cursor.fetchall()
    conn.close()
    
    return {'results': [{'id': r[0], 'name': r[1]} for r in results]}

@app.route('/search-results', methods=['GET'])
def search_results():
    query = request.args.get('query', '').strip()
    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT id, material_name, material_type, base_unit, status
        FROM material_requests 
        WHERE material_name LIKE ? OR CAST(id AS TEXT) LIKE ?
    ''', (f'%{query}%', f'%{query}%'))
    
    results = cursor.fetchall()
    conn.close()
    
    return render_template('search_results.html', query=query, results=results)


@app.route('/tasks')
def tasks():
    if 'user' not in session or session.get('role') != 'Alan Doldurucu':
        return render_template('error.html', message="You do not have permission to access this page.")

    conn = sqlite3.connect('database/masterdx.db')
    cursor = conn.cursor()

    # Kullanıcının görevlerini al
    cursor.execute('''
        SELECT id, material_name, material_type, base_unit, status 
        FROM material_requests 
        WHERE assigned_to = ?
    ''', (session['user'],))
    user_tasks = cursor.fetchall()

    conn.close()

    return render_template('tasks.html', user_tasks=user_tasks)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=True)

app.config['TEMPLATES_AUTO_RELOAD'] = True
