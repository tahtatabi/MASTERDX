from ldap3 import Server, Connection, ALL

LDAP_URL = 'ldap://192.168.16.44'
LDAP_BIND_DN = 'CN=LDAP-Widgetx,OU=Service Accounts,OU=IST,OU=EMEA,OU=_New,DC=farmasidom,DC=net'
LDAP_BIND_PASSWORD = 'gD7MBv7hxkUvg935@^c7tQFo*sE'
LDAP_BASE_DN = 'DC=farmasidom,DC=net'

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

# Test
group_dn = "CN=widgetx,OU=\\#AccessRights_Group,DC=farmasidom,DC=net"
members = fetch_group_members(group_dn)
print("Members of widgetx Group:")
for member in members:
    print(member)
