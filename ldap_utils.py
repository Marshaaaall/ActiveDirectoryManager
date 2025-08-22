from ldap3 import Server, Connection, Tls, SIMPLE, MODIFY_REPLACE
import ssl
from config import DOMINIO_AD, SERVIDOR_AD
from ldap3 import Server, Connection, MODIFY_REPLACE

# ================= Conexão LDAP =================
def conectar_ldap(usuario, senha):
    """
    Conecta ao servidor LDAP usando NTLM.
    Retorna uma conexão bindada.
    """
    # Configurações de TLS para conexão segura
    tls_configuration = Tls(
        validate=ssl.CERT_NONE,
        version=ssl.PROTOCOL_TLSv1_2
    )
    
    server = Server(
        SERVIDOR_AD,
        use_ssl=True,
        tls=tls_configuration,
        get_info='ALL',
        port=636
    )
    
    # Usar autenticação NTLM
    conn = Connection(
        server,
        user=f"{DOMINIO_AD}\\{usuario}",
        password=senha,
        authentication=SIMPLE,
        auto_bind=True
    )
    
    return conn
    


# ================= Criação de Usuário =================
def create_user(conn, cn, surname, ou_dn, user_password, additional_attrs=None):
    """
    Cria um usuário no LDAP.
    """
    dn = f"CN={cn},{ou_dn}"
    attributes = {
        'objectClass': ['top', 'person', 'organizationalPerson', 'user'],
        'cn': cn,
        'sn': surname,
        'userPrincipalName': f"{cn}@motiva.matriz",
        'sAMAccountName': cn,
        'displayName': cn
    }
    if additional_attrs:
        attributes.update(additional_attrs)

    try:
        conn.add(dn, attributes=attributes)
        if conn.result['description'] != 'success':
            raise Exception(conn.result['message'])
        # Definir senha do usuário
        conn.extend.microsoft.modify_password(dn, user_password)
        # Habilitar a conta
        conn.modify(dn, {'userAccountControl': [(MODIFY_REPLACE, [512])]})
        return True
    except Exception as e:
        print(f"Erro criar usuário {cn}: {e}")
        return False

# ================= Verifica status do usuário =================
def is_account_disabled(userAccountControl):
    """
    Retorna True se a conta estiver desabilitada
    """
    # Bit 2 = ACCOUNTDISABLE
    return bool(int(userAccountControl) & 0x2)

# ================= Extrai OU de DN =================
def extract_ou_from_dn(dn):
    """
    Retorna a OU de um DN completo
    """
    parts = dn.split(',')
    ou_parts = [p for p in parts if p.upper().startswith('OU=')]
    return ','.join(ou_parts) if ou_parts else ''

# ================= Mover usuário =================
def move_user(conn, user_dn, new_parent_dn):
    """
    Move um usuário para outra OU no Active Directory.
    """
    try:
        cn_part = user_dn.split(',', 1)[0]
        if conn.modify_dn(user_dn, cn_part, new_superior=new_parent_dn):
            return True
        else:
            raise Exception(conn.last_error or "Erro desconhecido ao mover usuário")
    except Exception as e:
        print(f"Erro mover usuário {user_dn}: {e}")
        return False
