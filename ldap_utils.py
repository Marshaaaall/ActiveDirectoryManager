from ldap3 import Server, Connection, Tls, SIMPLE, MODIFY_REPLACE
import ssl
import configparser
import os
import logging

# ================= Carregar Configurações =================
def carregar_configuracao():
    """Carrega as configurações do arquivo config.ini"""
    config = configparser.ConfigParser()
    config_file = 'config.ini'
    
    
    configuracao_padrao = {
        'DOMINIO_AD': 'MOTIVA',
        'SERVIDOR_AD': '10.100.0.10',
        'BASE_DN': 'dc=motiva,dc=matriz',
        'PORT': '636'
    }
    
    if os.path.exists(config_file):
        config.read(config_file)
       
        if 'LDAP' in config:
            return {
                'DOMINIO_AD': config['LDAP'].get('DOMINIO_AD', configuracao_padrao['DOMINIO_AD']),
                'SERVIDOR_AD': config['LDAP'].get('SERVIDOR_AD', configuracao_padrao['SERVIDOR_AD']),
                'BASE_DN': config['LDAP'].get('BASE_DN', configuracao_padrao['BASE_DN']),
                'PORT': config['LDAP'].get('PORT', configuracao_padrao['PORT'])
            }
    

    return configuracao_padrao

# Carrega as configurações
CONFIG = carregar_configuracao()
DOMINIO_AD = CONFIG['DOMINIO_AD']
SERVIDOR_AD = CONFIG['SERVIDOR_AD']
BASE_DN = CONFIG['BASE_DN']
PORT = int(CONFIG['PORT'])

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
    
    # Determinar se deve usar SSL com base na porta
    use_ssl = PORT == 636  # SSL para porta 636, sem SSL para outras portas
    
    server = Server(
        SERVIDOR_AD,
        use_ssl=use_ssl,
        tls=tls_configuration if use_ssl else None,
        get_info='ALL',
        port=PORT
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

def get_user_ou(conn, username):
    """
    Obtém a OU de um usuário existente no AD
    """
    try:
        search_filter = f"(sAMAccountName={username})"
        result = conn.search(
            search_base=BASE_DN,
            search_filter=search_filter,
            attributes=['distinguishedName']
        )
        
        if result:
            for entry in conn.entries:
                dn = entry.distinguishedName.value
                # Extrai a OU do DN
                ou_parts = [part for part in dn.split(',') if part.startswith('OU=')]
                if ou_parts:
                    return ou_parts[0][3:]  # Remove o 'OU=' prefix
        return None
    except Exception as e:
        logging.error(f"Erro ao obter OU do usuário {username}: {e}")
        return None

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

# Função para obter configurações em outros módulos
def obter_configuracao():
    """Retorna as configurações carregadas"""
    return CONFIG