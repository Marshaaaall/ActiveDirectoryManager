import logging

DOMINIO_AD = "MOTIVA"
SERVIDOR_AD = "10.100.0.10"
BASE_DN = "dc=motiva,dc=matriz"
GRUPOS_PERMITIDOS = [
    "g_fg_analistas_ti",
    "Admins. do domínio",
]

# Configurar logging
logging.basicConfig(
    filename='ldap_user_creator.log', 
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

GRUPOS_INTERNET = [
    "g_fg_analistas_ti",
    "Admins. do domínio",
]