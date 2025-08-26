import logging
import configparser
import os

def get_config():
    config = configparser.ConfigParser()
    config_file = 'config.ini'
    
    if os.path.exists(config_file):
        config.read(config_file)
    else:
        # Configurações padrão
        config['LDAP'] = {
            'DOMINIO_AD': 'MOTIVA',
            'SERVIDOR_AD': '10.100.0.10',
            'BASE_DN': 'dc=motiva,dc=matriz'
        }
        with open(config_file, 'w') as configfile:
            config.write(configfile)
    
    return config

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