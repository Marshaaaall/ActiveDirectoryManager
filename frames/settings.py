import tkinter as tk
from tkinter import ttk, messagebox
import configparser
import os

class SettingsFrame(ttk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent, padding = 10)
        self.root = root
        self.config = configparser.ConfigParser()
        self.config_file = 'config.ini'

        self.load_config()
        self.create_widgets()

    def load_config(self):
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            
            self.config['LDAP'] = {
            'DOMINIO_AD' : 'MOTIVA',
            'SERVIDOR_AD' : '10.100.0.10',
            'BASE_DN' : 'dc=motiva,dc=matriz'
            }
    
    def save_config(self):
        try:
            with open(self.config_file, 'w') as configfile:
                self.config.write(configfile)
            messagebox.showinfo("sucesso", "Configurações salvas com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar as configurações: {str(e)}")
    
    def create_widgets(self):

        main_frame = ttk.Frame(self, padding= 20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Configurações do LDAP", font= ('Arial', 16, 'bold')).pack(pady=10)

        form_frame = ttk.Frame(main_frame)
        form_frame.pack(fill=tk.X, pady=10)

        ttk.Label(form_frame, text="IP do servidor:").grid(row=0, column=0, sticky=tk.W, pady= 5)
        self.server_ip = ttk.Entry(form_frame, width=40)
        self.server_ip.grid(row=0, column=1, padx=5, pady=5)
        self.server_ip.insert(0, self.config['LDAP'].get('SERVIDOR_AD', ''))

        ttk.Label(form_frame, text="Domínio:").grid(row=1, column=0, sticky=tk.W, pady=5)

        self.domain = ttk.Entry(form_frame, width=40)
        self.domain.grid(row=1, column=1, padx=5, pady=5)
        self.domain.insert(0, self.config['LDAP'].get('DOMINIO_AD', ''))

        ttk.Label(form_frame, text="Base DN:").grid(row=2, column=0, sticky=tk.W, pady=5)
        self.base_dn = ttk.Entry(form_frame, width=40)
        self.base_dn.grid(row=2, column=1, padx=5, pady=5)
        self.base_dn.insert(0, self.config['LDAP'].get('BASE_DN', ''))


        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=20)

        ttk.Button(button_frame, text="Salvar", command=self.on_save).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Testar Conexão", command=self.test_connection).pack(side=tk.LEFT, padx=5)

    def on_save(self):
        self.config['LDAP']['SERVIDOR_AD'] = self.server_ip.get()
        self.config['LDAP']['DOMINIO_AD'] = self.domain.get()
        self.config['LDAP']['BASE_DN'] = self.base_dn.get()
        self.save_config()
    
    def test_connection(self):
        messagebox.showinfo("Info", "FUNCIONALIDADE NAO IMPLEMENTADA")