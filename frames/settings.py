import tkinter as tk
from tkinter import ttk, messagebox
import configparser
import os

class SettingsFrame(ttk.frame):
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

        main_frame = ttk.Frame(self.frame, padding= 20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Configurações do LDAP", font= 20)