import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from ldap3 import Server, Connection, ALL, SUBTREE, Tls, NTLM, SIMPLE, BASE, MODIFY_REPLACE, MODIFY_ADD
import ssl
import re
from ldap3.utils.dn import escape_rdn
import logging
import traceback
import unicodedata
import threading
import pandas as pd
import os
from datetime import datetime, timedelta
from datetime import timezone

import queue

# Configurações do servidor LDAP
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

class LDAPUserCreator:
    def __init__(self, root):
        self.root = root
        root.title("Criação de Usuário LDAP - MOTIVA")
        root.geometry("1100x900")
        root.resizable(False, False)
        
        # Variáveis para controle de edição manual
        self.full_name_edited = False
        self.login_edited = False
        self.login_counter = {}
        self.import_queue = queue.Queue()
        self.import_running = False
        self.import_progress = 0
        self.import_total = 0
        
        # Estilo
        style = ttk.Style()
        style.configure("TLabel", padding=5, font=("Arial", 10))
        style.configure("TButton", padding=5, font=("Arial", 10))
        style.configure("TEntry", padding=5, font=("Arial", 10))
        style.configure("Header.TLabel", font=("Arial", 11, "bold"))
        style.configure("Success.TLabel", foreground="green")
        style.configure("Error.TLabel", foreground="red")
        
        # Frame principal
        main_frame = ttk.Frame(root, padding=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Notebook (abas)
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.grid(row=0, column=0, columnspan=2, sticky="nsew")
        
        # Aba de criação individual
        individual_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(individual_frame, text="Criação Individual")
        
        # Aba de importação em massa
        mass_import_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(mass_import_frame, text="Importação em Massa")
        
        # Aba: Mover Usuários
        move_users_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(move_users_frame, text="Mover Usuários")

        # Aba: Mover Usuários em Massa
        mass_move_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(mass_move_frame, text="Mover Usuários em Massa")

        # aba: dashboard
        dashboard_frame = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(dashboard_frame, text="Dashboard")
        
        # Conteúdo das abas
        self.setup_individual_frame(individual_frame)
        self.setup_mass_import_frame(mass_import_frame)
        self.setup_move_users_frame(move_users_frame)
        self.setup_mass_move_frame(mass_move_frame)
        self.setup_dashboard_frame(dashboard_frame)
        
        # Status
        self.status_var = tk.StringVar()
        self.status_bar = ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status_var.set(f"Preencha as credenciais de um usuário de um dos grupos: {', '.join(GRUPOS_PERMITIDOS)}")
        
        # Ajustar colunas
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(0, weight=1)
    
    def update_dashboard(self):
        """Atualiza os dados do dashboard"""
        username = self.dash_admin_user.get().strip()
        password = self.dash_admin_password.get()

        if not username or not password:
            messagebox.showerror("Erro", "Preencha ambos os campos de usuário e senha")
            return
    
        self.dash_status.config(text="Conectando...")
        self.dash_refresh_btn.config(state=tk.DISABLED)
        threading.Thread(target=self.dashboard_thread, args=(username, password), daemon=True).start()

    def setup_dashboard_frame(self, frame):
        """Configura a aba de dashboard com informações do AD"""
        ttk.Label(frame, text="Dashboard - Informações do Active Directory", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)

        cred_frame = ttk.Frame(frame)
        cred_frame.grid(row=1, column=0, columnspan=2, pady=10)

        ttk.Label(cred_frame, text="Credenciais: ").pack(side=tk.LEFT)
        ttk.Label(cred_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.dash_admin_user = ttk.Entry(cred_frame, width=20)
        self.dash_admin_user.pack(side=tk.LEFT)
        
        ttk.Label(cred_frame, text="Senha:").pack(side=tk.LEFT, padx=(10, 0))
        self.dash_admin_password = ttk.Entry(cred_frame, width=20, show="*")
        self.dash_admin_password.pack(side=tk.LEFT)

        self.dash_refresh_btn = ttk.Button(
            cred_frame,
            text="Atualizar",
            command=self.update_dashboard  
        )
        self.dash_refresh_btn.pack(side=tk.LEFT, padx=(10, 0))

        self.dash_status = ttk.Label(frame, text="", font=("Arial", 9), foreground="blue")
        self.dash_status.grid(row=2, column=0, columnspan=2, pady=5)

        # frame principal para exibir dados
        data_frame = ttk.Frame(frame)
        data_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky="nsew")

        # Painel de Estatisticas
        stats_frame = ttk.LabelFrame(data_frame, text="Estatísticas Gerais", padding=10)
        stats_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        # Labels para estatísticas
        ttk.Label(stats_frame, text="Total de Usuários:").grid(row=0, column=0, sticky=tk.W)
        self.total_users = ttk.Label(stats_frame, text="0")
        self.total_users.grid(row=0, column=1, sticky=tk.W)

        ttk.Label(stats_frame, text="Usuários Desativados:").grid(row=1, column=0, sticky=tk.W)
        self.disabled_users = ttk.Label(stats_frame, text="0", foreground="red", cursor="hand2")
        self.disabled_users.grid(row=1, column=1, sticky=tk.W)
        self.disabled_users.bind("<Button-1>", lambda e: self.on_statistic_click("disabled"))

        ttk.Label(stats_frame, text="Usuários Ativos:").grid(row=2, column=0, sticky=tk.W)
        self.active_users = ttk.Label(stats_frame, text="0", foreground="green", cursor="hand2")
        self.active_users.grid(row=2, column=1, sticky=tk.W)
        self.active_users.bind("<Button-1>", lambda e: self.on_statistic_click("active"))

        ttk.Label(stats_frame, text="Usuários nunca logados:").grid(row=3, column=0, sticky=tk.W)
        self.never_logged_users = ttk.Label(stats_frame, text="0", foreground="orange", cursor="hand2")
        self.never_logged_users.grid(row=3, column=1, sticky=tk.W)
        self.never_logged_users.bind("<Button-1>", lambda e: self.on_statistic_click("never_logged"))

        ttk.Label(stats_frame, text="Usuários inativos > 30 dias:").grid(row=4, column=0, sticky=tk.W)
        self.inactive_users = ttk.Label(stats_frame, text="0", foreground="purple", cursor="hand2")
        self.inactive_users.grid(row=4, column=1, sticky=tk.W)
        self.inactive_users.bind("<Button-1>", lambda e: self.on_statistic_click("inactive"))

        ou_frame = ttk.LabelFrame(data_frame, text="Distribuição por OU", padding=10)
        ou_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)

        # Treeview para exibir OUs
        self.ou_tree = ttk.Treeview(ou_frame, columns=("OU", "Quantidade"), show="headings", height=8)
        self.ou_tree.pack(fill=tk.BOTH, expand=True)
        self.ou_tree.heading("OU", text="OU")
        self.ou_tree.heading("Quantidade", text="Quantidade")
        self.ou_tree.column("OU", width=200)
        self.ou_tree.column("Quantidade", width=80, anchor=tk.CENTER)

        # Grupo de internet
        internet_frame = ttk.LabelFrame(data_frame, text="Grupos de Internet", padding=10)
        internet_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)

        self.internet_tree = ttk.Treeview(internet_frame, columns=("Grupo", "Quantidade"), show="headings", height=5)
        self.internet_tree.pack(fill=tk.BOTH, expand=True)
        self.internet_tree.heading("Grupo", text="Grupo")
        self.internet_tree.heading("Quantidade", text="Quantidade")
        self.internet_tree.column("Grupo", width=200)
        self.internet_tree.column("Quantidade", width=80, anchor=tk.CENTER)

        # Frame para detalhes de usuários
        users_frame = ttk.LabelFrame(data_frame, text="Detalhes dos Usuários", padding=10)
        users_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)

        # Treeview para usuários
        scrollbar = ttk.Scrollbar(users_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.users_tree = ttk.Treeview(
            users_frame,
            columns=("nome", "Login", "OU", "Status", "Ultimo Logon", "Grupo"),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=10
        )
        self.users_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.users_tree.yview)

        self.users_tree.heading("nome", text="Nome")
        self.users_tree.heading("Login", text="Login")
        self.users_tree.heading("OU", text="OU")
        self.users_tree.heading("Status", text="Status")
        self.users_tree.heading("Ultimo Logon", text="Último Logon")
        self.users_tree.heading("Grupo", text="Grupo de Internet")

        self.users_tree.column("nome", width=150)
        self.users_tree.column("Login", width=100)
        self.users_tree.column("OU", width=150)
        self.users_tree.column("Status", width=80)
        self.users_tree.column("Ultimo Logon", width=120)
        self.users_tree.column("Grupo", width=200)

        # tag para status
        self.users_tree.tag_configure('disabled', foreground='grey')
        self.users_tree.tag_configure('active', foreground='black')
        self.users_tree.tag_configure('inactive', foreground='orange')
        self.users_tree.tag_configure('never', foreground='purple')

        # Ajustar layout
        data_frame.columnconfigure(0, weight=1)
        data_frame.columnconfigure(1, weight=1)
        data_frame.rowconfigure(0, weight=1)
        data_frame.rowconfigure(1, weight=1)
        
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(3, weight=1)
    
    def dashboard_thread(self, username, password):
        """Thread para atualizar os dados do dashboard"""
        try:
            # Configurar TLS
            tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_configuration, port=636)
        
        # Tentativa com autenticação SIMPLE
            try:
                conn = Connection(
                    server,
                    user=f"{username}@{DOMINIO_AD}.matriz",
                    password=password,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            except Exception as e:
                logging.error(f"Erro na autenticação SIMPLE: {str(e)}")
                # Fallback para NTLM
                user_ntlm = f"{DOMINIO_AD}\\{username}"
                conn = Connection(
                    server,
                    user=user_ntlm,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
        
        # Atualização correta do status
            self.root.after(0, lambda: self.dash_status.config(text="Coletando dados...", foreground="blue"))
        
        # Coletar todos os usuários
            conn.search(
                search_base=BASE_DN,
                search_filter='(&(objectClass=user)(objectCategory=person))',
                attributes=[
                    'cn', 
                    'sAMAccountName', 
                    'distinguishedName', 
                    'userAccountControl', 
                    'lastLogonTimestamp',
                    'memberOf'
                ],
                search_scope=SUBTREE
            )
        
            total_users = len(conn.entries)
            disabled_count = 0
            never_logged_count = 0
            inactive_count = 0
            active_count = 0
        
            # Dados para distribuição por OU
            ou_distribution = {}
        
            # Dados para grupos de internet
            internet_groups = {group: 0 for group in GRUPOS_INTERNET}
        
            # Dados para treeview de usuários
            user_data = []

            self.dashboard_user_data = user_data
        
            # Processar cada usuário
            for i, entry in enumerate(conn.entries):
                # Status da conta
                uac = entry.userAccountControl.value if hasattr(entry, "userAccountControl") else None
                is_disabled = self.is_account_disabled(uac)
            
            # Contagens
                if is_disabled:
                    disabled_count += 1
                else:
                    active_count += 1
            
            # CORREÇÃO: Processamento do último logon com tratamento de timezone
                last_logon = None
                if hasattr(entry, "lastLogonTimestamp") and entry.lastLogonTimestamp.value:
                    # Verificar se já é um objeto datetime
                    if isinstance(entry.lastLogonTimestamp.value, datetime):
                        last_logon = entry.lastLogonTimestamp.value
                    else:
                        # Converter timestamp do AD para datetime
                        last_logon_timestamp = int(entry.lastLogonTimestamp.value)
                        last_logon = datetime(1601, 1, 1) + timedelta(microseconds=last_logon_timestamp/10)
                
                # Converter para UTC se for um datetime com timezone
                    if last_logon.tzinfo is not None:
                        last_logon = last_logon.astimezone(timezone.utc).replace(tzinfo=None)
                
                # Verificar se nunca logou
                    if last_logon.year == 1601:
                        last_logon_str = "Nunca"
                        if not is_disabled:
                            never_logged_count += 1
                    else:
                        last_logon_str = last_logon.strftime("%d/%m/%Y %H:%M")
                    
                    # CORREÇÃO: Usar UTC para ambos os lados da comparação
                        now_utc = datetime.utcnow()
                    
                    # Verificar inatividade (mais de 30 dias)
                        if (now_utc - last_logon) > timedelta(days=30):
                            inactive_count += 1
                else:
                    last_logon_str = "Nunca"
                    if not is_disabled:
                        never_logged_count += 1
            
            # OU
                dn = entry.distinguishedName.value
                ou = self.extract_ou_from_dn(dn)
            
            # Atualizar distribuição por OU
                if ou:
                    ou_distribution[ou] = ou_distribution.get(ou, 0) + 1
            
            # Grupos de internet
                groups = entry.memberOf.values if hasattr(entry, "memberOf") else []
                internet_group = "Nenhum"
                for group in groups:
                    group_name = group.split(",")[0].split("=")[1]
                    if group_name in GRUPOS_INTERNET:
                        internet_group = group_name
                        internet_groups[group_name] = internet_groups.get(group_name, 0) + 1
                        break
            
            # Adicionar dados para treeview
                user_data.append({
                    "cn": entry.cn.value,
                    "login": entry.sAMAccountName.value,
                    "ou": ou,
                    "status": "Desativado" if is_disabled else "Ativo",
                    "last_logon": last_logon_str,
                    "groups": internet_group
                })
            
            # Atualizar status periodicamente
                if i % 50 == 0:
                    self.root.after(0, lambda i=i, total=total_users: 
                        self.dash_status.config(text=f"Processando {i+1}/{total} usuários...", foreground="blue")
                    )
        
        # Ordenar distribuição por OU
            sorted_ou = sorted(ou_distribution.items(), key=lambda x: x[1], reverse=True)
        
        # Atualizar UI com chamada correta
            self.root.after(0, lambda: self.update_dashboard_ui(
                total_users, disabled_count, active_count, 
                never_logged_count, inactive_count,
                sorted_ou, internet_groups, user_data
            ))

        
            conn.unbind()
            self.root.after(0, lambda: self.dash_status.config(text="Dados atualizados com sucesso!", foreground="green"))
        
        except Exception as e:
            error_msg = f"Erro ao atualizar dashboard: {str(e)}"
            logging.error(error_msg)
            self.root.after(0, lambda: self.dash_status.config(text=error_msg, foreground="red"))
        finally:
            self.root.after(0, lambda: self.dash_refresh_btn.config(state=tk.NORMAL))
    
    def extract_ou_from_dn(self, dn):
        """Extrai a OU de um DN"""
        try:
            parts = dn.split(',')
            ou_parts = [part for part in parts[1:] if part.startswith('OU=')]
            if ou_parts:
                # Remover prefixo 'OU=' e juntar com '/'
                return '/'.join([ou[3:] for ou in ou_parts])
            return "Domínio Raiz"
        except Exception:
            return "Erro ao analisar DN"
    
    def update_dashboard_ui(self, total, disabled, active, never_logged, inactive, ou_data, internet_data, user_data):
        """Atualiza a interface do dashboard com os dados coletados"""
        # Atualizar estatísticas
        self.total_users.config(text=str(total))
        self.disabled_users.config(text=str(disabled))
        self.active_users.config(text=str(active))
        self.never_logged_users.config(text=str(never_logged))
        self.inactive_users.config(text=str(inactive))
        
        # Atualizar distribuição por OU
        for item in self.ou_tree.get_children():
            self.ou_tree.delete(item)
        
        for ou, count in ou_data:
            self.ou_tree.insert("", "end", values=(ou, count))
        
        # Atualizar grupos de internet
        for item in self.internet_tree.get_children():
            self.internet_tree.delete(item)
        
        for group in GRUPOS_INTERNET:
            count = internet_data.get(group, 0)
            self.internet_tree.insert("", "end", values=(group, count))
        
        # Atualizar detalhes de usuários
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
        
        for user in user_data:
            status = user["status"]
            tags = ()
            
            if status == "Desativado":
                tags = ("disabled",)
            elif user["last_logon"] == "Nunca":
                tags = ("never",)
            elif "inativo" in user and user["inativo"]:
                tags = ("inactive",)
            else:
                tags = ("active",)
                
            self.users_tree.insert("", "end", values=(
                user["cn"],
                user["login"],
                user["ou"],
                status,
                user["last_logon"],
                user["groups"]
            ), tags=tags)
    
    def is_account_disabled(self, uac):
        """Verifica se a conta está desativada com base no userAccountControl"""
        if uac is None:
            return False
    # O valor 2 representa a conta desativada (ADS_UF_ACCOUNTDISABLE)
        return uac & 2 == 2


    def setup_mass_move_frame(self, frame):
        """Configura a aba para mover usuários em massa entre OUs"""
        ttk.Label(frame, text="Mover Usuários em Massa", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)
        
        # Instruções
        instructions = (
            "Instruções:\n"
            "1. Prepare uma planilha Excel com a coluna 'Usuário' (nome completo ou login)\n"
            "2. Selecione a OU de destino para onde os usuários serão movidos\n"
            "3. Clique em 'Selecionar Planilha' para carregar os dados\n"
            "4. Clique em 'Mover Usuários' para iniciar a movimentação\n"
        )
        ttk.Label(frame, text=instructions, justify=tk.LEFT).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=10)

        # Botão para selecionar planilha
        self.mass_move_select_btn = ttk.Button(
            frame,
            text="Selecionar Planilha",
            command=self.select_mass_move_spreadsheet
        )
        self.mass_move_select_btn.grid(row=2, column=0, columnspan=2, pady=10)

        # Área de visualização da planilha
        self.mass_move_tree_frame = ttk.Frame(frame)
        self.mass_move_tree_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=10)

        # Barra de rolagem
        scrollbar = ttk.Scrollbar(self.mass_move_tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Treeview para mostrar os dados da planilha
        self.mass_move_tree = ttk.Treeview(
            self.mass_move_tree_frame, 
            columns=("Usuário",),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=10
        )
        self.mass_move_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.mass_move_tree.yview)

        # Configurar colunas
        self.mass_move_tree.heading("Usuário", text="Usuário")
        self.mass_move_tree.column("Usuário", width=300)

        # Seção de destino
        ttk.Label(frame, text="Mover para OU:").grid(row=4, column=0, sticky=tk.W)
        self.mass_move_target_ou = ttk.Combobox(frame, width=50)
        self.mass_move_target_ou.grid(row=4, column=1, pady=5, sticky=tk.EW)

        # Seção de credenciais
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(
            row=5, column=0, columnspan=2, sticky=tk.EW, pady=10
        )

        ttk.Label(frame, text="Credenciais do Grupo de TI", style="Header.TLabel").grid(row=6, column=0, columnspan=2, pady=5)

        ttk.Label(frame, text="Usuário de Rede:").grid(row=7, column=0, sticky=tk.W)
        move_user_frame = ttk.Frame(frame)
        move_user_frame.grid(row=7, column=1, sticky=tk.W)
        ttk.Label(move_user_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.mass_move_admin_user = ttk.Entry(move_user_frame, width=25)
        self.mass_move_admin_user.pack(side=tk.LEFT)

        ttk.Label(frame, text="Senha:").grid(row=8, column=0, sticky=tk.W)
        self.mass_move_admin_password = ttk.Entry(frame, width=30, show="*")
        self.mass_move_admin_password.grid(row=8, column=1, pady=5, sticky=tk.EW)

        # Botão de verificação de credenciais
        self.mass_move_test_btn = ttk.Button(
            frame, 
            text="Verificar Credenciais", 
            command=self.verify_mass_move_credentials
        )
        self.mass_move_test_btn.grid(row=9, column=0, columnspan=2, pady=10)
        self.mass_move_connection_status = ttk.Label(frame, text="", font=("Arial", 9))
        self.mass_move_connection_status.grid(row=10, column=0, columnspan=2)

        # Botão de mover usuários
        self.mass_move_btn = ttk.Button(
            frame,
            text="Mover Usuários",
            command=self.start_mass_move,
            state=tk.DISABLED
        )
        self.mass_move_btn.grid(row=11, column=0, columnspan=2, pady=20)

        # Barra de progresso
        self.mass_move_progress_var = tk.DoubleVar()
        self.mass_move_progress_bar = ttk.Progressbar(
            frame, 
            orient=tk.HORIZONTAL, 
            length=300, 
            mode='determinate',
            variable=self.mass_move_progress_var
        )
        self.mass_move_progress_bar.grid(row=12, column=0, columnspan=2, pady=10)

        # Status da movimentação
        self.mass_move_status = ttk.Label(frame, text="", foreground="blue")
        self.mass_move_status.grid(row=13, column=0, columnspan=2)

        # Ajustar layout
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)
    
    def is_account_disabled(self, user_account_control):
        """Verifica se a conta está desabilitada com base no userAccountControl"""
        if user_account_control is None:
            return False

        try:
            uac = int(user_account_control)

            return uac & 2 == 2
        
        except (ValueError, TypeError):
            return False

    def select_mass_move_spreadsheet(self):
        """Seleciona um arquivo Excel para mover usuários em massa"""
        file_path = filedialog.askopenfilename(
            title="Selecione a planilha Excel",
            filetypes=[("Excel Files", "*.xlsx *.xls")]
        )
        
        if not file_path:
            return
        
        try:
            # Ler a planilha Excel
            df = pd.read_excel(file_path)
            
            # Verificar coluna obrigatória
            if 'Usuário' not in df.columns:
                messagebox.showerror("Erro", "A planilha deve conter a coluna 'Usuário'")
                return
            
            # Limpar dados
            df = df.dropna(subset=['Usuário'])
            df = df.fillna('')
                
            # Limpar a treeview
            for item in self.mass_move_tree.get_children():
                self.mass_move_tree.delete(item)
            
            # Adicionar dados à treeview
            for _, row in df.iterrows():
                username = str(row['Usuário']).strip()

                status = "desabilitado" if 'desativado' in username.lower() else "ativo"
                tags = ('desativado',) if 'desativado' in username.lower() else ('habilitado',)

                self.mass_move_tree.insert("", "end", values=(username, status), tags=tags)
            
            # Armazenar os dados para processamento
            self.mass_move_data = df
            self.mass_move_status.config(text=f"Planilha carregada com {len(df)} usuários", foreground="green")
            
        except Exception as e:
            error_msg = f"Falha ao ler a planilha: {str(e)}"
            messagebox.showerror("Erro", error_msg)
            logging.error(f"Erro ao ler planilha (mover em massa): {error_msg}")
            self.mass_move_status.config(text=error_msg, foreground="red")

    def verify_mass_move_credentials(self):
        """Verifica credenciais para mover usuários em massa"""
        username = self.mass_move_admin_user.get().strip()
        password = self.mass_move_admin_password.get()
        
        if not username or not password:
            messagebox.showerror("Erro", "Preencha ambos os campos de usuário e senha")
            return
        
        try:
            # Configurar TLS
            tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_configuration, port=636)
            
            # Tentativa com autenticação SIMPLE
            try:
                conn = Connection(
                    server,
                    user=f"{username}@{DOMINIO_AD}.matriz",
                    password=password,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            except Exception as e:
                logging.error(f"Erro na autenticação SIMPLE: {str(e)}")
                # Fallback para NTLM
                user_ntlm = f"{DOMINIO_AD}\\{username}"
                conn = Connection(
                    server,
                    user=user_ntlm,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
            
            # Armazenar conexão
            self.conn_mass_move = conn
            
            # Carregar OUs
            if self.load_ous_for_mass_move():
                self.mass_move_connection_status.config(
                    text=f"✅ Credenciais validadas com sucesso!",
                    style="Success.TLabel"
                )
                self.mass_move_btn.config(state=tk.NORMAL)
                self.mass_move_status.config(text="Credenciais validadas - Pronto para mover usuários", foreground="green")
                logging.info("Credenciais validadas para mover usuários em massa")
            else:
                raise Exception("Falha ao carregar OUs")
        
        except Exception as e:
            error_msg = f"Erro: {str(e)}"
            logging.error(f"Falha na verificação de credenciais (mover em massa): {error_msg}")
            self.mass_move_connection_status.config(text=f"❌ {error_msg}", style="Error.TLabel")
            self.mass_move_btn.config(state=tk.DISABLED)
            self.mass_move_status.config(text=error_msg, foreground="red")

    def load_ous_for_mass_move(self):
        """Carrega todas as OUs do AD para a aba de mover em massa"""
        if not hasattr(self, 'conn_mass_move') or not self.conn_mass_move.bound:
            return False
        
        try:
            ous_list = ["Domínio Raiz"]
            
            # Buscar todas as OUs
            self.conn_mass_move.search(
                search_base=BASE_DN,
                search_filter='(objectClass=organizationalUnit)',
                attributes=['ou', 'distinguishedName'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn_mass_move.entries:
                ou_name = entry.ou.value
                dn = entry.distinguishedName.value
                ous_list.append(dn)
            
            # Atualizar combobox
            self.mass_move_target_ou['values'] = ous_list
            
            return True
        except Exception as e:
            error_msg = f"Erro ao carregar OUs: {str(e)}"
            logging.error(error_msg)
            self.mass_move_status.config(text=error_msg, foreground="red")
            return False

    def start_mass_move(self):
        """Inicia o processo de mover usuários em massa"""
        if not hasattr(self, 'mass_move_data') or self.mass_move_data.empty:
            messagebox.showwarning("Aviso", "Nenhuma planilha carregada ou dados vazios")
            return
        
        target_ou = self.mass_move_target_ou.get()
        if not target_ou:
            messagebox.showerror("Erro", "Selecione uma OU de destino")
            return
        
        # Desabilitar botões durante a operação
        self.mass_move_select_btn.config(state=tk.DISABLED)
        self.mass_move_btn.config(state=tk.DISABLED)
        self.mass_move_test_btn.config(state=tk.DISABLED)
        
        # Configurar progresso
        total_users = len(self.mass_move_data)
        self.mass_move_progress_var.set(0)
        self.mass_move_progress_bar["maximum"] = total_users
        self.mass_move_status.config(text=f"Iniciando movimentação de {total_users} usuários...", foreground="blue")
        
        # Iniciar thread de movimentação
        threading.Thread(
            target=self.mass_move_thread,
            args=(target_ou,),
            daemon=True
        ).start()

    def mass_move_thread(self, target_ou):
        """Thread para processar a movimentação em massa"""
        try:
            success_count = 0
            error_count = 0
            log_details = []
            
            for i, row in self.mass_move_data.iterrows():
                username = str(row['Usuário']).strip()
                if not username:
                    continue
                
                try:
                    #verifica se a conta está desabilitada

                    is_disabled = self.is_user_disabled(username)
                    status_note = "desabilitado" if is_disabled else ""

                    # Buscar DN do usuário
                    self.conn_mass_move.search(
                        search_base=BASE_DN,
                        search_filter=f"(|(cn={username})(sAMAccountName={username}))",
                        attributes=['distinguishedName'],
                        search_scope=SUBTREE
                    )
                    
                    if not self.conn_mass_move.entries:
                        raise Exception(f"Usuário não encontrado: {username}")
                    
                    user_dn = self.conn_mass_move.entries[0].distinguishedName.value
                    
                    # Determinar novo DN
                    if target_ou == "Domínio Raiz":
                        new_parent = BASE_DN
                    else:
                        new_parent = target_ou

                    # Extrair CN do DN atual
                    cn_part = user_dn.split(',', 1)[0]
                    # O CN é a parte após o '='
                    cn_value = cn_part.split('=')[1]
                    new_dn = f"{cn_part},{new_parent}"
                    
                    # Mover usuário: modifica o DN, mantendo o CN e mudando o superior
                    if not self.conn_mass_move.modify_dn(user_dn, cn_part, new_superior=new_parent):
                        error_msg = self.conn_mass_move.last_error or "Erro desconhecido"
                        raise Exception(f"Falha ao mover: {error_msg}")
                    
                    success_count += 1
                    log_details.append(f"✅ {username}{status_note}: Movido com sucesso para {new_parent}")
                
                except Exception as e:
                    error_count += 1
                    error_msg = str(e)
                    log_details.append(f"❌ {username}: {error_msg}")
                    logging.error(f"Erro ao mover {username}: {error_msg}")
                
                # Atualizar progresso
                progress = i + 1
                self.root.after(100, self.update_mass_move_progress, progress, success_count, error_count)
                self.root.update_idletasks()
            
            # Resultado final
            result_msg = (
                f"Movimentação concluída!\n\n"
                f"Total de usuários: {len(self.mass_move_data)}\n"
                f"Sucessos: {success_count}\n"
                f"Erros: {error_count}"
            )
            
            # Salvar logs
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"mass_move_log_{timestamp}.txt"
            with open(log_filename, 'w', encoding='utf-8') as f:
                f.write(result_msg + "\n\n")
                f.write("\n".join(log_details))
            
            self.mass_move_status.config(
                text=result_msg + f"\nLog salvo em: {os.path.abspath(log_filename)}", 
                foreground="green" if error_count == 0 else "orange"
            )
            messagebox.showinfo("Concluído", result_msg + f"\n\nVerifique o log completo em:\n{os.path.abspath(log_filename)}")
        
        except Exception as e:
            error_msg = f"Erro na movimentação em massa: {str(e)}"
            logging.error(error_msg)
            self.mass_move_status.config(text=error_msg, foreground="red")
        finally:
            # Reabilitar botões
            self.mass_move_select_btn.config(state=tk.NORMAL)
            self.mass_move_btn.config(state=tk.NORMAL)
            self.mass_move_test_btn.config(state=tk.NORMAL)

    def update_mass_move_progress(self, current, success, errors):
        """Atualiza a barra de progresso e status da movimentação em massa"""
        self.mass_move_progress_var.set(current)
        self.mass_move_status.config(
            text=f"Processando: {current}/{len(self.mass_move_data)} | Sucessos: {success} | Erros: {errors}",
            foreground="blue"
        )

    def setup_individual_frame(self, frame):
        """Configura a aba de criação individual de usuários"""
        # Título
        ttk.Label(frame, text="Copiar objeto - Usuário", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)
        
        # Localização
        ttk.Label(frame, text="O usuário será criado no mesmo local do modelo selecionado", foreground="blue").grid(row=1, column=0, columnspan=2, pady=5)
        
        # Separador
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=10)
        
        # Campos do usuário
        ttk.Label(frame, text="Nome:").grid(row=3, column=0, sticky=tk.W)
        self.first_name = ttk.Entry(frame, width=30)
        self.first_name.grid(row=3, column=1, pady=5, sticky=tk.EW)
        self.first_name.bind("<KeyRelease>", self.update_full_name)
        
        ttk.Label(frame, text="Sobrenome:").grid(row=4, column=0, sticky=tk.W)
        self.last_name = ttk.Entry(frame, width=30)
        self.last_name.grid(row=4, column=1, pady=5, sticky=tk.EW)
        self.last_name.bind("<KeyRelease>", self.update_full_name)
        
        ttk.Label(frame, text="Nome completo:").grid(row=5, column=0, sticky=tk.W)
        self.full_name = ttk.Entry(frame, width=30)
        self.full_name.grid(row=5, column=1, pady=5, sticky=tk.EW)
        self.full_name.bind("<Key>", self.on_full_name_edit)
        self.full_name.bind("<KeyRelease>", self.generate_login_from_fullname)
        
        # Nome de logon
        ttk.Label(frame, text="Nome de logon do usuário:").grid(row=6, column=0, sticky=tk.W)
        logon_frame = ttk.Frame(frame)
        logon_frame.grid(row=6, column=1, sticky=tk.W)
        self.username = ttk.Entry(logon_frame, width=20)
        self.username.pack(side=tk.LEFT)
        ttk.Label(logon_frame, text="@motivabpo.com.br", foreground="gray").pack(side=tk.LEFT, padx=5)
        self.username.bind("<Key>", self.mark_login_edited)
        
        # Nome de logon anterior
        ttk.Label(frame, text="Nome de logon (anterior ao Windows 2000):").grid(row=7, column=0, sticky=tk.W)
        old_logon_frame = ttk.Frame(frame)
        old_logon_frame.grid(row=7, column=1, sticky=tk.W, pady=5)
        ttk.Label(old_logon_frame, text="MOTIVA\\", foreground="gray").pack(side=tk.LEFT)
        self.old_username = ttk.Entry(old_logon_frame, width=20)
        self.old_username.pack(side=tk.LEFT)
        
        # Bind para sincronizar os usernames
        self.username.bind("<KeyRelease>", self.sync_usernames)
        
        # Usuário espelho
        ttk.Label(frame, text="Usuário espelho para cópia:").grid(row=8, column=0, sticky=tk.W)
        
        # Frame para combobox e botão de limpeza
        template_frame = ttk.Frame(frame)
        template_frame.grid(row=8, column=1, pady=5, sticky=tk.EW)
        
        self.template_user = ttk.Combobox(template_frame, width=25)
        self.template_user.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.template_user.set("Digite para pesquisar...")
        self.template_user.bind('<KeyRelease>', self.filter_template_users_with_status)
        
        # Botão de limpar pesquisa
        self.clear_btn = ttk.Button(
            template_frame, 
            text="Limpar", 
            width=8,
            command=self.clear_template_search
        )
        self.clear_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Lista para armazenar todos os modelos
        self.all_template_users = []
        self.template_dns = []        
        self.template_ous = []        
        
        # Vincular evento de digitação para filtragem
        self.template_user.bind('<KeyRelease>', self.filter_template_users)
        
        # Separador para seção de administração
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(
            row=9, column=0, columnspan=2, sticky=tk.EW, pady=10
        )
        
        # Seção de Credenciais do Grupo de TI
        admin_header = ttk.Label(frame, text="Credenciais do Grupo de TI", style="Header.TLabel")
        admin_header.grid(row=10, column=0, columnspan=2, pady=5)
        ttk.Label(frame, text=f"Utilize um usuário de um dos grupos: {', '.join(GRUPOS_PERMITIDOS)}").grid(row=11, column=0, columnspan=2, sticky=tk.W)
        
        ttk.Label(frame, text="Usuário de Rede:").grid(row=12, column=0, sticky=tk.W)
        user_frame = ttk.Frame(frame)
        user_frame.grid(row=12, column=1, sticky=tk.W)
        ttk.Label(user_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.admin_user = ttk.Entry(user_frame, width=25)
        self.admin_user.pack(side=tk.LEFT)
        
        ttk.Label(frame, text="Senha:").grid(row=13, column=0, sticky=tk.W)
        self.admin_password = ttk.Entry(frame, width=30, show="*")
        self.admin_password.grid(row=13, column=1, pady=5, sticky=tk.EW)
        
        # Botão para testar credenciais e permissões
        self.test_btn = ttk.Button(
            frame, 
            text="Verificar Credenciais e Permissões", 
            command=self.verify_ti_credentials
        )
        self.test_btn.grid(row=14, column=0, columnspan=2, pady=10)
        self.connection_status = ttk.Label(frame, text="", font=("Arial", 9))
        self.connection_status.grid(row=15, column=0, columnspan=2)
        
        # Botões
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=16, column=0, columnspan=2, pady=20)
        
        ttk.Button(btn_frame, text="< Voltar", width=10).pack(side=tk.LEFT, padx=5)
        self.create_btn = ttk.Button(
            btn_frame, 
            text="Avançar >", 
            width=10,
            command=self.create_user,
            state=tk.DISABLED
        )
        self.create_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar", width=10, command=self.root.destroy).pack(side=tk.LEFT, padx=5)
        
        # Ajustar colunas
        frame.columnconfigure(1, weight=1)
    
    def filter_template_users_with_status(self, event):
        """filtra os usuários modelo com base no texto digitado e exibe o status"""
        search_term = self.template_user.get().strip().lower()
        if not search_term:
            self.template_user['values'] = self.all_template_users_with_status
            return
        
        filtered = [
            user for user in self.all_template_users_with_status
            if search_term in user.lower()
        ]

        self.template_user['values'] = filtered
        self.status_var.set(f"Mostrando {len(filtered)} de {len(self.all_template_users_with_status)} usuários modelo")

    def setup_mass_import_frame(self, frame):
        """Configura a aba de importação em massa"""
        ttk.Label(frame, text="Importação em Massa via Planilha Excel", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)
        
        # Instruções
        instructions = (
            "Instruções:\n"
            "1. Prepare uma planilha Excel com as colunas: 'Nome', 'Sobrenome', 'Nome Completo', 'Modelo'\n"
            "2. O campo 'Nome Completo' é opcional - se vazio, será gerado automaticamente\n"
            "3. O campo 'Modelo' deve conter o nome completo de um usuário existente\n"
            "4. Clique em 'Selecionar Planilha' para carregar os dados\n"
            "5. Clique em 'Iniciar Importação' para criar todos os usuários"
        )
        ttk.Label(frame, text=instructions, justify=tk.LEFT).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=10)
        
        # Botão para selecionar planilha
        self.select_btn = ttk.Button(
            frame,
            text="Selecionar Planilha",
            command=self.select_spreadsheet
        )
        self.select_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Área de visualização da planilha
        self.tree_frame = ttk.Frame(frame)
        self.tree_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=10)
        
        # Barra de rolagem
        scrollbar = ttk.Scrollbar(self.tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview para mostrar os dados da planilha
        self.tree = ttk.Treeview(
            self.tree_frame, 
            columns=("Nome", "Sobrenome", "Nome Completo", "Modelo", "Status"),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=10
        )
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)
        
        # Configurar colunas
        self.tree.heading("Nome", text="Nome")
        self.tree.heading("Sobrenome", text="Sobrenome")
        self.tree.heading("Nome Completo", text="Nome Completo")
        self.tree.heading("Modelo", text="Modelo")
        self.tree.heading("Status", text="Status")
        
        self.tree.column("Nome", width=100)
        self.tree.column("Sobrenome", width=100)
        self.tree.column("Nome Completo", width=150)
        self.tree.column("Modelo", width=150)
        self.tree.column("Status", width=80)

        self.tree.tag_configure("disabled", foreground="grey")
        self.tree.tag_configure("enabled", foreground="black")

        # Seção de credenciais
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(
            row=4, column=0, columnspan=2, sticky=tk.EW, pady=10
        )
        
        ttk.Label(frame, text="Credenciais do Grupo de TI", style="Header.TLabel").grid(row=5, column=0, columnspan=2, pady=5)
        
        ttk.Label(frame, text="Usuário de Rede:").grid(row=6, column=0, sticky=tk.W)
        user_frame = ttk.Frame(frame)
        user_frame.grid(row=6, column=1, sticky=tk.W)
        ttk.Label(user_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.mass_admin_user = ttk.Entry(user_frame, width=25)
        self.mass_admin_user.pack(side=tk.LEFT)
        
        ttk.Label(frame, text="Senha:").grid(row=7, column=0, sticky=tk.W)
        self.mass_admin_password = ttk.Entry(frame, width=30, show="*")
        self.mass_admin_password.grid(row=7, column=1, pady=5, sticky=tk.EW)
        
        # Botão de verificação de credenciais
        self.mass_test_btn = ttk.Button(
            frame, 
            text="Verificar Credenciais", 
            command=self.verify_mass_credentials
        )
        self.mass_test_btn.grid(row=8, column=0, columnspan=2, pady=10)
        self.mass_connection_status = ttk.Label(frame, text="", font=("Arial", 9))
        self.mass_connection_status.grid(row=9, column=0, columnspan=2)
        
        # Botão de importação
        self.import_btn = ttk.Button(
            frame,
            text="Iniciar Importação",
            command=self.start_mass_import,
            state=tk.DISABLED
        )
        self.import_btn.grid(row=10, column=0, columnspan=2, pady=20)
        
        # Barra de progresso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            frame, 
            orient=tk.HORIZONTAL, 
            length=300, 
            mode='determinate',
            variable=self.progress_var
        )
        self.progress_bar.grid(row=11, column=0, columnspan=2, pady=10)
        
        # Status da importação
        self.import_status = ttk.Label(frame, text="", foreground="blue")
        self.import_status.grid(row=12, column=0, columnspan=2)
        
        # Ajustar colunas
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)

    def setup_move_users_frame(self, frame):
        """Configura a aba para mover usuários entre OUs"""
        ttk.Label(frame, text="Mover Usuários para outra OU", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)
    
        # Seção de pesquisa de usuários
        ttk.Label(frame, text="Pesquisar Usuários:").grid(row=1, column=0, sticky=tk.W)
        self.user_search_var = tk.StringVar()
        user_search_frame = ttk.Frame(frame)
        user_search_frame.grid(row=1, column=1, sticky=tk.EW, pady=5)

        self.user_search_entry = ttk.Entry(user_search_frame, width=30, textvariable=self.user_search_var)
        self.user_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.user_search_entry.bind("<KeyRelease>", self.filter_users)

        ttk.Button(
            user_search_frame, 
            text="Pesquisar", 
            width=10,
            command=self.load_users
        ).pack(side=tk.LEFT, padx=(5, 0))

    # Botão de Refresh
        ttk.Button(
            user_search_frame,
            text="Atualizar",
            width=10,
            command=self.load_users
        ).pack(side=tk.LEFT, padx=(5, 0))
    
    # Lista de usuários com checkboxes
        self.move_users_tree = ttk.Treeview(  # NOME ALTERADO PARA EVITAR CONFLITO
            frame,
            columns=("selected", "username", "ou", "status"),
            show="headings",
            height=8
        )
        self.move_users_tree.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)
    
    # Configurar colunas
        self.move_users_tree.heading("selected", text="Selecionar")
        self.move_users_tree.heading("username", text="Usuário")
        self.move_users_tree.heading("ou", text="OU Atual")
        self.move_users_tree.heading("status", text="Status") 
    
        self.move_users_tree.column("selected", width=80, anchor="center")
        self.move_users_tree.column("username", width=150)
        self.move_users_tree.column("ou", width=250)
        self.move_users_tree.column("status", width=80)

    # Configurar a coluna de status
        self.move_users_tree.tag_configure("disabled", foreground='grey')
        self.move_users_tree.tag_configure("active", foreground='black')
    
    # Vincular evento de clique na coluna de seleção
        self.move_users_tree.bind("<Button-1>", self.on_tree_click)
    
    # Seção de destino
        ttk.Label(frame, text="Mover para OU:").grid(row=3, column=0, sticky=tk.W)
        self.target_ou = ttk.Combobox(frame, width=40)
        self.target_ou.grid(row=3, column=1, pady=5, sticky=tk.EW)
    
    # Seção de credenciais
        ttk.Separator(frame, orient=tk.HORIZONTAL).grid(
            row=4, column=0, columnspan=2, sticky=tk.EW, pady=10
        )
    
        ttk.Label(frame, text="Credenciais do Grupo de TI", style="Header.TLabel").grid(row=5, column=0, columnspan=2, pady=5)
    
        ttk.Label(frame, text="Usuário de Rede:").grid(row=6, column=0, sticky=tk.W)
        move_user_frame = ttk.Frame(frame)
        move_user_frame.grid(row=6, column=1, sticky=tk.W)
        ttk.Label(move_user_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.move_admin_user = ttk.Entry(move_user_frame, width=25)
        self.move_admin_user.pack(side=tk.LEFT)
    
        ttk.Label(frame, text="Senha:").grid(row=7, column=0, sticky=tk.W)
        self.move_admin_password = ttk.Entry(frame, width=30, show="*")
        self.move_admin_password.grid(row=7, column=1, pady=5, sticky=tk.EW)
    
    # Botão de verificação de credenciais
        self.move_test_btn = ttk.Button(
            frame, 
            text="Verificar Credenciais", 
            command=self.verify_move_credentials
        )
        self.move_test_btn.grid(row=8, column=0, columnspan=2, pady=10)
        self.move_connection_status = ttk.Label(frame, text="", font=("Arial", 9))
        self.move_connection_status.grid(row=9, column=0, columnspan=2)
    
    # Botão de mover usuários
        self.move_btn = ttk.Button(
            frame,
            text="Mover Usuários Selecionados",
            command=self.move_selected_users,
            state=tk.DISABLED
        )
        self.move_btn.grid(row=10, column=0, columnspan=2, pady=20)
    
    # Botão de remover usuários
        self.remove_btn = ttk.Button(
            frame,
            text="Remover Usuários Selecionados",
            command=self.remove_selected_users,
            state=tk.NORMAL  # ou tk.DISABLED se quiser controlar por credencial
        )
        self.remove_btn.grid(row=12, column=0, columnspan=2, pady=10)
    
    # Botão de atualizar usuário pelo modelo
        self.update_by_template_btn = ttk.Button(
            frame,
            text="Atualizar Usuário Selecionado pelo Modelo",
            command=self.update_selected_user_by_template,
            state=tk.NORMAL
        )
        self.update_by_template_btn.grid(row=13, column=0, columnspan=2, pady=10)

    # Status da operação
        self.move_status = ttk.Label(frame, text="", foreground="blue")
        self.move_status.grid(row=11, column=0, columnspan=2)
    
    # Armazenar dados
        self.all_users = []
        self.ous_list = []
    
    # Ajustar layout
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(2, weight=1)

    def on_tree_click(self, event):
        """Lida com cliques na coluna de seleção"""
        try:
            # Identificar a região clicada
            region = self.move_users_tree.identify("region", event.x, event.y)
        
            # Verificar se foi clicado na célula da coluna "Selecionar"
            if region == "cell":
                column = self.move_users_tree.identify_column(event.x)
                item = self.move_users_tree.identify_row(event.y)
            
            # A coluna "#1" é a coluna "Selecionar"
                if column == "#1" and item:
                    current_values = list(self.move_users_tree.item(item, "values"))
                    if current_values[0] == "[ ]":
                        current_values[0] = "[X]"
                    else:
                        current_values[0] = "[ ]"
                
                    self.move_users_tree.item(item, values=current_values)
        except Exception as e:
            logging.error(f"Erro ao processar clique na treeview: {str(e)}")

    def filter_users(self, event=None):
        """Filtra a lista de usuários conforme o texto digitado"""
        search_term = self.user_search_var.get().lower()
    
        if not search_term:
            self.move_users_tree.delete(*self.move_users_tree.get_children())
            for user in self.all_users:
                cn, ou, status, is_disabled = user
                tags = ("disabled",) if is_disabled else ("active",)
                self.move_users_tree.insert("", "end", values=("[ ]", cn, ou, status), tags=tags)
            return
    
        filtered = [user for user in self.all_users if search_term in user[0].lower()]
    
        self.move_users_tree.delete(*self.move_users_tree.get_children())
        for user in filtered:
                cn, ou, status, is_disabled = user
                tags = ("disabled",) if is_disabled else ("active",)
                self.move_users_tree.insert("", "end", values=("[ ]", cn, ou, status), tags=tags)

    def load_users(self):
        """Carrega todos os usuários do AD"""
    # Verificar se a conexão está ativa
        if not hasattr(self, 'conn_move') or not self.conn_move.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return
    
        try:
            self.move_status.config(text="Carregando usuários...", foreground="blue")
            self.all_users = []
        
            # Buscar todos os usuários
            self.conn_move.search(
                search_base=BASE_DN,
                search_filter='(&(objectClass=user)(objectCategory=person))',
                attributes=['cn', 'distinguishedName', 'sAMAccountName', 'userAccountControl'],
                search_scope=SUBTREE
            )
        
            for entry in self.conn_move.entries:
                cn = entry.cn.value
                dn = entry.distinguishedName.value
                uac = entry.userAccountControl.value if hasattr(entry, "userAccountControl") else None
            
            # Extrair OU do DN
                ou = self.extract_ou_from_dn(dn)
            
                is_disabled = self.is_account_disabled(uac)
                status = "Desativado" if is_disabled else "Ativo"
            
                self.all_users.append((cn, ou, status, is_disabled))
        
        # Atualizar treeview
            self.move_users_tree.delete(*self.move_users_tree.get_children())
            for user in self.all_users:
                cn, ou, status, is_disabled = user
                tags = ("disabled",) if is_disabled else ("active",)
                self.move_users_tree.insert("", "end", values=("[ ]", cn, ou, status), tags=tags)
        
            self.move_status.config(text=f"{len(self.all_users)} usuários carregados", foreground="green")
        
        except Exception as e:
            error_msg = f"Erro ao carregar usuários: {str(e)}"
            logging.error(error_msg)
            self.move_status.config(text=error_msg, foreground="red")

    def load_ous(self):
        """Carrega todas as OUs do AD"""
        if not hasattr(self, 'conn_move') or not self.conn_move.bound:
            return
        
        try:
            self.ous_list = ["Domínio Raiz"]  # Adicionar opção para raiz
            
            # Buscar todas as OUs
            self.conn_move.search(
                search_base=BASE_DN,
                search_filter='(objectClass=organizationalUnit)',
                attributes=['ou', 'distinguishedName'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn_move.entries:
                ou_name = entry.ou.value
                dn = entry.distinguishedName.value
                self.ous_list.append(dn)
            
            # Atualizar combobox
            self.target_ou['values'] = self.ous_list
            
            return True
        except Exception as e:
            logging.error(f"Erro ao carregar OUs: {str(e)}")
            return False

    def verify_move_credentials(self):
        """Verifica credenciais para mover usuários"""
        username = self.move_admin_user.get().strip()
        password = self.move_admin_password.get()
    
        if not username or not password:
            messagebox.showerror("Erro", "Preencha ambos os campos de usuário e senha")
            return
        
        try:
            # Configurar TLS
            tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_configuration, port=636)
        
        # Tentativa com autenticação SIMPLE
            try:
                conn = Connection(
                    server,
                    user=f"{username}@{DOMINIO_AD}.matriz",
                    password=password,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            except Exception as e:
                logging.error(f"Erro na autenticação SIMPLE: {str(e)}")
            # Fallback para NTLM
                user_ntlm = f"{DOMINIO_AD}\\{username}"
                conn = Connection(
                    server,
                    user=user_ntlm,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
        
        # Armazenar conexão
            self.conn_move = conn
        
        # Carregar OUs
            if self.load_ous():
                self.move_connection_status.config(
                    text=f"✅ Credenciais validadas com sucesso!",
                    style="Success.TLabel"
                )
                self.move_btn.config(state=tk.NORMAL)
                self.move_status.config(text="Credenciais validadas - Pronto para mover usuários", foreground="green")
                logging.info("Credenciais validadas para mover usuários")
            
            # Carregar usuários automaticamente após conexão
                self.load_users()
        
        except Exception as e:
            error_msg = f"Erro: {str(e)}"
            logging.error(f"Falha na verificação de credenciais (mover usuários): {error_msg}")
            self.move_connection_status.config(text=f"❌ {error_msg}", style="Error.TLabel")
            self.move_btn.config(state=tk.DISABLED)
            self.move_status.config(text=error_msg, foreground="red")

    def move_selected_users(self):
        """Move os usuários selecionados para a OU de destino"""
        if not hasattr(self, 'conn_move') or not self.conn_move.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return

        target_ou = self.target_ou.get()
        if not target_ou:
            messagebox.showerror("Erro", "Selecione uma OU de destino")
            return

        selected_users = []
        for item in self.move_users_tree.get_children():
            values = self.move_users_tree.item(item, "values")
            if values and values[0] == "[X]":
                selected_users.append((values[1], values[2]))  # (username, current_ou)

        if not selected_users:
            messagebox.showinfo("Aviso", "Nenhum usuário selecionado")
            return

    # Confirmar ação
        confirm = messagebox.askyesno(
            "Confirmar Movimentação",
            f"Deseja mover {len(selected_users)} usuário(s) para:\n{target_ou}?"
        )
        if not confirm:
            return

    # Verificar e renovar conexão se necessário
        try:
            if not self.conn_move.bound:
                self.verify_move_credentials()
                if not hasattr(self, 'conn_move') or not self.conn_move.bound:
                    raise Exception("Falha ao reconectar ao AD")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha na conexão: {str(e)}")
            return

    # Mover cada usuário
        success_count = 0
        error_count = 0
        log_details = []

        for username, current_ou in selected_users:
            try:
                # Buscar DN completo do usuário
                self.conn_move.search(
                    search_base=BASE_DN,
                    search_filter=f"(cn={escape_rdn(username)})",
                    attributes=['distinguishedName'],
                    search_scope=SUBTREE,
                    size_limit=1
                )
        
                if not self.conn_move.entries:
                    raise Exception(f"Usuário não encontrado: {username}")
        
                user_dn = self.conn_move.entries[0].distinguishedName.value
        
                # Determinar novo DN
                if target_ou == "Domínio Raiz":
                    new_parent = BASE_DN
                else:
                    new_parent = target_ou

            # Extrair CN do DN atual
                cn_part = user_dn.split(',', 1)[0]
                new_dn = f"{cn_part},{new_parent}"
        
            # Mover usuário
                if not self.conn_move.modify_dn(user_dn, cn_part, new_superior=new_parent):
                    error_msg = self.conn_move.last_error or "Erro desconhecido"
                    raise Exception(f"Falha ao mover: {error_msg}")
        
                success_count += 1
                log_details.append(f"✅ {username}: Movido com sucesso para {new_parent}")
            except Exception as e:
                error_count += 1
                error_msg = str(e)
                log_details.append(f"❌ {username}: {error_msg}")
                logging.error(f"Erro ao mover {username}: {error_msg}")

    # Resultado final
        result_msg = (
            f"Movimentação concluída!\n\n"
            f"Total de usuários: {len(selected_users)}\n"
            f"Sucessos: {success_count}\n"
            f"Erros: {error_count}"
        )

    # Criar janela de detalhes
        detail_window = tk.Toplevel(self.root)
        detail_window.title("Detalhes da Movimentação")
        detail_window.geometry("600x400")

        text_frame = ttk.Frame(detail_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_area = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_area.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_area.yview)

        text_area.insert(tk.END, result_msg + "\n\n")
        text_area.insert(tk.END, "\n".join(log_details))
        text_area.config(state=tk.DISABLED)

        ttk.Button(
            detail_window, 
            text="Fechar", 
            command=detail_window.destroy
        ).pack(pady=10)

        self.move_status.config(text=result_msg, foreground="green" if error_count == 0 else "orange")

        # Atualizar lista de usuários após movimentação
        self.load_users()

    def update_full_name(self, event=None):
        """Atualiza o campo Nome completo automaticamente"""
        if not self.full_name_edited:
            first = self.first_name.get().strip()
            last = self.last_name.get().strip()
            full = f"{first} {last}".strip()
            self.full_name.delete(0, tk.END)
            self.full_name.insert(0, full)

    def on_full_name_edit(self, event):
        """Marca o campo como editado manualmente"""
        self.full_name_edited = True

    def mark_login_edited(self, event):
        """Marca que o login foi editado manualmente"""
        self.login_edited = True

    def generate_login_from_fullname(self, event=None):
        """Gera o login de rede automaticamente com base no nome completo"""
        if self.login_edited:
            return
            
        full_name = self.full_name.get().strip()
        if not full_name:
            return
            
        # Gerar login com a regra especificada
        generated_login = self.generate_login(full_name)
        
        # Atualizar o campo de login apenas se for diferente do atual
        current_login = self.username.get().strip()
        if generated_login and generated_login != current_login:
            self.username.delete(0, tk.END)
            self.username.insert(0, generated_login)
            # Forçar sincronização com o campo de login antigo
            self.sync_usernames(None)

    def generate_login(self, full_name):
        """Gera login tratando casos especiais e nomes curtos"""
        if not full_name.strip():
            return ""

        # Normalização mais robusta
        full_name = unicodedata.normalize('NFD', full_name)
        full_name = full_name.encode('ascii', 'ignore').decode('utf-8').lower()
        full_name = re.sub(r'[^a-z\s]', '', full_name)  # Removes special characters
        parts = [p for p in full_name.split() if p]  # Non-empty parts

        if not parts:
            return ""

        # First letter of the first name
        first_letter = parts[0][0] if parts[0] else ""
        login_parts = [first_letter, "_"]

        # Case 1: Very short name (less than 2 parts)
        if len(parts) < 2:
            if len(parts[0]) >= 6:
                login_parts.append(parts[0][:3])
                login_parts.append(parts[0][3:6])
            else:
                base = parts[0].ljust(6, 'x')  # Pads with 'x' if necessary
                login_parts.append(base[:3])
                login_parts.append(base[3:6])
        else:
            # Last surname (at least 3 characters)
            last_part = parts[-1][:3] if len(parts[-1]) >= 3 else parts[-1] + 'x' * (3 - len(parts[-1]))
            
            # First surname (second part)
            if len(parts) >= 2:
                first_last = parts[1][:3] if len(parts[1]) >= 3 else parts[1] + 'x' * (3 - len(parts[1]))
            else:
                first_last = last_part  # Uses last name again
            
            login_parts.append(first_last)
            login_parts.append(last_part)

        return ''.join(login_parts)[:20]  # Limits to 20 characters

    def sync_usernames(self, event):
        """Sincroniza o nome de logon antigo com o novo"""
        new_user = self.username.get()
        if new_user and not self.old_username.get():
            self.old_username.delete(0, tk.END)
            self.old_username.insert(0, new_user)
    
    def clear_template_search(self):
        """Limpa a pesquisa e mostra todos os modelos"""
        self.template_user.set('')
        self.template_user['values'] = self.all_template_users
        if self.all_template_users:
            self.template_user.set("Digite para pesquisar...")
        self.status_var.set(f"{len(self.all_template_users)} modelos disponíveis")
        
    def filter_template_users(self, event):
        """Filtra a lista de modelos enquanto o usuário digita"""
        search_term = self.template_user.get().lower()
        if not search_term:
            self.template_user['values'] = self.all_template_users
            return

        # Filtrar por nome OU login
        filtered = [
            user for user in self.all_template_users
            if search_term in user.lower()
        ]
        self.template_user['values'] = filtered
        self.status_var.set(f"Mostrando {len(filtered)} de {len(self.all_template_users)} modelos")


    def on_statistic_click(self, filter_type):
        if not hasattr(self, 'dashboard_user_data'):
            return
        
        filtered_users = []
        now = datetime.utcnow()

        for user in self.dashboard_user_data:
            status = user["status"]
            last_logon = user["last_logon"]
        
            if filter_type == "disabled":
                if status == "Desativado":
                    filtered_users.append(user)
                
            elif filter_type == "active":
                if status == "Ativo":
                    filtered_users.append(user)
                
            elif filter_type == "never_logged":
                if status == "Ativo" and last_logon == "Nunca":
                    filtered_users.append(user)
                
            elif filter_type == "inactive":
                if status == "Ativo" and last_logon != "Nunca":
                    try:
                        # Converter a string de volta para datetime
                        last_logon_dt = datetime.strptime(last_logon, "%d/%m/%Y %H:%M")
                        if (now - last_logon_dt) > timedelta(days=30):
                            filtered_users.append(user)
                    except ValueError as e:
                        logging.error(f"Erro ao converter data do último logon para o usuário {user['login']}: {e}")
                        continue

        self.update_users_treeview(filtered_users)
        self.dash_status.config(text=f"Filtrado: {len(filtered_users)} usuários", foreground="blue")
    
    def update_users_treeview(self, user_data):
        """Update the users treeview with provided data"""
        for item in self.users_tree.get_children():
            self.users_tree.delete(item)
    
        for user in user_data:
            status = user["status"]
            tags = ()
        
            if status == "Desativado":
                tags = ("disabled",)
            elif user["last_logon"] == "Nunca":
                tags = ("never",)
            elif "inativo" in user and user["inativo"]:
                tags = ("inactive",)
            else:
                tags = ("active",)
            
            self.users_tree.insert("", "end", values=(
                user["cn"],
                user["login"],
                user["ou"],
                status,
                user["last_logon"],
                user["groups"]
            ), tags=tags)
            
        
    def verify_ti_credentials(self):
        """Verifica se o usuário pertence a um dos grupos permitidos e tem permissões"""
        username = self.admin_user.get().strip()
        password = self.admin_password.get()
        
        if not username or not password:
            messagebox.showerror("Erro", "Preencha ambos os campos de usuário e senha")
            return
            
        try:
            # Configurar TLS
            tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_configuration, port=636)
            
            # Tentativa com autenticação SIMPLE
            try:
                conn = Connection(
                    server,
                    user=f"{username}@{DOMINIO_AD}.matriz",
                    password=password,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            except Exception as e:
                logging.error(f"Erro na autenticação SIMPLE: {str(e)}")
                # Fallback para NTLM
                user_ntlm = f"{DOMINIO_AD}\\{username}"
                conn = Connection(
                    server,
                    user=user_ntlm,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
            
            # Buscar o DN do usuário e grupos em todo o diretório
            conn.search(
                search_base=BASE_DN,
                search_filter=f"(sAMAccountName={username})",
                attributes=["memberOf", "distinguishedName"],
                search_scope=SUBTREE
            )
            
            if not conn.entries:
                error_msg = "Usuário não encontrado no diretório"
                logging.error(error_msg)
                raise Exception(error_msg)
            
            user_entry = conn.entries[0]
            user_dn = user_entry.distinguishedName.value
            grupos = user_entry.memberOf.values if hasattr(user_entry, 'memberOf') else []
            
            # Verificar se pertence a um dos grupos permitidos
            grupo_permitido_encontrado = False
            for grupo in grupos:
                # Extrai o nome do grupo do DN completo
                grupo_nome = str(grupo).split(",")[0].split("=")[-1]
                if any(gp.lower() == grupo_nome.lower() for gp in GRUPOS_PERMITIDOS):
                    grupo_permitido_encontrado = True
                    break
            
            if not grupo_permitido_encontrado:
                error_msg = f"Usuário não pertence a nenhum grupo permitido: {', '.join(GRUPOS_PERMITIDOS)}"
                logging.error(error_msg)
                raise Exception(error_msg)
            
            # Buscar usuários modelo em TODO O DIRETÓRIO
            conn.search(
                search_base=BASE_DN,
                search_filter='(&(objectClass=user)(objectCategory=person))',
                attributes=['cn', 'distinguishedName', 'sAMAccountName', 'userAccountControl'],
                search_scope=SUBTREE
            )
            
            if conn.entries:
                # Armazenar DNs completos
                self.template_dns = [entry.distinguishedName.value for entry in conn.entries]
                
                # Armazenar as OUs dos modelos
                self.template_ous = []
                self.all_template_users = []
                self.all_template_users_with_status = []

                for entry in conn.entries:

                    cn = entry.cn.value
                    login = entry.sAMAccountName.value if hasattr(entry, "sAMAccountName") else ""

                    uac = entry.userAccountControl.value if hasattr(entry, "userAccountControl") else None
                    is_disabled = self.is_account_disabled(uac)
                    status_suffix = " (Desativado)" if is_disabled else ""

                    display_text = f"{cn} ({login}) {status_suffix}"

                    self.all_template_users.append(f"{cn} ({login})")
                    self.all_template_users_with_status.append(display_text)

                self.template_user['values'] = self.all_template_users_with_status

                for dn in self.template_dns:
                    # Extrair a OU do DN (tudo após o primeiro CN)
                    parts = dn.split(',')
                    ou_parts = [part for part in parts[1:] if part.startswith('OU=')]
                    self.template_ous.append(','.join(ou_parts))
                
                # Armazenar todos os CNs para filtragem
                self.all_template_users = [
                    f"{entry.cn.value} ({entry.sAMAccountName.value})" if hasattr(entry, "sAMAccountName") else entry.cn.value
                    for entry in conn.entries
                ]
                self.template_user['values'] = self.all_template_users

                # E também armazene os logins para busca reversa:
                self.template_logins = [
                    entry.sAMAccountName.value if hasattr(entry, "sAMAccountName") else ""
                    for entry in conn.entries
                ]
                
                if self.all_template_users:
                    self.status_var.set(f"{len(self.all_template_users)} modelos encontrados")
                    logging.info(f"{len(self.all_template_users)} modelos de usuário encontrados")
                else:
                    self.status_var.set("Nenhum usuário modelo encontrado")
                    logging.warning("Nenhum usuário modelo encontrado")
            else:
                self.status_var.set("Nenhum usuário modelo encontrado")
                logging.warning("Nenhum usuário modelo encontrado")
                self.template_dns = []
                self.template_ous = []
                self.all_template_users = []
                
            # Sucesso - credenciais e permissões válidas
            self.connection_status.config(
                text=f"✅ Usuário validado com sucesso! Pertence a um grupo permitido.",
                style="Success.TLabel"
            )
            self.create_btn.config(state=tk.NORMAL)
            self.status_var.set("Credenciais e permissões validadas - Pronto para criar usuário")
            logging.info("Credenciais validadas com sucesso - usuário pertence a grupo permitido")
                
            conn.unbind()
            
        except Exception as e:
            error_msg = f"Erro: {str(e)}"
            logging.error(f"Falha na verificação de credenciais: {error_msg}")
            self.connection_status.config(text=f"❌ {error_msg}", style="Error.TLabel")
            self.status_var.set(error_msg)
            self.create_btn.config(state=tk.DISABLED)
            self.template_user['values'] = []
            self.all_template_users = []

    def verify_mass_credentials(self):
        """Verifica credenciais para importação em massa"""
        username = self.mass_admin_user.get().strip()
        password = self.mass_admin_password.get()
        
        if not username or not password:
            messagebox.showerror("Erro", "Preencha ambos os campos de usuário e senha")
            return
            
        try:
            # Configurar TLS
            tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_configuration, port=636)
            
            # Tentativa com autenticação SIMPLE
            try:
                conn = Connection(
                    server,
                    user=f"{username}@{DOMINIO_AD}.matriz",
                    password=password,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            except Exception as e:
                logging.error(f"Erro na autenticação SIMPLE: {str(e)}")
                # Fallback para NTLM
                user_ntlm = f"{DOMINIO_AD}\\{username}"
                conn = Connection(
                    server,
                    user=user_ntlm,
                    password=password,
                    authentication=NTLM,
                    auto_bind=True
                )
            
            # Buscar o DN do usuário e grupos em todo o diretório
            conn.search(
                search_base=BASE_DN,
                search_filter=f"(sAMAccountName={username})",
                attributes=["memberOf"],
                search_scope=SUBTREE
            )
            
            if not conn.entries:
                error_msg = "Usuário não encontrado no diretório"
                logging.error(error_msg)
                raise Exception(error_msg)
            
            user_entry = conn.entries[0]
            grupos = user_entry.memberOf.values if hasattr(user_entry, 'memberOf') else []
            
            # Verificar se pertence a um dos grupos permitidos
            grupo_permitido_encontrado = False
            for grupo in grupos:
                # Extrai o nome do grupo do DN completo
                grupo_nome = str(grupo).split(",")[0].split("=")[-1]
                if any(gp.lower() == grupo_nome.lower() for gp in GRUPOS_PERMITIDOS):
                    grupo_permitido_encontrado = True
                    break
            
            if not grupo_permitido_encontrado:
                error_msg = f"Usuário não pertence a nenhum grupo permitido: {', '.join(GRUPOS_PERMITIDOS)}"
                logging.error(error_msg)
                raise Exception(error_msg)
            
            # BUSCAR USUÁRIOS MODELO (ADICIONADO PARA IMPORTÇÃO EM MASSA)
            conn.search(
                search_base=BASE_DN,
                search_filter='(&(objectClass=user)(objectCategory=person))',
                attributes=['cn', 'distinguishedName', 'sAMAccountName', 'userAccountControl'],
                search_scope=SUBTREE
            )
            
            if conn.entries:
                # Armazenar DNs completos
                self.template_dns = [entry.distinguishedName.value for entry in conn.entries]
                
                # Armazenar as OUs dos modelos
                self.template_ous = []
                self.all_template_users = []
                self.all_template_users_with_status = []

                for entry in conn.entries:
                    cn = entry.cn.value
                    login = entry.sAMAccountName.value if hasattr(entry, "sAMAccountName") else ""

                    uac = entry.userAccountControl.value if hasattr(entry, "userAccountControl") else None
                    is_disabled = self.is_account_disabled(uac)
                    status_suffix = " (Desativado)" if is_disabled else ""

                    display_text = f"{cn} ({login}) {status_suffix}"

                    self.all_template_users.append(f"{cn} ({login})")
                    self.all_template_users_with_status.append(display_text)

                for dn in self.template_dns:
                    # Extrair a OU do DN (tudo após o primeiro CN)
                    parts = dn.split(',')
                    ou_parts = [part for part in parts[1:] if part.startswith('OU=')]
                    self.template_ous.append(','.join(ou_parts))
                
                # Armazenar todos os CNs para filtragem
                self.all_template_users = [
                    f"{entry.cn.value} ({entry.sAMAccountName.value})" if hasattr(entry, "sAMAccountName") else entry.cn.value
                    for entry in conn.entries
                ]
                
                if self.all_template_users:
                    self.status_var.set(f"{len(self.all_template_users)} modelos encontrados")
                    logging.info(f"{len(self.all_template_users)} modelos de usuário encontrados")
                else:
                    self.status_var.set("Nenhum usuário modelo encontrado")
                    logging.warning("Nenhum usuário modelo encontrado")
            else:
                self.status_var.set("Nenhum usuário modelo encontrado")
                logging.warning("Nenhum usuário modelo encontrado")
                self.template_dns = []
                self.template_ous = []
                self.all_template_users = []
                
            # Sucesso - credenciais válidas
            self.mass_connection_status.config(
                text=f"✅ Credenciais validadas com sucesso!",
                style="Success.TLabel"
            )

            
            self.import_btn.config(state=tk.NORMAL)
            logging.info("Credenciais validadas com sucesso para importação em massa")

            conn.unbind()
            self.update_template_status_in_treeview()            
            
        except Exception as e:
            error_msg = f"Erro: {str(e)}"
            logging.error(f"Falha na verificação de credenciais (importação em massa): {error_msg}")
            self.mass_connection_status.config(text=f"❌ {error_msg}", style="Error.TLabel")
            self.import_btn.config(state=tk.DISABLED)
        
    
    def update_template_status_in_treeview(self):

        if not hasattr(self, 'import_data'):
            return
        
        for item in self.users_tree.get_children():
            values = self.users_tree.item(item, "values")
            if values and len(values) > 3:
                template_name  = values[3]
                is_disabled = self.is_template_disabled(template_name)
                status = "Desativado" if is_disabled else "Ativo"
                tags = ("disabled",) if is_disabled else ("enabled",)

                new_values = list(values)
                if len(new_values) > 4:
                    new_values[4] = status
                else:
                    new_values.append(status)
                
                self.users_tree.item(item, values=new_values, tags=tags)

    def validate_fields(self):
        """Valida todos os campos do formulário"""
        fields = [
            (self.first_name, "Nome"),
            (self.last_name, "Sobrenome"),
            (self.full_name, "Nome completo"),
            (self.username, "Nome de logon"),
            (self.old_username, "Nome de logon anterior"),
            (self.admin_user, "Usuário do grupo de TI"),
            (self.admin_password, "Senha do usuário")
        ]
        
        for field, name in fields:
            if not field.get().strip():
                messagebox.showerror("Erro", f"O campo '{name}' é obrigatório!")
                return False
        
        # Validação do nome completo (até 64 caracteres)
        full_name = self.full_name.get().strip()
        if len(full_name) > 64:
            messagebox.showerror("Erro", "Nome completo deve ter até 64 caracteres!")
            return False
        
        if not self.template_user.get().strip() or self.template_user.get() == "Digite para pesquisar...":
            messagebox.showerror("Erro", "Selecione um usuário espelho válido!")
            return False
        
        username = self.username.get().strip()
        # Expressão regular atualizada para aceitar underscores (_)
        if not re.match(r"^[a-z0-9\._\-]{3,20}$", username):
            messagebox.showerror("Erro", 
                "Nome de logon inválido! Use apenas:\n"
                "- Letras minúsculas\n"
                "- Números\n"
                "- Pontos (.)\n"
                "- Underscores (_)\n"
                "- Hífens (-)\n"
                "Com 3-20 caracteres.")
            return False
            
        return True

    def check_login_availability(self, conn, login, old_login):
        """Verifica disponibilidade com filtro combinado"""
        search_filter = (
            f"(|"
            f"(sAMAccountName={old_login})"
            f"(userPrincipalName={login}@motivabpo.com.br)"
            f")"
        )
        
        conn.search(
            search_base=BASE_DN,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['1.1'],  # Apenas verifica existência
            size_limit=1
        )
        return not bool(conn.entries)

    def generate_unique_login(self, conn, base_login, old_base_login):
        """Gera um login único com sufixo numérico se necessário"""
        # Tentar o login base primeiro
        if self.check_login_availability(conn, base_login, old_base_login):
            return base_login, old_base_login
        
        # Adicionar sufixo numérico começando de 2
        counter = 2
        while True:
            new_login = f"{base_login}{counter}"
            new_old_login = f"{old_base_login}{counter}"
            
            if self.check_login_availability(conn, new_login, new_old_login):
                return new_login, new_old_login
                
            counter += 1
            
            # Prevenir loop infinito
            if counter > 100:
                messagebox.showerror("Erro", "Não foi possível gerar um login único após 100 tentativas")
                return base_login, old_base_login

    def create_user(self):
        """Cria o novo usuário no LDAP no mesmo local e com os mesmos atributos do modelo"""
        if not self.validate_fields():
            return
            
        try:
            # Configurar TLS
            tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_configuration, port=636)
            
            # Tentativa com autenticação SIMPLE
            try:
                conn = Connection(
                    server,
                    user=f"{self.admin_user.get().strip()}@{DOMINIO_AD}.matriz",
                    password=self.admin_password.get(),
                    authentication=SIMPLE,
                    auto_bind=True
                )
            except Exception as e:
                logging.error(f"Erro na autenticação SIMPLE: {str(e)}")
                # Fallback para NTLM
                user_ntlm = f"{DOMINIO_AD}\\{self.admin_user.get().strip()}"
                conn = Connection(
                    server,
                    user=user_ntlm,
                    password=self.admin_password.get(),
                    authentication=NTLM,
                    auto_bind=True
                )
            
            success_msg = self.create_user_with_connection(conn, 
                self.first_name.get().strip(),
                self.last_name.get().strip(),
                self.full_name.get().strip(),
                self.username.get().strip(),
                self.old_username.get().strip(),
                self.template_user.get()
            )
            
            # Exibir popup de sucesso
            messagebox.showinfo("Sucesso", success_msg)
            
            # Limpar campos após criação bem-sucedida
            self.first_name.delete(0, tk.END)
            self.last_name.delete(0, tk.END)
            self.full_name.delete(0, tk.END)
            self.username.delete(0, tk.END)
            self.old_username.delete(0, tk.END)
            self.admin_password.delete(0, tk.END)
            self.create_btn.config(state=tk.DISABLED)
            self.connection_status.config(text="")
            self.clear_template_search()  # Limpar pesquisa também
            
            # Resetar flags de edição
            self.full_name_edited = False
            self.login_edited = False
            
            conn.unbind()
    
        except Exception as e:
            error_msg = f"Erro: {str(e)}"
            trace = traceback.format_exc()
            logging.error(f"Erro na criação do usuário: {error_msg}\n{trace}")
            self.status_var.set(error_msg)
            messagebox.showerror("Erro", f"Erro detalhado:\n{error_msg}\n\nVerifique o arquivo ldap_user_creator.log para mais informações.")

    def create_user_with_connection(self, conn, first_name, last_name, full_name, username, old_username, template_input):
        """Cria um usuário usando uma conexão LDAP existente"""
        # Permitir busca por nome ou login
        template_input = template_input.strip().lower()
        selected_index = None
        for i, user in enumerate(self.all_template_users):
            if template_input in user.lower():
                selected_index = i
                break
            # Busca direta por login, se disponível
            if hasattr(self, "template_logins") and template_input == self.template_logins[i].lower():
                selected_index = i
                break
        if selected_index is None:
            error_msg = "Selecione um modelo válido da lista!"
            logging.error(error_msg)
            raise Exception(error_msg)
        
        # Obter DN completo do modelo selecionado
        try:
            template_dn = self.template_dns[selected_index]
            template_ou = self.template_ous[selected_index]
            logging.info(f"Modelo selecionado: {template_input} (DN: {template_dn})")
        except ValueError:
            error_msg = "Selecione um modelo válido da lista!"
            logging.error(error_msg)
            raise Exception(error_msg)
        
        # Verificar se o modelo ainda existe
        conn.search(
            search_base=template_dn,
            search_filter='(objectClass=user)',
            attributes=['*', 'memberOf'],
            search_scope=BASE
        )
        
        if not conn.entries:
            error_msg = f"Usuário espelho não encontrado: {template_dn}. O objeto pode ter sido removido."
            logging.error(error_msg)
            raise Exception(error_msg)
            
        template = conn.entries[0]
        self.status_var.set(f"Modelo encontrado: {template.cn.value} (OU: {template_ou})")
        logging.info(f"Modelo encontrado: {template.cn.value} (OU: {template_ou})")
        
        # Converter objectClass para lista de strings
        object_classes = [str(oc) for oc in template.objectClass.values]
        
        # CORREÇÃO: Obter DN completo do container
        container_dn = ",".join(template_dn.split(",")[1:])
        
        # Preparar DN do novo usuário usando a mesma OU do modelo
        full_name_escaped = escape_rdn(full_name)
        new_dn = f"cn={full_name_escaped},{container_dn}"
        
        # Verificar logins originais
        original_login = username
        original_old_login = old_username
        
        # Verificar e gerar logins únicos se necessário
        unique_login, unique_old_login = self.generate_unique_login(
            conn, 
            original_login, 
            original_old_login
        )
        
        # Criar usuário com atributos mínimos essenciais (SEM SENHA)
        attributes = {
            'objectClass': object_classes,
            'cn': full_name,
            'givenName': first_name,
            'sn': last_name,
            'displayName': full_name,
            'sAMAccountName': unique_old_login,
            'userPrincipalName': f"{unique_login}@motivabpo.com.br",
            'mail': f"{unique_login}@motivabpo.com.br",
            'userAccountControl': 544,  # 512 (NORMAL_ACCOUNT) + 32 (PASSWD_NOTREQD)
            'name': full_name,          # Campo obrigatório
            'instanceType': '4',        # Valor padrão necessário
            'accountExpires': '0',       # Nunca expira
        }
        
        logging.info("Tentando criar usuário com atributos mínimos...")
        logging.info(f"DN: {new_dn}")
        logging.info(f"Atributos: {attributes}")
        
        if not conn.add(dn=new_dn, attributes=attributes):
            error_msg = (
                f"Erro ao criar usuário: {conn.last_error}\n"
                f"Código: {conn.result['result']}\n"
                f"Mensagem: {conn.result['message']}\n"
                f"Detalhes: {conn.result['description']}"
            )
            
            logging.error(f"Resultado completo: {conn.result}")
            self.status_var.set(error_msg)
            raise Exception(error_msg)
        
        logging.info(f"Usuário criado com sucesso: {new_dn}")
        
        # CORREÇÃO: Definir senha em operação separada
        password_value = '!@123456Aa'.encode('utf-16-le')
        if not conn.modify(new_dn, {'unicodePwd': [(MODIFY_REPLACE, [password_value])]}):
            error_msg = f"Erro ao definir senha: {conn.last_error}"
            logging.error(error_msg)
        else:
            logging.info("Senha definida com sucesso")
        
        # Atualizar flags da conta
        if not conn.modify(new_dn, {
            'userAccountControl': [(MODIFY_REPLACE, [512])],  # Normal account
            'pwdLastSet': [(MODIFY_REPLACE, [0])]             # Forçar troca de senha
        }):
            error_msg = f"Erro ao atualizar flags da conta: {conn.last_error}"
            logging.warning(error_msg)
        else:
            logging.info("Flags da conta atualizadas com sucesso")
        
        # Lista de atributos que NÃO devem ser copiados (atributos de sistema)
        atributos_nao_copiar = [
            # Atributos básicos controlados
            'objectClass', 'cn', 'givenName', 'sn', 'displayName',
            'sAMAccountName', 'userPrincipalName', 'mail',
            'userAccountControl', 'unicodePwd', 'userPassword',
            
            # Atributos de segurança
            'pwdLastSet', 'lastLogon', 'lastLogoff', 'badPasswordTime',
            'badPwdCount', 'lockoutTime', 'lockOutObservationWindow',
            'nTSecurityDescriptor', 'objectGUID', 'objectSid',
            'primaryGroupID', 'adminCount',
            
            # Atributos de replicação e metadados
            'dScorePropagationData', 'd3CorePropagationData', 'd5CorePropagationData',
            'uSNCreated', 'uSNChanged', 'whenCreated', 'whenChanged',
            'replPropertyMetaData', 'replUpToDateVector',
            'instanceType', 'isCriticalSystemObject', 
            'showInAdvancedViewOnly', 'creationTime',
            
            # Atributos específicos de serviços
            'msDS-UserPasswordExpiryTimeComputed', 
            'accountExpires', 'msExchMailboxGuid',
            'msRTCSIP-UserRoutingGroupId', 'msRTCSIP-PrimaryUserAddress',
            'msExchRecipientTypeDetails', 'msExchVersion',
            
            # Outros atributos internos
            'objectCategory', 'codePage', 'countryCode',
            'logonCount', 'forceLogoff', 'lastLogonTimestamp',
            'logonHours', 'userWorkstations', 'operatingSystem',
            'operatingSystemVersion', 'operatingSystemServicePack',
            'gPCFileSysPath', 'gPCMachineExtensionNames',
            'gPCUserExtensionNames', 'flags', 'r'
        ]
        
        # Converter para conjunto de nomes em minúsculas para verificação insensível a maiúsculas
        atributos_nao_copiar_set = {attr.lower() for attr in atributos_nao_copiar}
        
        # Copiar todos os outros atributos do modelo em operações separadas
        logging.info("Copiando atributos adicionais do modelo...")
        for attr_name in template.entry_attributes:
            # Pular atributos que não devem ser copiados, comparando em minúsculas
            if attr_name.lower() in atributos_nao_copiar_set:
                continue
            
            # Obter o valor do atributo
            attr_value = template[attr_name].value
            
            # Ignorar valores vazios ou nulos
            if attr_value is None or attr_value == '':
                continue
            
            # Tratar listas (atributos multi-valor)
            if isinstance(attr_value, list):
                # Filtrar valores nulos e vazios
                clean_values = [v for v in attr_value if v is not None and v != '']
                if clean_values:
                    changes = {attr_name: [(MODIFY_REPLACE, clean_values)]}
                    if not conn.modify(new_dn, changes):
                        logging.warning(f"Falha ao copiar atributo {attr_name}: {conn.last_error}")
                    else:
                        logging.info(f"Atributo copiado (multivalor): {attr_name}")
            else:
                # Converter apenas se não for nulo
                if attr_value is not None and attr_value != '':
                    changes = {attr_name: [(MODIFY_REPLACE, [attr_value])]}
                    if not conn.modify(new_dn, changes):
                        logging.warning(f"Falha ao copiar atributo {attr_name}: {conn.last_error}")
                    else:
                        logging.info(f"Atributo copiado: {attr_name}")
        
        # --- COPIAR GRUPOS (memberOf) DO MODELO ---
        total_grupos = 0
        grupos_copiados = 0
        grupos_falhas = []
        
        # Verificar se o modelo possui grupos
        if hasattr(template, 'memberOf') and template.memberOf.values:
            grupos_modelo = template.memberOf.values
            total_grupos = len(grupos_modelo)
            logging.info(f"Iniciando cópia de {total_grupos} grupos do modelo")

            # Adicionar novo usuário a cada grupo
            for grupo_dn in grupos_modelo:
                try:
                    # Tentar adicionar ao grupo
                    changes = {'member': [(MODIFY_ADD, [new_dn])]}
                    if conn.modify(grupo_dn, changes):
                        logging.info(f"Usuário adicionado ao grupo {grupo_dn}")
                        grupos_copiados += 1
                    else:
                        erro_grupo = f"{conn.last_error} (Código: {conn.result['result']})"
                        logging.warning(f"Falha ao adicionar ao grupo {grupo_dn}: {erro_grupo}")
                        grupos_falhas.append(f"{grupo_dn} - {erro_grupo}")
                except Exception as e:
                    erro_msg = str(e)
                    logging.error(f"Erro ao adicionar ao grupo {grupo_dn}: {erro_msg}")
                    grupos_falhas.append(f"{grupo_dn} - {erro_msg}")

            logging.info(f"Grupos copiados: {grupos_copiados}/{total_grupos}")
        else:
            logging.info("O modelo não possui grupos associados")

        # Mensagem de sucesso final
        success_msg = (
            f"Usuário criado com sucesso!\n\n"
            f"Nome: {full_name}\n"
            f"Logon: {unique_login}@motivabpo.com.br\n"
            f"Logon anterior: MOTIVA\\{unique_old_login}\n"
            f"Local: {container_dn}\n"
            f"DN: {new_dn}\n\n"
            f"Senha inicial: !@123456Aa (deve ser alterada no primeiro logon)"
        )
        logging.info(success_msg)
        return success_msg  # Retornar a mensagem para exibir no popup

    def select_spreadsheet(self):
        """Seleciona um arquivo Excel para importação em massa"""
        file_path = filedialog.askopenfilename(
            title="Selecione a planilha Excel",
            filetypes=[("Excel Files", "*.xlsx *.xls")]
        )
        
        if not file_path:
            return
            
        try:
            # Ler a planilha Excel
            df = pd.read_excel(file_path)
            
            # Verificar colunas obrigatórias
            required_columns = ['Nome', 'Sobrenome', 'Modelo']
            missing_columns = [col for col in required_columns if col not in df.columns]
            
            if missing_columns:
                messagebox.showerror("Erro", f"Colunas obrigatórias faltando: {', '.join(missing_columns)}")
                return
            
            # Limpeza de dados críticos
            df = df.dropna(subset=['Nome', 'Sobrenome', 'Modelo'])
            df = df.fillna('')
                
            # Preencher nome completo se não existir
            if 'Nome Completo' not in df.columns:
                df['Nome Completo'] = df['Nome'] + ' ' + df['Sobrenome']
            
            # Limpar a treeview
            for item in self.tree.get_children():
                self.tree.delete(item)
            
            self.import_data = df  # Armazenar os dados para processamento posterior
            has_valid_conn = hasattr(self, 'conn_mass') and self.conn_mass.bound
                
            # Adicionar dados à treeview
            for _, row in df.iterrows():
                template = str(row['Modelo']).strip()
                status = ""
                tags = ""

                if has_valid_conn:
                # Verificar status do modelo
                    is_disabled = self.is_template_disabled(template)
                    status = "Desabilitado" if is_disabled else "Ativo"
                    tags = ('disabled',) if is_disabled else ('enabled',)
                
                self.tree.insert("", "end", values=(
                    row['Nome'],
                    row['Sobrenome'],
                    row.get('Nome Completo', ''),
                    template,
                    status
                ), tags=tags)
                
            # Armazenar os dados para processamento
            self.import_data = df
            self.import_status.config(text=f"Planilha carregada com {len(df)} usuários")

            if not has_valid_conn:
                self.import_status.config(
                    text="Valide as credenciais para verificar status dos modelos", foreground="red")
            
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao ler a planilha: {str(e)}")
            logging.error(f"Erro ao ler planilha: {str(e)}")

    def is_template_disabled(self, template_name):
        """Verifica se um modelo está desabilitado com base na lista carregada"""
        if not hasattr(self, 'all_template_users_with_status'):
            return False
            
        # Procurar pelo nome do modelo na lista de modelos com status
        for template in self.all_template_users_with_status:
            # O formato é "Nome (login) [STATUS]"
            # Extrair apenas a parte do nome para comparação
            base_name = template.split(' (')[0].strip()
            
            # Verificar se o nome corresponde e se está desabilitado
            if template_name.strip() == base_name and "DESABILITADO" in template:
                return True
        return False
    
    def update_import_progress(self, current, success, errors):
        """Atualiza a barra de progresso e status da importação"""
        self.progress_var.set(current)
        self.import_status.config(
            text=f"Processando: {current}/{self.import_total} | Sucessos: {success} | Erros: {errors}"
        )

    def start_mass_import(self):
        """Inicia o processo de importação em massa"""
        if not hasattr(self, 'import_data') or self.import_data.empty:
            messagebox.showwarning("Aviso", "Nenhuma planilha carregada ou dados vazios")
            return
            
        # Desabilitar botões durante a importação
        self.select_btn.config(state=tk.DISABLED)
        self.import_btn.config(state=tk.DISABLED)
        self.mass_test_btn.config(state=tk.DISABLED)
        
        # Configurar progresso
        self.import_total = len(self.import_data)
        self.progress_var.set(0)
        self.progress_bar["maximum"] = self.import_total
        self.import_status.config(text=f"Iniciando importação de {self.import_total} usuários...")
        
        # Obter credenciais
        admin_user = self.mass_admin_user.get().strip()
        admin_password = self.mass_admin_password.get()
        
        if not admin_user or not admin_password:
            messagebox.showerror("Erro", "Preencha as credenciais de administrador")
            return
            
        # Iniciar thread de importação
        threading.Thread(
            target=self.mass_import_thread,
            args=(admin_user, admin_password),
            daemon=True
        ).start()

    def mass_import_thread(self, admin_user, admin_password):
        """Thread para processar a importação em massa"""
        try:
            # Configurar TLS
            tls_configuration = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_configuration, port=636)
            
            # Tentativa com autenticação SIMPLE
            try:
                conn = Connection(
                    server,
                    user=f"{admin_user}@{DOMINIO_AD}.matriz",
                    password=admin_password,
                    authentication=SIMPLE,
                    auto_bind=True
                )
            except Exception as e:
                logging.error(f"Erro na autenticação SIMPLE: {str(e)}")
                # Fallback para NTLM
                user_ntlm = f"{DOMINIO_AD}\\{admin_user}"
                conn = Connection(
                    server,
                    user=user_ntlm,
                    password=admin_password,
                    authentication=NTLM,
                    auto_bind=True
                )
            
            # Processar cada linha da planilha
            success_count = 0
            error_count = 0
            log_entries = []  # Lista para logs estruturados
            
            for i, row in self.import_data.iterrows():
                try:
                    # CORREÇÃO: Tratar valores NaN/empty
                    first_name = str(row['Nome']).strip() if pd.notna(row['Nome']) else ''
                    last_name = str(row['Sobrenome']).strip() if pd.notna(row['Sobrenome']) else ''
                    full_name = str(row.get('Nome Completo', '')).strip() if pd.notna(row.get('Nome Completo', '')) else ''
                    template_cn = str(row['Modelo']).strip() if pd.notna(row['Modelo']) else ''

                    # CORREÇÃO: Gerar nome completo se necessário
                    if not full_name:
                        full_name = f"{first_name} {last_name}".strip()
                        if not full_name:
                            raise Exception("Nome completo não pode ser vazio")
                            
                    # Validar modelo
                    if template_cn not in self.all_template_users:
                        raise Exception(f"Modelo inválido: {template_cn}")
                    
                    # Gerar login automaticamente
                    login = self.generate_login(full_name)
                    
                    # Criar usuário
                    result = self.create_user_with_connection(
                        conn,
                        first_name,
                        last_name,
                        full_name,
                        login,
                        login,
                        template_cn
                    )
                    
                    success_count += 1
                    # Adicionar entrada de log de sucesso
                    log_entries.append({
                        "Linha": i+1,
                        "Nome Completo": full_name,
                        "Login": login,
                        "Modelo": template_cn,
                        "Status": "Sucesso",
                        "Mensagem": "Usuário criado com sucesso"
                    })
                    
                except Exception as e:
                    error_count += 1
                    error_msg = str(e)
                    # Adicionar entrada de log de erro
                    log_entries.append({
                        "Linha": i+1,
                        "Nome Completo": full_name,
                        "Login": login if 'login' in locals() else '',
                        "Modelo": template_cn,
                        "Status": "Erro",
                        "Mensagem": error_msg
                    })
                    logging.error(f"Erro ao criar {full_name}: {error_msg}")
                
                # Atualizar progresso
                self.root.after(100, self.update_import_progress, i+1, success_count, error_count)
                
                # Pequena pausa para atualizar a interface
                self.root.update_idletasks()
            
            # Salvar logs em múltiplos formatos
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"import_log_{timestamp}"
            
            # 1. Salvar em CSV
            csv_filename = f"{base_filename}.csv"
            df_log = pd.DataFrame(log_entries)
            df_log.to_csv(csv_filename, index=False, encoding='utf-8-sig')
            
            # 2. Salvar em Excel (XLSX)
            xlsx_filename = f"{base_filename}.xlsx"
            df_log.to_excel(xlsx_filename, index=False)
            
            # Mensagem final
            result_msg = (
                f"Importação concluída!\n\n"
                f"Total de usuários: {self.import_total}\n"
                f"Sucessos: {success_count}\n"
                f"Erros: {error_count}\n\n"
                f"Logs salvos em:\n"
                f"- CSV: {os.path.abspath(csv_filename)}\n"
                f"- Excel: {os.path.abspath(xlsx_filename)}"
            )
            
            self.import_status.config(text=result_msg)
            messagebox.showinfo("Importação Concluída", result_msg)
            
            conn.unbind()
            
        except Exception as e:
            logging.error(f"Erro na importação em massa: {str(e)}")
        finally:
            # Reabilitar botões
            self.select_btn.config(state=tk.NORMAL)
            self.import_btn.config(state=tk.NORMAL)
            self.mass_test_btn.config(state=tk.NORMAL)

    def remove_selected_users(self):
        """Remove os usuários selecionados do AD"""
        if not hasattr(self, 'conn_move') or not self.conn_move.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return

        selected_users = []
        for item in self.users_tree.get_children():
            values = self.users_tree.item(item, "values")
            if values and values[0] == "[X]":
                selected_users.append(values[1])  # username

        if not selected_users:
            messagebox.showinfo("Aviso", "Nenhum usuário selecionado")
            return

        confirm = messagebox.askyesno(
            "Confirmar Remoção",
            f"Deseja remover {len(selected_users)} usuário(s) do AD?\nEsta ação não pode ser desfeita."
        )
        if not confirm:
            return

        success_count = 0
        error_count = 0
        log_details = []

        for username in selected_users:
            try:
                # Buscar DN do usuário
                self.conn_move.search(
                    search_base=BASE_DN,
                    search_filter=f"(cn={username})",
                    attributes=['distinguishedName'],
                    search_scope=SUBTREE
                )
                if not self.conn_move.entries:
                    raise Exception(f"Usuário não encontrado: {username}")

                user_dn = self.conn_move.entries[0].distinguishedName.value

                # Remover usuário
                if not self.conn_move.delete(user_dn):
                    error_msg = self.conn_move.last_error
                    raise Exception(f"Falha ao remover: {error_msg}")

                success_count += 1
                log_details.append(f"✅ {username}: Removido com sucesso")
            
            except Exception as e:
                error_count += 1
                log_details.append(f"❌ {username}: {str(e)}")
                logging.error(f"Erro ao remover {username}: {str(e)}")

        # Mostrar resultado
        result_msg = (
            f"Remoção concluída!\n\n"
            f"Total de usuários: {len(selected_users)}\n"
            f"Sucessos: {success_count}\n"
            f"Erros: {error_count}"
        )

        # Janela de detalhes
        detail_window = tk.Toplevel(self.root)
        detail_window.title("Detalhes da Remoção")
        detail_window.geometry("600x400")

        text_frame = ttk.Frame(detail_window)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_area = tk.Text(text_frame, wrap=tk.WORD, yscrollcommand=scrollbar.set)
        text_area.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=text_area.yview)

        text_area.insert(tk.END, result_msg + "\n\n")
        text_area.insert(tk.END, "\n".join(log_details))
        text_area.config(state=tk.DISABLED)

        ttk.Button(
            detail_window,
            text="Fechar",
            command=detail_window.destroy
        ).pack(pady=10)

        self.move_status.config(text=result_msg, foreground="green" if error_count == 0 else "orange")

        # Atualizar lista de usuários após remoção
        self.load_users()

    def update_user_from_template(self, conn, target_username, template_input):
        """Atualiza um usuário existente com base em um modelo"""
        # Buscar DN do usuário de destino
        conn.search(
            search_base=BASE_DN,
            search_filter=f"(|(cn={target_username})(sAMAccountName={target_username}))",
            attributes=['distinguishedName'],
            search_scope=SUBTREE
        )
        if not conn.entries:
            raise Exception(f"Usuário de destino não encontrado: {target_username}")
        user_dn = conn.entries[0].distinguishedName.value

        # Buscar modelo (igual create_user_with_connection)
        template_input = template_input.strip().lower()
        selected_index = None
        for i, user in enumerate(self.all_template_users):
            # Permitir busca por nome, login ou ambos
            if template_input in user.lower():
                selected_index = i
                break
            # Busca direta por login, se disponível
            if hasattr(self, "template_logins") and template_input == self.template_logins[i].lower():
                selected_index = i
                break
        if selected_index is None:
            raise Exception("Modelo não encontrado na lista!")

        template_dn = self.template_dns[selected_index]
        conn.search(
            search_base=template_dn,
            search_filter='(objectClass=user)',
            attributes=['*', 'memberOf'],

            search_scope=BASE
        )
        if not conn.entries:
            raise Exception(f"Modelo não encontrado: {template_dn}")
        template = conn.entries[0]

        # Lista de atributos que NÃO devem ser copiados
        atributos_nao_copiar = [
            'objectClass', 'cn', 'givenName', 'sn', 'displayName',
            'sAMAccountName', 'userPrincipalName', 'mail',
            'userAccountControl', 'unicodePwd', 'userPassword',
            'pwdLastSet', 'lastLogon', 'lastLogoff', 'badPasswordTime',
            'badPwdCount', 'lockoutTime', 'lockOutObservationWindow',
            'nTSecurityDescriptor', 'objectGUID', 'objectSid',
            'primaryGroupID', 'adminCount',
            'dScorePropagationData', 'd3CorePropagationData', 'd5CorePropagationData',
            'uSNCreated', 'uSNChanged', 'whenCreated', 'whenChanged',
            'replPropertyMetaData', 'replUpToDateVector',
            'instanceType', 'isCriticalSystemObject', 
            'showInAdvancedViewOnly', 'creationTime',
            'msDS-UserPasswordExpiryTimeComputed', 
            'accountExpires', 'msExchMailboxGuid',
            'msRTCSIP-UserRoutingGroupId', 'msRTCSIP-PrimaryUserAddress',
            'msExchRecipientTypeDetails', 'msExchVersion',
            'objectCategory', 'codePage', 'countryCode',
            'logonCount', 'forceLogoff', 'lastLogonTimestamp',
            'logonHours', 'userWorkstations', 'operatingSystem',
            'operatingSystemVersion', 'operatingSystemServicePack',
            'gPCFileSysPath', 'gPCMachineExtensionNames',
            'gPCUserExtensionNames', 'flags', 'r'
        ]
        atributos_nao_copiar_set = {attr.lower() for attr in atributos_nao_copiar}

        # Copiar atributos do modelo para o usuário de destino
        for attr_name in template.entry_attributes:
            if attr_name.lower() in atributos_nao_copiar_set:
                continue
            attr_value = template[attr_name].value
            if attr_value is None or attr_value == '':
                continue
            if isinstance(attr_value, list):
                clean_values = [v for v in attr_value if v is not None and v != '']
                if clean_values:
                    changes = {attr_name: [(MODIFY_REPLACE, clean_values)]}
                    conn.modify(user_dn, changes)
            else:
                changes = {attr_name: [(MODIFY_REPLACE, [attr_value])]}
                conn.modify(user_dn, changes)

        return f"Usuário {target_username} atualizado com sucesso com base no modelo '{self.all_template_users[selected_index]}'."  # Mostra o nome do modelo encontrado
    
    def update_selected_user_by_template(self):
        """Atualiza o usuário selecionado com base em um modelo (usando Combobox)"""
        if not hasattr(self, 'conn_move') or not self.conn_move.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return

        if not self.all_template_users:
            messagebox.showerror("Erro", "Nenhum modelo disponível. Valide as credenciais na aba de criação individual primeiro.")
            return

        # Pega o usuário selecionado
        selected = [
            self.users_tree.item(item, "values")[1]
            for item in self.users_tree.get_children()
            if self.users_tree.item(item, "values")[0] == "[X]"
        ]
        if not selected:
            messagebox.showinfo("Aviso", "Selecione um usuário para atualizar")
            return
        if len(selected) > 1:
            messagebox.showinfo("Aviso", "Selecione apenas um usuário para atualizar")
            return

        username = selected[0]

        # --- Nova janela para seleção do modelo ---
        top = tk.Toplevel(self.root)
        top.title("Selecionar Modelo")
        top.geometry("400x150")
        ttk.Label(top, text="Selecione o modelo para copiar os atributos:").pack(pady=10)

        model_var = tk.StringVar()
        model_combo = ttk.Combobox(top, textvariable=model_var, values=self.all_template_users, width=40, state="normal")
        model_combo.pack(pady=5)
        if self.all_template_users:
            model_combo.current(0)

        # Filtro dinâmico para o Combobox (opcional, mas útil)
        def filter_models(event):
            search = model_var.get().lower()
            if not search:
                model_combo['values'] = self.all_template_users
                return
            filtered = [u for u in self.all_template_users if search in u.lower()]
            model_combo['values'] = filtered if filtered else self.all_template_users

        model_combo.bind('<KeyRelease>', filter_models)

        def on_confirm():
            template = model_var.get()
            # Tenta encontrar o modelo na lista, mesmo se o usuário digitou e não selecionou
            selected_index = None
            for i, user in enumerate(self.all_template_users):
                if template.strip().lower() == user.lower():
                    selected_index = i
                    break
            if selected_index is None:
                messagebox.showerror("Erro", "Selecione um modelo válido!", parent=top)
                return
            try:
                msg = self.update_user_from_template(self.conn_move, username, self.all_template_users[selected_index])
                messagebox.showinfo("Sucesso", msg, parent=top)
                self.load_users()
                top.destroy()
            except Exception as e:
                logging.error(f"Erro ao atualizar usuário: {str(e)}")
                messagebox.showerror("Erro", str(e), parent=top)

        ttk.Button(top, text="Atualizar", command=on_confirm).pack(pady=10)
        top.transient(self.root)
        top.grab_set()
        self.root.wait_window(top)

if __name__ == "__main__":
    root = tk.Tk()
    app = LDAPUserCreator(root)
    root.mainloop()