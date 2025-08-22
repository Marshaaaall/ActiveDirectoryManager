import tkinter as tk
from tkinter import ttk, messagebox
from ldap3 import Server, Connection, SUBTREE, Tls, NTLM, SIMPLE
import ssl
import logging
from datetime import datetime, timedelta
from datetime import timezone
import threading

# Configurações do servidor LDAP
DOMINIO_AD = "MOTIVA"
SERVIDOR_AD = "10.100.0.10"
BASE_DN = "dc=motiva,dc=matriz"
GRUPOS_INTERNET = [
    "g_fg_analistas_ti",
    "Admins. do domínio",
]

class DashboardFrame(ttk.Frame):  # Agora herda de ttk.Frame
    def __init__(self, parent):
        super().__init__(parent)  # Chama o construtor do ttk.Frame
        self.parent = parent
        
        # Variáveis para armazenar dados
        self.dashboard_user_data = []
        
        # Configurar interface
        self.setup_dashboard_frame()
        
    def setup_dashboard_frame(self):
        """Configura a aba de dashboard com informações do AD"""
        ttk.Label(self, text="Dashboard - Informações do Active Directory", 
                 font=("Arial", 11, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

        cred_frame = ttk.Frame(self)
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
            command=self.update_dashboard  # Agora está correto
        )
        self.dash_refresh_btn.pack(side=tk.LEFT, padx=(10, 0))

        self.dash_status = ttk.Label(self, text="", font=("Arial", 9), foreground="blue")
        self.dash_status.grid(row=2, column=0, columnspan=2, pady=5)

        # Resto do código permanece igual...
        # frame principal para exibir dados
        data_frame = ttk.Frame(self)
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
        
        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)
    
    def update_dashboard(self):
        """Atualiza os dados do dashboard"""
        username = self.dash_admin_user.get().strip()
        password = self.dash_admin_password.get()

        if not username or not password:
            messagebox.showerror("Erro", "Preencha ambos os campos de usuário e senha")
            return
    
        self.dash_status.config(text="Conectando...")
        self.dash_refresh_btn.config(state=tk.DISABLED)
        
        # Obter a janela principal para atualizações da interface
        root = self.winfo_toplevel()
        threading.Thread(target=self.dashboard_thread, args=(username, password, root), daemon=True).start()

    def dashboard_thread(self, username, password, root):
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
            root.after(0, lambda: self.dash_status.config(text="Coletando dados...", foreground="blue"))
        
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
            
                # Processamento do último logon com tratamento de timezone
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
                    
                        # Usar UTC para ambos os lados da comparação
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
                    root.after(0, lambda i=i, total=total_users: 
                        self.dash_status.config(text=f"Processando {i+1}/{total} usuários...", foreground="blue")
                    )
        
            # Ordenar distribuição por OU
            sorted_ou = sorted(ou_distribution.items(), key=lambda x: x[1], reverse=True)
        
            # Atualizar UI com chamada correta
            root.after(0, lambda: self.update_dashboard_ui(
                total_users, disabled_count, active_count, 
                never_logged_count, inactive_count,
                sorted_ou, internet_groups, user_data
            ))

            conn.unbind()
            root.after(0, lambda: self.dash_status.config(text="Dados atualizados com sucesso!", foreground="green"))
        
        except Exception as e:
            error_msg = f"Erro ao atualizar dashboard: {str(e)}"
            logging.error(error_msg)
            root.after(0, lambda: self.dash_status.config(text=error_msg, foreground="red"))
        finally:
            root.after(0, lambda: self.dash_refresh_btn.config(state=tk.NORMAL))
    
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

# Exemplo de uso standalone (para testar o dashboard isoladamente)
if __name__ == "__main__":
    root = tk.Tk()
    root.title("Dashboard AD")
    root.geometry("1100x700")
    
    dashboard = DashboardFrame(root)
    dashboard.pack(fill=tk.BOTH, expand=True)
    
    root.mainloop()