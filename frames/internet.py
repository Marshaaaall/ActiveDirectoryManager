import tkinter as tk
from tkinter import ttk, messagebox
from ldap3 import MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE, SUBTREE
import threading
import logging
from ldap_utils import conectar_ldap, extract_ou_from_dn, is_account_disabled, obter_configuracao

class PasswordResetDialog(tk.Toplevel):
    def __init__(self, parent, username):
        super().__init__(parent)
        self.title(f"Redefinir senha - {username}")
        self.geometry("500x300")
        self.resizable(False, False)
        self.username = username
        self.result = None
        
        self.create_widgets()
        self.grab_set()
        self.focus_force()
        
    def create_widgets(self):
        # Título
        ttk.Label(self, text="Redefinir senha", font=("Arial", 12, "bold")).pack(pady=10)
        
        # Nova senha
        ttk.Label(self, text="Nova senha:").pack(anchor=tk.W, padx=20)
        self.new_password = ttk.Entry(self, show="*", width=30)
        self.new_password.pack(padx=20, pady=5, fill=tk.X)
        
        # Confirmar senha
        ttk.Label(self, text="Confirmar senha:").pack(anchor=tk.W, padx=20)
        self.confirm_password = ttk.Entry(self, show="*", width=30)
        self.confirm_password.pack(padx=20, pady=5, fill=tk.X)
        
        # Checkbox para alterar senha no próximo logon
        self.must_change = tk.BooleanVar()
        ttk.Checkbutton(self, text="O usuário deve alterar a senha no próximo logon", 
                       variable=self.must_change).pack(anchor=tk.W, padx=20, pady=10)
        
        # Texto informativo
        ttk.Label(self, text="O usuário deve fazer logoff e fazer logon novamente para que a alteração entre em vigor.", 
                 font=("Arial", 8), foreground="gray").pack(anchor=tk.W, padx=20)
        
        # Status de bloqueio
        ttk.Label(self, text="Status de Bloqueio da Conta neste Controlador de Domínio: Desbloqueado").pack(anchor=tk.W, padx=20, pady=10)
        
        # Checkbox desbloquear conta
        self.unlock_account = tk.BooleanVar()
        ttk.Checkbutton(self, text="Desbloquear a conta do usuário", 
                       variable=self.unlock_account).pack(anchor=tk.W, padx=20, pady=5)
        
        # Botões
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=20)
        
        ttk.Button(btn_frame, text="OK", command=self.on_ok).pack(side=tk.LEFT, padx=10)
        ttk.Button(btn_frame, text="Cancelar", command=self.destroy).pack(side=tk.LEFT, padx=10)
    
    def on_ok(self):
        new_pwd = self.new_password.get()
        confirm_pwd = self.confirm_password.get()
        
        if not new_pwd or not confirm_pwd:
            messagebox.showerror("Erro", "Preencha ambos os campos de senha")
            return
            
        if new_pwd != confirm_pwd:
            messagebox.showerror("Erro", "As senha não coincidem")
            return
            
        self.result = {
            'new_password': new_pwd,
            'must_change': self.must_change.get(),
            'unlock_account': self.unlock_account.get()
        }
        self.destroy()

class InternetGroupsFrame(ttk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent)
        self.root = root
        
        self.conn = None
        self.all_users = []
        self.internet_groups = []
        self.user_details = {}
        self.selected_user = None
        self.selected_users_set = set()
        
        # Carrega as configurações iniciais
        self.config = obter_configuracao()
        self.dominio_ad = self.config['DOMINIO_AD']
        self.base_dn = self.config['BASE_DN']
        self.internet_group_attribute = self.config.get('INTERNET_GROUP_ATTRIBUTE', 'memberOf')
        
        self._setup_ui()
        
    def _setup_ui(self):
        # Título
        ttk.Label(self, text="Gerenciamento de Grupos de Internet", font=("Arial", 14, "bold")).grid(
            row=0, column=0, columnspan=3, pady=10, sticky=tk.W
        )
        
        # Frame de pesquisa
        search_frame = ttk.Frame(self)
        search_frame.grid(row=1, column=0, columnspan=3, sticky=tk.EW, pady=5)
        
        ttk.Label(search_frame, text="Pesquisar por:").pack(side=tk.LEFT, padx=(0, 5))
        self.search_type = ttk.Combobox(search_frame, values=["Nome", "Usuário"], state="readonly", width=10)
        self.search_type.pack(side=tk.LEFT)
        self.search_type.set("Nome")
        
        ttk.Label(search_frame, text="Termo:").pack(side=tk.LEFT, padx=(5, 5))
        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.bind("<KeyRelease>", self.filter_users)
        
        ttk.Button(search_frame, text="Pesquisar", command=self.load_users).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(search_frame, text="Atualizar", command=self.load_users).pack(side=tk.LEFT, padx=(5, 0))
        
        # Lista de usuários
        user_list_frame = ttk.LabelFrame(self, text="Usuários")
        user_list_frame.grid(row=2, column=0, rowspan=8, sticky=tk.NSEW, padx=5, pady=5)
        
        self.tree = ttk.Treeview(user_list_frame, columns=("selected", "username", "ou", "status", "internet_groups"), 
                                show="headings", height=20)
        
        scrollbar = ttk.Scrollbar(user_list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        for col, width in [("selected", 50), ("username", 150), ("ou", 200), ("status", 80), ("internet_groups", 250)]:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=width)
            
        self.tree.tag_configure("disabled", foreground='grey')
        self.tree.tag_configure("active", foreground='black')
        self.tree.bind("<Button-1>", self.on_tree_click)
        self.tree.bind("<<TreeviewSelect>>", self.on_user_select)
        
        # Detalhes do usuário (lado direito)
        details_frame = ttk.LabelFrame(self, text="Detalhes do Usuário")
        details_frame.grid(row=2, column=1, columnspan=2, sticky=tk.NSEW, padx=5, pady=5)
        
        # Frame para informações básicas
        info_frame = ttk.Frame(details_frame)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(info_frame, text="Nome de usuário:", width=15, anchor=tk.W).grid(row=0, column=0, sticky=tk.W)
        self.detail_username = ttk.Label(info_frame, text="", width=30)
        self.detail_username.grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(info_frame, text="OU:", width=15, anchor=tk.W).grid(row=1, column=0, sticky=tk.W)
        self.detail_ou = ttk.Label(info_frame, text="", width=30)
        self.detail_ou.grid(row=1, column=1, sticky=tk.W)
        
        ttk.Label(info_frame, text="Status:", width=15, anchor=tk.W).grid(row=2, column=0, sticky=tk.W)
        self.detail_status = ttk.Label(info_frame, text="", width=30)
        self.detail_status.grid(row=2, column=1, sticky=tk.W)
        
        # Botão para resetar senha
        self.reset_password_btn = ttk.Button(info_frame, text="Resetar Senha", command=self.reset_password)
        self.reset_password_btn.grid(row=3, column=0, columnspan=2, pady=5)
        
        # Botão para ativar/desativar usuário
        self.toggle_status_btn = ttk.Button(info_frame, text="Ativar/Desativar", command=self.toggle_user_status)
        self.toggle_status_btn.grid(row=4, column=0, columnspan=2, pady=5)
        
        # Frame para grupos de internet
        groups_frame = ttk.LabelFrame(details_frame, text="Grupos de Internet")
        groups_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Frame para controles de grupos
        group_controls_frame = ttk.Frame(groups_frame)
        group_controls_frame.pack(fill=tk.X, padx=5, pady=5)
        
        ttk.Label(group_controls_frame, text="Grupo:").pack(side=tk.LEFT)
        self.group_combo = ttk.Combobox(group_controls_frame, width=25)
        self.group_combo.pack(side=tk.LEFT, padx=5)
        self.group_combo.bind("<KeyRelease>", self.filter_groups)
        
        ttk.Button(group_controls_frame, text="Adicionar", command=self.add_group_to_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(group_controls_frame, text="Remover", command=self.remove_group_from_user).pack(side=tk.LEFT, padx=2)
        ttk.Button(group_controls_frame, text="Espelhar Grupos", command=self.mirror_groups).pack(side=tk.LEFT, padx=2)
        
        # Treeview para grupos
        self.groups_tree = ttk.Treeview(groups_frame, columns=("group_name",), show="headings", height=8)
        groups_scrollbar = ttk.Scrollbar(groups_frame, orient=tk.VERTICAL, command=self.groups_tree.yview)
        self.groups_tree.configure(yscrollcommand=groups_scrollbar.set)
        
        self.groups_tree.heading("group_name", text="Nome do Grupo")
        self.groups_tree.column("group_name", width=300)
        
        self.groups_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)
        groups_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Controles de modificação em massa
        mass_update_frame = ttk.LabelFrame(self, text="Modificação em Massa de Grupos")
        mass_update_frame.grid(row=10, column=1, columnspan=2, sticky=tk.EW, padx=5, pady=5)
        
        ttk.Label(mass_update_frame, text="Ação:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.mass_action = ttk.Combobox(mass_update_frame, values=["Adicionar grupo", "Remover grupo"], state="readonly")
        self.mass_action.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        self.mass_action.set("Adicionar grupo")
        
        ttk.Label(mass_update_frame, text="Grupo:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.mass_group = ttk.Combobox(mass_update_frame, width=25)
        self.mass_group.grid(row=0, column=3, sticky=tk.EW, padx=5, pady=5)
        self.mass_group.bind("<KeyRelease>", self.filter_groups)
        
        ttk.Button(mass_update_frame, text="Aplicar", command=self.apply_mass_update).grid(row=0, column=4, padx=5, pady=5)
        
        # Credenciais
        cred_frame = ttk.LabelFrame(self, text="Credenciais de Administrador")
        cred_frame.grid(row=11, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
        
        ttk.Label(cred_frame, text="Usuário:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        user_cred_frame = ttk.Frame(cred_frame)
        user_cred_frame.grid(row=0, column=1, sticky=tk.EW, padx=5, pady=5)
        ttk.Label(user_cred_frame, text=f"{self.dominio_ad}\\", foreground="gray").pack(side=tk.LEFT)
        self.admin_user = ttk.Entry(user_cred_frame, width=20)
        self.admin_user.pack(side=tk.LEFT)
        
        ttk.Label(cred_frame, text="Senha:").grid(row=0, column=2, sticky=tk.W, padx=5, pady=5)
        self.admin_pass = ttk.Entry(cred_frame, width=20, show="*")
        self.admin_pass.grid(row=0, column=3, sticky=tk.EW, padx=5, pady=5)
        
        ttk.Button(cred_frame, text="Conectar", command=self.verify_credentials).grid(row=0, column=4, padx=5, pady=5)
        
        self.status_label = ttk.Label(cred_frame, text="Não conectado", foreground="red")
        self.status_label.grid(row=0, column=5, padx=5, pady=5)
        
        # Barra de progresso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=300, mode='determinate', 
                                           variable=self.progress_var)
        self.progress_bar.grid(row=12, column=0, columnspan=3, sticky=tk.EW, padx=5, pady=5)
        
        # Configurar pesos das colunas e linhas
        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=2)
        self.columnconfigure(2, weight=1)
        self.rowconfigure(2, weight=1)
        
        # Carregar grupos de internet conhecidos
        self.load_known_groups()
    
    def filter_groups(self, event):
        combo = event.widget
        term = combo.get().lower()

        if not term:
            filtered_groups = self.internet_groups
        else:
            filtered_groups = [g for g in self.internet_groups if term in g.lower()]
        
        current_text = combo.get()
        combo['values'] = filtered_groups
        combo.set(current_text)
    
    def load_known_groups(self):
        self.internet_groups = self.config.get('KNOWN_INTERNET_GROUPS', [])
        self.mass_group['values'] = self.internet_groups
        self.group_combo['values'] = self.internet_groups
        if self.internet_groups:
            self.mass_group.set(self.internet_groups[0])
            self.group_combo.set(self.internet_groups[0])
    
    def on_tree_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region == "cell":
            col = self.tree.identify_column(event.x)
            item = self.tree.identify_row(event.y)
            if col == "#1" and item:  # Coluna de seleção
                vals = list(self.tree.item(item, "values"))
                username = vals[1]
                
                if vals[0] == "[ ]":
                    vals[0] = "[X]"
                    self.selected_users_set.add(username)
                else:
                    vals[0] = "[ ]"
                    if username in self.selected_users_set:
                        self.selected_users_set.remove(username)
                
                self.tree.item(item, values=vals)
    
    def on_user_select(self, event):
        selection = self.tree.selection()
        if selection:
            item = selection[0]
            username = self.tree.item(item, "values")[1]
            self.selected_user = username
            self.show_user_details(username)
    
    def show_user_details(self, username):
        if not self.conn or not self.conn.bound:
            return
            
        try:
            self.config = obter_configuracao()
            self.base_dn = self.config['BASE_DN']
            
            # Busca informações detalhadas do usuário
            self.conn.search(
                self.base_dn, 
                f"(cn={username})", 
                attributes=['cn', 'distinguishedName', 'userAccountControl', self.internet_group_attribute]
            )
            
            if self.conn.entries:
                user = self.conn.entries[0]
                dn = user.distinguishedName.value
                ou = extract_ou_from_dn(dn)
                disabled = is_account_disabled(user.userAccountControl.value)
                status = "Desativado" if disabled else "Ativo"
                
                self.detail_username.config(text=username)
                self.detail_ou.config(text=ou)
                self.detail_status.config(text=status)
                
                self.groups_tree.delete(*self.groups_tree.get_children())
                
                internet_groups = []
                if hasattr(user, self.internet_group_attribute):
                    groups = getattr(user, self.internet_group_attribute).values
                    internet_groups = [g for g in groups if any(ig in g for ig in self.internet_groups)]
                
                for group in internet_groups:
                    self.groups_tree.insert("", "end", values=(group,))
                    
                self.user_details[username] = {
                    'dn': dn,
                    'ou': ou,
                    'status': status,
                    'internet_groups': internet_groups
                }
                
        except Exception as e:
            logging.error(f"Erro ao carregar detalhes do usuário {username}: {e}")
            messagebox.showerror("Erro", f"Não foi possível carregar os detalhes do usuário: {e}")
    
    def filter_users(self, event=None):
        term = self.search_var.get().lower()
        search_type = self.search_type.get()
        self.tree.delete(*self.tree.get_children())
        
        if term:
            if search_type == "Nome":
                # Filtra pelo nome (cn)
                filtered = [u for u in self.all_users if term in u[0].lower()]
            else:  # Pesquisa por Usuário (sAMAccountName)
                filtered = [u for u in self.all_users if term in u[1].lower()]
        else:
            filtered = self.all_users
        
        for cn, sam, ou, status, is_disabled, groups in filtered:
            selected_mark = "[X]" if cn in self.selected_users_set else "[ ]"
            tag = "disabled" if is_disabled else "active"
            self.tree.insert("", "end", values=(selected_mark, cn, ou, status, ", ".join(groups)), tags=(tag,))
    
    def load_users(self):
        if not self.conn or not self.conn.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return
            
        try:
            self.config = obter_configuracao()
            self.base_dn = self.config['BASE_DN']
            
            self.status_label.config(text="Carregando usuários...", foreground="blue")
            self.all_users = []
            self.selected_users_set.clear()
            
            # Buscar tanto cn quanto sAMAccountName
            self.conn.search(
                self.base_dn, 
                '(&(objectClass=user)(objectCategory=person))', 
                attributes=['cn', 'sAMAccountName', 'distinguishedName', 'userAccountControl', self.internet_group_attribute]
            )
            
            for entry in self.conn.entries:
                cn = entry.cn.value
                sam_account_name = entry.sAMAccountName.value if hasattr(entry, 'sAMAccountName') else cn
                dn = entry.distinguishedName.value
                ou = extract_ou_from_dn(dn)
                disabled = is_account_disabled(entry.userAccountControl.value)
                status = "Desativado" if disabled else "Ativo"
                
                internet_groups = []
                if hasattr(entry, self.internet_group_attribute):
                    groups = getattr(entry, self.internet_group_attribute).values
                    internet_groups = [g for g in groups if any(ig in g for ig in self.internet_groups)]
                
                # Armazenar ambos cn e sAMAccountName
                self.all_users.append((cn, sam_account_name, ou, status, disabled, internet_groups))
                
            self.filter_users()
            self.status_label.config(text=f"{len(self.all_users)} usuários carregados", foreground="green")
            
        except Exception as e:
            logging.error(f"Erro ao carregar usuários: {e}")
            self.status_label.config(text=f"Erro: {e}", foreground="red")
    
    def verify_credentials(self):
        user = self.admin_user.get().strip()
        password = self.admin_pass.get()
        
        if not user or not password:
            messagebox.showerror("Erro", "Preencha usuário e senha")
            return
            
        try:
            self.conn = conectar_ldap(user, password)
            
            if self.conn.bound:
                self.status_label.config(text="Conectado", foreground="green")
                self.load_users()
                if not self.internet_groups:
                    self.load_internet_groups_from_ad()
            else:
                raise Exception("Falha na autenticação")
                
        except Exception as e:
            logging.error(f"Erro de conexão: {e}")
            self.status_label.config(text=f"Erro: {e}", foreground="red")
    
    def load_internet_groups_from_ad(self):
        try:
            search_base = self.config.get('GROUPS_BASE_DN', self.base_dn)
            filter_str = self.config.get('INTERNET_GROUPS_FILTER', '(objectClass=group)')
            
            self.conn.search(search_base, filter_str, attributes=['cn'])
            groups = [entry.cn.value for entry in self.conn.entries]
            
            self.internet_groups = groups
            self.mass_group['values'] = groups
            self.group_combo['values'] = groups
            if groups:
                self.mass_group.set(groups[0])
                self.group_combo.set(groups[0])
                
        except Exception as e:
            logging.error(f"Erro ao carregar grupos do AD: {e}")
            messagebox.showwarning("Aviso", "Não foi possível carregar grupos do AD. Usando lista padrão.")
    
    def add_group_to_user(self):
        if not self.selected_user:
            messagebox.showwarning("Aviso", "Selecione um usuário primeiro")
            return
        
        group = self.group_combo.get()
        if not group:
            messagebox.showwarning("Aviso", "Selecione um grupo")
            return
        
        try:
            user_dn = self.user_details[self.selected_user]['dn']
            group_dn = self.get_group_dn(group)
            
            if not group_dn:
                messagebox.showerror("Erro", f"Grupo '{group}' não encontrado")
                return
            
            changes = {
                'member': [(MODIFY_ADD, [user_dn])]
            }
            
            if self.conn.modify(group_dn, changes):
                messagebox.showinfo("Sucesso", f"Usuário '{self.selected_user}' adicionado ao grupo '{group}'")
                if group not in self.user_details[self.selected_user]['internet_groups']:
                    self.user_details[self.selected_user]['internet_groups'].append(group)
                    self.groups_tree.insert("", "end", values=(group,))
            else:
                messagebox.showerror("Erro", f"Falha ao adicionar ao grupo: {self.conn.result}")
            
        except Exception as e:
            logging.error(f"Erro ao adicionar grupo: {e}")
            messagebox.showerror("Erro", f"Não foi possível adicionar o grupo: {e}")
    
    def remove_group_from_user(self):
        if not self.selected_user:
            messagebox.showwarning("Aviso", "Selecione um usuário primeiro")
            return
        
        selection = self.groups_tree.selection()
        if not selection:
            messagebox.showwarning("Aviso", "Selecione um grupo para remover")
            return
        
        group = self.groups_tree.item(selection[0], "values")[0]
    
        try:
            user_dn = self.user_details[self.selected_user]['dn']
            group_dn = self.get_group_dn(group)
            
            if not group_dn:
                messagebox.showerror("Erro", f"Grupo '{group}' não encontrado")
                return
            
            changes = {
                'member': [(MODIFY_DELETE, [user_dn])]
            }
            
            if self.conn.modify(group_dn, changes):
                messagebox.showinfo("Sucesso", f"Usuário '{self.selected_user}' removido do grupo '{group}'")
                if group in self.user_details[self.selected_user]['internet_groups']:
                    self.user_details[self.selected_user]['internet_groups'].remove(group)
                    self.groups_tree.delete(selection[0])
            else:
                messagebox.showerror("Erro", f"Falha ao remover do grupo: {self.conn.result}")
            
        except Exception as e:
            logging.error(f"Erro ao remover grupo: {e}")
            messagebox.showerror("Erro", f"Não foi possível remover o grupo: {e}")

    def get_group_dn(self, group_name):
        if group_name.lower().startswith('cn=') and 'ou=' in group_name.lower() and 'dc=' in group_name.lower():
            return group_name
        
        try:
            search_bases = [
                self.config.get('GROUPS_BASE_DN', self.base_dn),
                self.base_dn,
                'OU=Grupos_Fortigate,OU=MOTIVA,DC=motiva,DC=matriz'
            ]
        
            search_filter = f"(|(cn={group_name})(sAMAccountName={group_name}))"

            for search_base in search_bases:
                if not search_base:
                    continue

                try:
                    self.conn.search(
                        search_base=search_base,
                        search_filter=search_filter,
                        search_scope=SUBTREE,
                        attributes=['distinguishedName']
                    )
            
                    if self.conn.entries:
                        group_dn = self.conn.entries[0].distinguishedName.value
                        return group_dn
                    else:
                        return None
            
                except Exception as e:
                    logging.warning(f"Busca falhou na base {search_base}: {e}")
                    continue
            
            logging.error(f"Grupo {group_name} não encontrado em nenhuma base de busca")
            return None
    
        except Exception as e:
            logging.error(f"Erro ao buscar DN do grupo {group_name}: {e}")
            return None
    
    def apply_mass_update(self):
        action = self.mass_action.get()
        group = self.mass_group.get()
        
        if not action or not group:
            messagebox.showerror("Erro", "Selecione uma ação e um grupo")
            return
            
        selected_users = self._get_selected_users()
                
        if not selected_users:
            messagebox.showinfo("Info", "Nenhum usuário selecionado")
            return
            
        confirm = messagebox.askyesno(
            "Confirmar", 
            f"Deseja {action.lower()} '{group}' para {len(selected_users)} usuário(s)?"
        )
        
        if not confirm:
            return
            
        threading.Thread(target=self._thread_mass_update, args=(selected_users, action, group), daemon=True).start()
    
    def _thread_mass_update(self, users, action, group):
        total = len(users)
        success, errors = 0, 0
        self.progress_var.set(0)
        self.progress_bar["maximum"] = total
        
        group_dn = self.get_group_dn(group)
        if not group_dn:
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Grupo '{group}' não encontrado"))
            return

        for i, username in enumerate(users):
            try:
                if username in self.user_details:
                    user_dn = self.user_details[username]['dn']
                else:
                    self.conn.search(self.base_dn, f"(cn={username})", attributes=['distinguishedName'])
                    if not self.conn.entries:
                        raise Exception("Usuário não encontrado")
                    user_dn = self.conn.entries[0].distinguishedName.value
                
                if action == "Adicionar grupo":
                    changes = {'member': [(MODIFY_ADD, [user_dn])]}
                else:
                    changes = {'member': [(MODIFY_DELETE, [user_dn])]}
                
                if self.conn.modify(group_dn, changes):
                    success += 1
                    if username in self.user_details:
                        if action == "Adicionar grupo":
                            if group not in self.user_details[username]['internet_groups']:
                                self.user_details[username]['internet_groups'].append(group)
                        else:
                            if group in self.user_details[username]['internet_groups']:
                                self.user_details[username]['internet_groups'].remove(group)
                else:
                    errors += 1
                    
            except Exception as e:
                logging.error(f"Erro ao modificar grupo para {username}: {e}")
                errors += 1
                
            self.root.after(0, lambda cur=i+1, s=success, er=errors: self._update_progress(cur, s, er, total))
            
        self.root.after(0, self.load_users)
        
        msg = f"Operação concluída: {success} sucesso(s), {errors} erro(s)"
        self.root.after(0, lambda: self.status_label.config(text=msg, 
                                                           foreground="green" if errors == 0 else "orange"))
        self.root.after(0, lambda: messagebox.showinfo("Resultado", msg))
    
    def _update_progress(self, current, success, errors, total):
        self.progress_var.set(current)
        self.status_label.config(text=f"Processados: {current}/{total} | Sucessos: {success} | Erros: {errors}")
    
    def reset_password(self):
        if not self.selected_user:
            messagebox.showwarning("Aviso", "Selecione um usuário primeiro")
            return

        if not self.conn or not self.conn.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return

        dialog = PasswordResetDialog(self, self.selected_user)
        self.wait_window(dialog)
        
        if not dialog.result:
            return

        try:
            user_dn = self.user_details[self.selected_user]['dn']
            new_password = dialog.result['new_password']
            
            encoded_password = f'"{new_password}"'.encode('utf-16-le')
            
            changes = {
                'unicodePwd': [(MODIFY_REPLACE, [encoded_password])]
            }
            
            if dialog.result['must_change']:
                changes['pwdLastSet'] = [(MODIFY_REPLACE, [0])]
                
            if dialog.result['unlock_account']:
                changes['lockoutTime'] = [(MODIFY_REPLACE, [0])]
            
            if self.conn.modify(user_dn, changes):
                messagebox.showinfo("Sucesso", f"Senha resetada com sucesso para {self.selected_user}")
            else:
                messagebox.showerror("Erro", f"Falha ao resetar senha: {self.conn.result}")
            
        except Exception as e:
            logging.error(f"Erro ao resetar senha: {e}")
            messagebox.showerror("Erro", f"Não foi possível resetar a senha: {e}")
    
    def toggle_user_status(self):
        selected_users = self._get_selected_users()
        
        if not selected_users:
            messagebox.showwarning("Aviso", "Selecione pelo menos um usuário")
            return

        if not self.conn or not self.conn.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return

        confirm = messagebox.askyesno(
            "Confirmar",
            f"Deseja alternar o status de {len(selected_users)} usuário(s)?"
        )
        if not confirm:
            return

        threading.Thread(target=self._thread_toggle_status, args=(selected_users,), daemon=True).start()

    def _get_selected_users(self):
        return list(self.selected_users_set)
    
    def _thread_toggle_status(self, users):
        total = len(users)
        success, errors = 0, 0
        self.root.after(0, lambda: self.progress_var.set(0))
        self.root.after(0, lambda: self.progress_bar.config(maximum=total))

        for i, username in enumerate(users):
            try:
                user_dn = self._get_user_dn(username)
                if not user_dn:
                    errors += 1
                    continue

                self.conn.search(
                    user_dn,
                    '(objectClass=user)',
                    attributes=['userAccountControl']
                )
                
                if not self.conn.entries:
                    errors += 1
                    continue

                current_uac = self.conn.entries[0].userAccountControl.value
                new_uac = current_uac ^ 2

                changes = {
                    'userAccountControl': [(MODIFY_REPLACE, [new_uac])]
                }

                if self.conn.modify(user_dn, changes):
                    success += 1
                    self._update_local_user_status(username, new_uac)
                else:
                    errors += 1

            except Exception as e:
                logging.error(f"Erro ao alternar status de {username}: {e}")
                errors += 1

            self.root.after(0, lambda cur=i+1: self.progress_var.set(cur))
            self.root.after(0, lambda: self.status_label.config(
                text=f"Processando: {i+1}/{total} | Sucessos: {success} | Erros: {errors}"
            ))

        self.root.after(0, self.load_users)
        if self.selected_user:
            self.root.after(0, lambda: self.show_user_details(self.selected_user))

        msg = f"Operação concluída: {success} sucesso(s), {errors} erro(s)"
        self.root.after(0, lambda: self.status_label.config(
            text=msg,
            foreground="green" if errors == 0 else "orange"
        ))
        self.root.after(0, lambda: messagebox.showinfo("Resultado", msg))

    def _get_user_dn(self, username):
        if username in self.user_details:
            return self.user_details[username]['dn']
        
        try:
            self.conn.search(
                self.base_dn,
                f"(cn={username})",
                attributes=['distinguishedName']
            )
            if self.conn.entries:
                return self.conn.entries[0].distinguishedName.value
        except Exception as e:
            logging.error(f"Erro ao buscar DN de {username}: {e}")
        
        return None

    def _update_local_user_status(self, username, new_uac):
        disabled = is_account_disabled(new_uac)
        status = "Desativado" if disabled else "Ativo"
        
        if username in self.user_details:
            self.user_details[username]['status'] = status

        for i, user in enumerate(self.all_users):
            if user[0] == username:
                self.all_users[i] = (
                    user[0],
                    user[1],
                    user[2],
                    status,
                    disabled,
                    user[5]
                )
                break
    
    def mirror_groups(self):
        if not self.conn or not self.conn.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return

        source_user = self.selected_user
        if not source_user:
            messagebox.showwarning("Aviso", "Selecione um usuário de origem primeiro")
            return

        target_users = self._get_selected_users()
        if not target_users:
            messagebox.showwarning("Aviso", "Selecione pelo menos um usuário destino")
            return

        if source_user in target_users:
            messagebox.showwarning("Aviso", "Usuário de origem não pode estar na lista de destinos")
            return

        confirm = messagebox.askyesno(
            "Confirmar",
            f"Deseja copiar os grupos de {source_user} para {len(target_users)} usuário(s)?"
        )
        if not confirm:
            return

        threading.Thread(target=self._thread_mirror_groups, 
                       args=(source_user, target_users), daemon=True).start()

    def _thread_mirror_groups(self, source_user, target_users):
        try:
            total = len(target_users)
            success, errors = 0, 0
            self.root.after(0, lambda: self.progress_var.set(0))
            self.root.after(0, lambda: self.progress_bar.config(maximum=total))

            source_groups = self._get_user_internet_groups(source_user)
            if source_groups is None:
                self.root.after(0, lambda: messagebox.showerror("Erro", 
                    f"Não foi possível obter grupos do usuário {source_user}"))
                return

            for i, target_user in enumerate(target_users):
                try:
                    if self._apply_groups_to_user(target_user, source_groups):
                        success += 1
                    else:
                        errors += 1
                except Exception as e:
                    logging.error(f"Erro ao espelhar grupos para {target_user}: {e}")
                    errors += 1

                self.root.after(0, lambda cur=i+1: self.progress_var.set(cur))
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Processando: {i+1}/{total} | Sucessos: {success} | Erros: {errors}"
                ))

            self.root.after(0, self.load_users)
            msg = f"Espelhamento concluído: {success} sucesso(s), {errors} erro(s)"
            self.root.after(0, lambda: self.status_label.config(
                text=msg,
                foreground="green" if errors == 0 else "orange"
            ))
            self.root.after(0, lambda: messagebox.showinfo("Resultado", msg))

        except Exception as e:
            logging.error(f"Erro no espelhamento: {e}")
            self.root.after(0, lambda: messagebox.showerror("Erro", f"Falha no espelhamento: {e}"))

    def _get_user_internet_groups(self, username):
        try:
            self.conn.search(
                self.base_dn,
                f"(cn={username})",
                attributes=[self.internet_group_attribute]
            )
            if self.conn.entries:
                groups = getattr(self.conn.entries[0], self.internet_group_attribute).values
                return [g for g in groups if any(ig in g for ig in self.internet_groups)]
        except Exception as e:
            logging.error(f"Erro ao buscar grupos de {username}: {e}")
        return None

    def _apply_groups_to_user(self, target_user, target_groups):
        try:
            user_dn = self._get_user_dn(target_user)
            if not user_dn:
                return False

            current_groups = self._get_user_internet_groups(target_user) or []

            groups_to_add = [g for g in target_groups if g not in current_groups]
            groups_to_remove = [g for g in current_groups if g not in target_groups]

            for group in groups_to_remove:
                group_dn = self.get_group_dn(group)
                if group_dn:
                    changes = {'member': [(MODIFY_DELETE, [user_dn])]}
                    self.conn.modify(group_dn, changes)

            for group in groups_to_add:
                group_dn = self.get_group_dn(group)
                if group_dn:
                    changes = {'member': [(MODIFY_ADD, [user_dn])]}
                    self.conn.modify(group_dn, changes)

            return True

        except Exception as e:
            logging.error(f"Erro ao aplicar grupos para {target_user}: {e}")
            return False