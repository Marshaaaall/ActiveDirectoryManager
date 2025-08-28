import tkinter as tk
from tkinter import ttk, messagebox
from ldap3 import MODIFY_ADD, MODIFY_DELETE, SUBTREE
import threading
import logging
from ldap_utils import conectar_ldap, extract_ou_from_dn, is_account_disabled, obter_configuracao

class InternetGroupsFrame(ttk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent)
        self.root = root
        
        self.conn = None
        self.all_users = []
        self.internet_groups = []
        self.user_details = {}
        self.selected_user = None
        
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
        
        ttk.Label(search_frame, text="Pesquisar Usuários:").pack(side=tk.LEFT, padx=(0, 5))
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
                vals[0] = "[X]" if vals[0] == "[ ]" else "[ ]"
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
        self.tree.delete(*self.tree.get_children())
        filtered = [u for u in self.all_users if term in u[0].lower()] if term else self.all_users
        for cn, ou, status, is_disabled, groups in filtered:
            tag = "disabled" if is_disabled else "active"
            self.tree.insert("", "end", values=("[ ]", cn, ou, status, ", ".join(groups)), tags=(tag,))
    
    def load_users(self):
        if not self.conn or not self.conn.bound:
            messagebox.showerror("Erro", "Conecte-se primeiro com credenciais válidas")
            return
            
        try:
            self.config = obter_configuracao()
            self.base_dn = self.config['BASE_DN']
            
            self.status_label.config(text="Carregando usuários...", foreground="blue")
            self.all_users = []
            
            self.conn.search(
                self.base_dn, 
                '(&(objectClass=user)(objectCategory=person))', 
                attributes=['cn', 'distinguishedName', 'userAccountControl', self.internet_group_attribute]
            )
            
            for entry in self.conn.entries:
                cn = entry.cn.value
                dn = entry.distinguishedName.value
                ou = extract_ou_from_dn(dn)
                disabled = is_account_disabled(entry.userAccountControl.value)
                status = "Desativado" if disabled else "Ativo"
                
                internet_groups = []
                if hasattr(entry, self.internet_group_attribute):
                    groups = getattr(entry, self.internet_group_attribute).values
                    internet_groups = [g for g in groups if any(ig in g for ig in self.internet_groups)]
                
                self.all_users.append((cn, ou, status, disabled, internet_groups))
                
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
            
            # Modificação para ldap3
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
            
            # Modificação para ldap3
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
        """
        Obtém o DN de um grupo. Se a string de entrada já for um DN, 
        retorna diretamente. Caso contrário, busca no AD.
        """
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
            
        selected_users = []
        for item in self.tree.get_children():
            values = self.tree.item(item, "values")
            if values[0] == "[X]":
                selected_users.append(values[1])
                
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
                
                # Determinar a operação com base na ação
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