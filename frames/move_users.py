import tkinter as tk
from tkinter import ttk, messagebox
import threading
import logging
from ldap3.utils.conv import escape_filter_chars
from ldap_utils import conectar_ldap, extract_ou_from_dn, is_account_disabled, move_user, obter_configuracao

class MoveUsersFrame(ttk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent)
        self.root = root

        self.conn_move = None
        self.all_users = []
        self.ous_list = []
        
        # Carrega as configurações iniciais
        self.config = obter_configuracao()
        self.dominio_ad = self.config['DOMINIO_AD']
        self.base_dn = self.config['BASE_DN']

        self._setup_ui()

    def _setup_ui(self):
        ttk.Label(self, text="Mover / Remover Usuários do AD", font=("Arial", 14)).grid(row=0, column=0, columnspan=2, pady=10)

        # Pesquisa
        ttk.Label(self, text="Pesquisar Usuários:").grid(row=1, column=0, sticky=tk.W)
        self.user_search_var = tk.StringVar()
        search_frame = ttk.Frame(self)
        search_frame.grid(row=1, column=1, sticky=tk.EW, pady=5)
        self.user_search_entry = ttk.Entry(search_frame, textvariable=self.user_search_var, width=30)
        self.user_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.user_search_entry.bind("<KeyRelease>", self.filter_users)
        ttk.Button(search_frame, text="Pesquisar", width=10, command=self.load_users).pack(side=tk.LEFT, padx=(5,0))
        ttk.Button(search_frame, text="Atualizar", width=10, command=self.load_users).pack(side=tk.LEFT, padx=(5,0))

        # Lista usuários
        self.tree = ttk.Treeview(self, columns=("selected","username","ou","status"), show="headings", height=10)
        self.tree.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)
        for col, w in zip(("selected","username","ou","status"), (80,150,250,80)):
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(col, width=w)
        self.tree.tag_configure("disabled", foreground='grey')
        self.tree.tag_configure("active", foreground='black')
        self.tree.bind("<Button-1>", self.on_tree_click)

        # OU destino
        ttk.Label(self, text="Mover para OU:").grid(row=3, column=0, sticky=tk.W)
        self.target_ou = ttk.Combobox(self, width=40)
        self.target_ou.grid(row=3, column=1, sticky=tk.EW, pady=5)

        # Credenciais
        ttk.Separator(self, orient=tk.HORIZONTAL).grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(self, text="Credenciais do Grupo de TI", font=("Arial",12)).grid(row=5, column=0, columnspan=2, pady=5)
        ttk.Label(self, text="Usuário de Rede:").grid(row=6, column=0, sticky=tk.W)
        user_frame = ttk.Frame(self)
        user_frame.grid(row=6, column=1, sticky=tk.W)
        ttk.Label(user_frame, text=f"{self.dominio_ad}\\", foreground="gray").pack(side=tk.LEFT)
        self.admin_user = ttk.Entry(user_frame, width=25)
        self.admin_user.pack(side=tk.LEFT)
        ttk.Label(self, text="Senha:").grid(row=7, column=0, sticky=tk.W)
        self.admin_pass = ttk.Entry(self, width=30, show="*")
        self.admin_pass.grid(row=7, column=1, sticky=tk.EW)
        ttk.Button(self, text="Verificar Credenciais", command=self.verify_credentials).grid(row=8,column=0,columnspan=2,pady=10)
        self.status_label = ttk.Label(self, text="", font=("Arial",9))
        self.status_label.grid(row=9,column=0,columnspan=2)

        # Botões de ação
        self.move_btn = ttk.Button(self, text="Mover Usuários Selecionados", command=self.move_selected_users, state=tk.DISABLED)
        self.move_btn.grid(row=10,column=0,columnspan=2,pady=10)

        self.remove_btn = ttk.Button(self, text="Remover Usuários Selecionados", command=self.remove_selected_users, state=tk.DISABLED)
        self.remove_btn.grid(row=11, column=0, columnspan=2, pady=5)

        # Barra de progresso
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=300, mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(row=12,column=0,columnspan=2, pady=10)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

    # ================= FUNÇÕES =================

    def on_tree_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region=="cell":
            col = self.tree.identify_column(event.x)
            item = self.tree.identify_row(event.y)
            if col=="#1" and item:
                vals = list(self.tree.item(item,"values"))
                vals[0] = "[X]" if vals[0]=="[ ]" else "[ ]"
                self.tree.item(item, values=vals)

    def filter_users(self, event=None):
        term = self.user_search_var.get().lower()
        self.tree.delete(*self.tree.get_children())
        filtered = [u for u in self.all_users if term in u[0].lower()] if term else self.all_users
        for cn, ou, status, is_disabled in filtered:
            tag = "disabled" if is_disabled else "active"
            self.tree.insert("", "end", values=("[ ]", cn, ou, status), tags=(tag,))

    def load_users(self):
        if not self.conn_move or not self.conn_move.bound:
            messagebox.showerror("Erro","Conecte-se primeiro com credenciais válidas")
            return
        try:
            # Atualiza as configurações antes de carregar os usuários
            self.config = obter_configuracao()
            self.base_dn = self.config['BASE_DN']
            
            self.status_label.config(text="Carregando usuários...", foreground="blue")
            self.all_users=[]
            self.conn_move.search(self.base_dn,'(&(objectClass=user)(objectCategory=person))',attributes=['cn','distinguishedName','userAccountControl'])
            for e in self.conn_move.entries:
                cn = e.cn.value
                dn = e.distinguishedName.value
                ou = extract_ou_from_dn(dn)
                disabled = is_account_disabled(e.userAccountControl.value)
                status = "Desativado" if disabled else "Ativo"
                self.all_users.append((cn,ou,status,disabled))
            self.filter_users()
            self.status_label.config(text=f"{len(self.all_users)} usuários carregados", foreground="green")
        except Exception as e:
            logging.error(f"Erro carregar usuários: {e}")
            self.status_label.config(text=f"Erro: {e}", foreground="red")

    def load_ous(self):
        try:
            # Atualiza as configurações antes de carregar as OUs
            self.config = obter_configuracao()
            self.base_dn = self.config['BASE_DN']
            
            self.conn_move.search(self.base_dn,'(objectClass=organizationalUnit)',attributes=['distinguishedName'])
            self.ous_list = [e.distinguishedName.value for e in self.conn_move.entries]
            self.target_ou['values'] = ["Domínio Raiz"]+self.ous_list
            return True
        except Exception as e:
            logging.error(f"Erro carregar OUs: {e}")
            return False

    def verify_credentials(self):
        user = self.admin_user.get().strip()
        password = self.admin_pass.get()
        if not user or not password:
            messagebox.showerror("Erro","Preencha usuário e senha")
            return
        try:
            self.conn_move = conectar_ldap(user,password)
            
            if self.conn_move.bound and self.load_ous():
                self.status_label.config(text="✅ Credenciais válidas", foreground="green")
                self.move_btn.config(state=tk.NORMAL)
                self.remove_btn.config(state=tk.NORMAL)
                self.load_users()
            else:
                raise Exception("Falha autenticação")
        except Exception as e:
            self.status_label.config(text=f"❌ {e}", foreground="red")
            self.move_btn.config(state=tk.DISABLED)
            self.remove_btn.config(state=tk.DISABLED)

    def move_selected_users(self):
        target = self.target_ou.get()
        if not target:
            messagebox.showerror("Erro","Selecione uma OU de destino")
            return
        selected = [self.tree.item(i,"values")[1] for i in self.tree.get_children() if self.tree.item(i,"values")[0]=="[X]"]
        if not selected:
            messagebox.showinfo("Aviso","Nenhum usuário selecionado")
            return

        confirm = messagebox.askyesno("Confirmar", f"Deseja mover {len(selected)} usuário(s) para:\n{target}?")
        if not confirm:
            return

        threading.Thread(target=self._thread_move, args=(selected,target),daemon=True).start()

    def _thread_move(self, users, target):
        # Atualiza as configurações antes de mover os usuários
        self.config = obter_configuracao()
        self.base_dn = self.config['BASE_DN']
        
        total = len(users)
        success, errors = 0,0
        self.progress_var.set(0)
        self.progress_bar["maximum"] = total
        for i,cn in enumerate(users):
            try:
                escaped_cn = escape_filter_chars(cn)
                self.conn_move.search(self.base_dn,f"(cn={escaped_cn})",attributes=['distinguishedName'], size_limit=1)
                if not self.conn_move.entries:
                    raise Exception("Usuário não encontrado")
                user_dn = self.conn_move.entries[0].distinguishedName.value
                new_parent = self.base_dn if target=="Domínio Raiz" else target
                if move_user(self.conn_move,user_dn,new_parent):
                    success+=1
                else:
                    errors+=1
            except Exception as e:
                logging.error(f"Erro mover {cn}: {e}")
                errors+=1
            self.root.after(0, lambda cur=i+1, s=success, er=errors: self._update_progress(cur, s, er, total))
        msg = f"Movimentação concluída: {success} sucesso(s), {errors} erro(s)"
        self.root.after(0, lambda: self.status_label.config(text=msg, foreground="green" if errors==0 else "orange"))
        self.root.after(0, lambda: messagebox.showinfo("Resultado", msg))
        self.root.after(0, self.load_users)

    def remove_selected_users(self):
        selected = [self.tree.item(i,"values")[1] for i in self.tree.get_children() if self.tree.item(i,"values")[0]=="[X]"]
        if not selected:
            messagebox.showinfo("Aviso","Nenhum usuário selecionado")
            return

        confirm = messagebox.askyesno("Confirmar", f"⚠ Tem certeza que deseja REMOVER {len(selected)} usuário(s) do AD?\n\nEssa ação é irreversível!")
        if not confirm:
            return

        threading.Thread(target=self._thread_remove, args=(selected,), daemon=True).start()

    def _thread_remove(self, users):
        # Atualiza as configurações antes de remover os usuários
        self.config = obter_configuracao()
        self.base_dn = self.config['BASE_DN']
        
        total = len(users)
        success, errors = 0, 0
        self.progress_var.set(0)
        self.progress_bar["maximum"] = total

        for i, cn in enumerate(users):
            try:
                escaped_cn = escape_filter_chars(cn)
                self.conn_move.search(self.base_dn, f"(cn={escaped_cn})", attributes=['distinguishedName'], size_limit=1)
                if not self.conn_move.entries:
                    raise Exception("Usuário não encontrado")
                user_dn = self.conn_move.entries[0].distinguishedName.value

                if self.conn_move.delete(user_dn):
                    success += 1
                else:
                    logging.error(f"Erro ao remover {cn}: {self.conn_move.result}")
                    errors += 1
            except Exception as e:
                logging.error(f"Erro remover {cn}: {e}")
                errors += 1

            self.root.after(0, lambda cur=i+1, s=success, er=errors: self._update_progress(cur, s, er, total))

        msg = f"Remoção concluída: {success} sucesso(s), {errors} erro(s)"
        self.root.after(0, lambda: self.status_label.config(text=msg, foreground="green" if errors==0 else "orange"))
        self.root.after(0, lambda: messagebox.showinfo("Resultado", msg))
        self.root.after(0, self.load_users)

    def _update_progress(self, current, success, errors, total):
        self.progress_var.set(current)
        self.status_label.config(text=f"Processados: {current}/{total} | Sucessos: {success} | Erros: {errors}")