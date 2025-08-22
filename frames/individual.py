import tkinter as tk
from tkinter import ttk, messagebox
import unicodedata
import re
from config import DOMINIO_AD, GRUPOS_PERMITIDOS
from ldap_utils import conectar_ldap
from ldap3 import MODIFY_REPLACE, MODIFY_ADD
import logging


class IndividualFrame:
    def __init__(self, notebook, root):
        self.root = root
        self.full_name_edited = False
        self.login_edited = False
        self.all_template_users = []
        self.all_template_users_with_status = []
        self.template_dns = []
        self.template_ous = []
        self.template_logins = []

        self.frame = ttk.Frame(notebook, padding=10)
        notebook.add(self.frame, text="Criação Individual")

        self._setup_ui()

    def _setup_ui(self):
        ttk.Label(self.frame, text="Copiar objeto - Usuário", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(self.frame, text="O usuário será criado no mesmo local do modelo selecionado", foreground="blue").grid(row=1, column=0, columnspan=2, pady=5)
        ttk.Separator(self.frame, orient=tk.HORIZONTAL).grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=10)

        # Nome e sobrenome
        ttk.Label(self.frame, text="Nome:").grid(row=3, column=0, sticky=tk.W)
        self.first_name = ttk.Entry(self.frame, width=30)
        self.first_name.grid(row=3, column=1, pady=5, sticky=tk.EW)
        self.first_name.bind("<KeyRelease>", self.update_full_name)

        ttk.Label(self.frame, text="Sobrenome:").grid(row=4, column=0, sticky=tk.W)
        self.last_name = ttk.Entry(self.frame, width=30)
        self.last_name.grid(row=4, column=1, pady=5, sticky=tk.EW)
        self.last_name.bind("<KeyRelease>", self.update_full_name)

        # Nome completo
        ttk.Label(self.frame, text="Nome completo:").grid(row=5, column=0, sticky=tk.W)
        self.full_name = ttk.Entry(self.frame, width=30)
        self.full_name.grid(row=5, column=1, pady=5, sticky=tk.EW)
        self.full_name.bind("<Key>", self.on_full_name_edit)
        self.full_name.bind("<KeyRelease>", self.generate_login_from_fullname)

        # Login
        ttk.Label(self.frame, text="Nome de logon do usuário:").grid(row=6, column=0, sticky=tk.W)
        logon_frame = ttk.Frame(self.frame)
        logon_frame.grid(row=6, column=1, sticky=tk.W)
        self.username = ttk.Entry(logon_frame, width=20)
        self.username.pack(side=tk.LEFT)
        ttk.Label(logon_frame, text="@motivabpo.com.br", foreground="gray").pack(side=tk.LEFT, padx=5)
        self.username.bind("<Key>", self.mark_login_edited)
        self.username.bind("<KeyRelease>", self.sync_usernames)

        # Login antigo
        ttk.Label(self.frame, text="Nome de logon (anterior ao Windows 2000):").grid(row=7, column=0, sticky=tk.W)
        old_logon_frame = ttk.Frame(self.frame)
        old_logon_frame.grid(row=7, column=1, sticky=tk.W, pady=5)
        ttk.Label(old_logon_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.old_username = ttk.Entry(old_logon_frame, width=20)
        self.old_username.pack(side=tk.LEFT)

        # Usuário espelho
        ttk.Label(self.frame, text="Usuário espelho para cópia:").grid(row=8, column=0, sticky=tk.W)
        template_frame = ttk.Frame(self.frame)
        template_frame.grid(row=8, column=1, pady=5, sticky=tk.EW)

        self.template_user = ttk.Combobox(template_frame, width=25)
        self.template_user.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.template_user.set("Digite para pesquisar...")
        self.template_user.bind("<KeyRelease>", self.filter_template_users_with_status)

        ttk.Button(template_frame, text="Limpar", width=8, command=self.clear_template_search).pack(side=tk.LEFT, padx=(5, 0))

        # Credenciais do TI
        ttk.Separator(self.frame, orient=tk.HORIZONTAL).grid(row=9, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(self.frame, text="Credenciais do Grupo de TI", style="Header.TLabel").grid(row=10, column=0, columnspan=2, pady=5)
        ttk.Label(self.frame, text=f"Utilize um usuário de um dos grupos: {', '.join(GRUPOS_PERMITIDOS)}").grid(row=11, column=0, columnspan=2, sticky=tk.W)

        ttk.Label(self.frame, text="Usuário de Rede:").grid(row=12, column=0, sticky=tk.W)
        user_frame = ttk.Frame(self.frame)
        user_frame.grid(row=12, column=1, sticky=tk.W)
        ttk.Label(user_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.admin_user = ttk.Entry(user_frame, width=25)
        self.admin_user.pack(side=tk.LEFT)

        ttk.Label(self.frame, text="Senha:").grid(row=13, column=0, sticky=tk.W)
        self.admin_password = ttk.Entry(self.frame, width=30, show="*")
        self.admin_password.grid(row=13, column=1, pady=5, sticky=tk.EW)

        self.test_btn = ttk.Button(self.frame, text="Verificar Credenciais e Permissões", command=self.verify_ti_credentials)
        self.test_btn.grid(row=14, column=0, columnspan=2, pady=10)
        self.connection_status = ttk.Label(self.frame, text="", font=("Arial", 9))
        self.connection_status.grid(row=15, column=0, columnspan=2)

        # Botões
        btn_frame = ttk.Frame(self.frame)
        btn_frame.grid(row=16, column=0, columnspan=2, pady=20)

        self.create_btn = ttk.Button(btn_frame, text="Avançar >", width=10, command=self.create_user, state=tk.DISABLED)
        self.create_btn.pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancelar", width=10, command=self.root.destroy).pack(side=tk.LEFT, padx=5)

        self.frame.columnconfigure(1, weight=1)

    # ================= FUNÇÕES AUXILIARES =================

    def update_full_name(self, event=None):
        if not self.full_name_edited:
            first = self.first_name.get().strip()
            last = self.last_name.get().strip()
            full = f"{first} {last}".strip()
            self.full_name.delete(0, tk.END)
            self.full_name.insert(0, full)

    def on_full_name_edit(self, event):
        self.full_name_edited = True

    def mark_login_edited(self, event):
        self.login_edited = True

    def generate_login_from_fullname(self, event=None):
        if self.login_edited:
            return
        full_name = self.full_name.get().strip()
        if not full_name:
            return
        generated_login = self.generate_login(full_name)
        if generated_login:
            self.username.delete(0, tk.END)
            self.username.insert(0, generated_login)
            self.sync_usernames()

    def generate_login(self, full_name):
        if not full_name.strip():
            return ""
        full_name = unicodedata.normalize('NFD', full_name)
        full_name = full_name.encode('ascii', 'ignore').decode('utf-8').lower()
        full_name = re.sub(r'[^a-z\s]', '', full_name)
        parts = [p for p in full_name.split() if p]

        if not parts:
            return ""

        first_letter = parts[0][0] if parts[0] else ""
        login_parts = [first_letter, "_"]

        if len(parts) < 2:
            base = parts[0].ljust(6, 'x')
            login_parts.append(base[:3])
            login_parts.append(base[3:6])
        else:
            last_part = parts[-1][:3].ljust(3, 'x')
            first_last = parts[1][:3].ljust(3, 'x')
            login_parts.append(first_last)
            login_parts.append(last_part)

        return ''.join(login_parts)[:20]

    def sync_usernames(self, event=None):
        new_user = self.username.get().strip()
        if new_user:
            self.old_username.delete(0, tk.END)
            self.old_username.insert(0, new_user)

    def clear_template_search(self):
        self.template_user.set('')
        self.template_user['values'] = self.all_template_users
        if self.all_template_users:
            self.template_user.set("Digite para pesquisar...")

    def filter_template_users_with_status(self, event):
        search_term = self.template_user.get().strip().lower()
        if not search_term:
            self.template_user['values'] = self.all_template_users_with_status
            return
        filtered = [user for user in self.all_template_users_with_status if search_term in user.lower()]
        self.template_user['values'] = filtered
    
    def load_template_users(self):
        """Carrega todos os usuários disponíveis para usar como modelo no AD"""
        if not hasattr(self, "conn_create") or not self.conn_create.bound:
            messagebox.showerror("Erro", "Conecte-se com credenciais válidas antes de carregar os modelos.")
            return

        conn = self.conn_create
        try:
            # Busca todos usuários do domínio
            search_base = conn.server.info.other["defaultNamingContext"][0]
            conn.search(
                search_base=search_base,
                search_filter="(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["cn", "distinguishedName", "sAMAccountName"]
            )

            self.all_template_users = []
            self.all_template_users_with_status = []
            self.template_dns = []
            self.template_ous = []
            self.template_logins = []

            for entry in conn.entries:
                cn = str(entry.cn)
                dn = str(entry.distinguishedName)
                sam = str(entry.sAMAccountName)
                ou = ",".join(dn.split(",")[1:])

                self.all_template_users.append(cn)
                self.all_template_users_with_status.append(f"{cn} ({sam})")
                self.template_dns.append(dn)
                self.template_ous.append(ou)
                self.template_logins.append(sam)

        # Preenche combobox
            self.template_user["values"] = self.all_template_users_with_status

        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar usuários: {e}")

    def verify_ti_credentials(self):
        user = self.admin_user.get().strip()
        password = self.admin_password.get()
        if not user or not password:
            messagebox.showerror("Erro","Preencha usuário e senha")
            return
        try:
            self.conn_create = conectar_ldap(user,password)
            if self.conn_create.bound:
                self.connection_status.config(text="✅ Credenciais válidas", foreground="green")
                self.create_btn.config(state=tk.NORMAL)
            else:
                raise Exception("Falha autenticação")
        except Exception as e:
            self.connection_status.config(text=f"❌ {e}", foreground="red")
            self.create_btn.config(state=tk.DISABLED)
        
        self.load_template_users()

    # ================= LÓGICA DE CRIAÇÃO =================

    def generate_unique_login(self, conn, login, old_login):
        """
        Garante que logins sejam únicos no AD.
        Se já existir, acrescenta um número incremental.
        """
        unique_login = login
        unique_old = old_login
        counter = 1

        while True:
            search_filter = f"(|(sAMAccountName={unique_old})(userPrincipalName={unique_login}@motivabpo.com.br))"
            conn.search(search_base=self.conn_create.server.info.other['defaultNamingContext'][0],
                        search_filter=search_filter,
                        attributes=["distinguishedName"])
            if not conn.entries:
                break
            unique_login = f"{login}{counter}"
            unique_old = f"{old_login}{counter}"
            counter += 1

        return unique_login, unique_old

    def create_user(self):
        if not hasattr(self, "conn_create") or not self.conn_create.bound:
            messagebox.showerror("Erro", "Conexão LDAP não está ativa. Verifique as credenciais.")
            return

        conn = self.conn_create

        # --- Dados da tela ---
        first_name = self.first_name.get().strip()
        last_name = self.last_name.get().strip()
        full_name = self.full_name.get().strip()
        username = self.username.get().strip()
        old_username = self.old_username.get().strip()
        template_input = self.template_user.get().strip()

        if not full_name or not username or not old_username or not template_input:
            messagebox.showerror("Erro", "Preencha todos os campos obrigatórios.")
            return

        try:
            # --- Encontrar modelo ---
            selected_index = None
            for i, user in enumerate(self.all_template_users_with_status):
                if template_input.lower() == user.lower():
                    selected_index = i
                    break
                if self.template_logins and template_input.lower() == self.template_logins[i].lower():
                    selected_index = i
                    break

            if selected_index is None:
                messagebox.showerror("Erro", "Selecione um modelo válido da lista!")
                return

            template_dn = self.template_dns[selected_index]
            container_dn = ",".join(template_dn.split(",")[1:])
            new_dn = f"cn={full_name},{container_dn}"

            # --- Buscar modelo no AD ---
            conn.search(template_dn, '(objectClass=user)', attributes=['*', 'memberOf'])
            if not conn.entries:
                raise Exception("Usuário espelho não encontrado.")
            template = conn.entries[0]
            object_classes = [str(oc) for oc in template.objectClass.values]

            # --- Verificar login único ---
            unique_login, unique_old_login = self.generate_unique_login(conn, username, old_username)

            # --- Criar usuário ---
            attributes = {
                'objectClass': object_classes,
                'cn': full_name,
                'givenName': first_name,
                'sn': last_name,
                'displayName': full_name,
                'sAMAccountName': unique_old_login,
                'userPrincipalName': f"{unique_login}@motivabpo.com.br",
                'mail': f"{unique_login}@motivabpo.com.br",
                'userAccountControl': 544,
                'name': full_name,
                'instanceType': '4',
                'accountExpires': '0',
            }

            if not conn.add(dn=new_dn, attributes=attributes):
                raise Exception(f"Erro ao criar usuário: {conn.last_error}")

            logging.info(f"Usuário criado: {new_dn}")

            # --- Definir senha ---
            password_value = '!@123456Aa'.encode('utf-16-le')
            conn.modify(new_dn, {'unicodePwd': [(MODIFY_REPLACE, [password_value])]})

            # --- Ativar conta ---
            conn.modify(new_dn, {
                'userAccountControl': [(MODIFY_REPLACE, [512])],
                'pwdLastSet': [(MODIFY_REPLACE, [0])]
            })

            # --- Copiar grupos ---
            if hasattr(template, 'memberOf') and template.memberOf.values:
                for grupo_dn in template.memberOf.values:
                    conn.modify(grupo_dn, {'member': [(MODIFY_ADD, [new_dn])]})

            # --- Sucesso ---
            success_msg = (
                f"Usuário criado com sucesso!\n\n"
                f"Nome: {full_name}\n"
                f"Login: {unique_login}@motivabpo.com.br\n"
                f"Login antigo: {DOMINIO_AD}\\{unique_old_login}\n"
                f"OU: {container_dn}\n\n"
                f"Senha inicial: !@123456Aa"
            )
            messagebox.showinfo("Sucesso", success_msg)

        except Exception as e:
            logging.error(f"Erro ao criar usuário: {e}")
            messagebox.showerror("Erro", str(e))
