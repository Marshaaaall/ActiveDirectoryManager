import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import pandas as pd
import threading
import logging
import unicodedata
import re
from config import DOMINIO_AD
from ldap_utils import conectar_ldap, create_user
from ldap3 import MODIFY_REPLACE, MODIFY_ADD


class MassImportFrame(ttk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent)
        self.root = root
        self.import_data = None
        self.conn_mass = None
        self.mirror_user_ou = None
        self.all_template_users_with_status = []
        self.template_dns = []
        self.template_ous = []
        self.template_logins = []
        self.import_results = []  # Para armazenar os resultados da importação

        self._setup_ui()

    def _setup_ui(self):
        ttk.Label(self, text="Importação em Massa via Excel", font=("Arial", 14)).grid(row=0, column=0, columnspan=2, pady=10)

        instructions = (
            "Instruções:\n"
            "1. Prepare uma planilha Excel com as colunas: 'Nome', 'Sobrenome'\n"
            "2. Clique em 'Selecionar Planilha' para carregar os dados\n"
            "3. Selecione um usuário espelho para copiar a OU\n"
            "4. Clique em 'Iniciar Importação' para criar todos os usuários"
        )
        ttk.Label(self, text=instructions, justify=tk.LEFT).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=10)

        ttk.Button(self, text="Selecionar Planilha", command=self.select_spreadsheet).grid(row=2, column=0, columnspan=2, pady=10)

        self.tree_frame = ttk.Frame(self)
        self.tree_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=10)

        scrollbar = ttk.Scrollbar(self.tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=("Nome", "Sobrenome", "Status"),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=10
        )
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)

        for col in ("Nome", "Sobrenome", "Status"):
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150 if col != "Status" else 100)

        ttk.Separator(self, orient=tk.HORIZONTAL).grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=10)
        ttk.Label(self, text="Credenciais do Grupo de TI", font=("Arial", 12)).grid(row=5, column=0, columnspan=2, pady=5)

        ttk.Label(self, text="Usuário de Rede:").grid(row=6, column=0, sticky=tk.W)
        user_frame = ttk.Frame(self)
        user_frame.grid(row=6, column=1, sticky=tk.W)
        ttk.Label(user_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.admin_user = ttk.Entry(user_frame, width=25)
        self.admin_user.pack(side=tk.LEFT)

        ttk.Label(self, text="Senha:").grid(row=7, column=0, sticky=tk.W)
        self.admin_password = ttk.Entry(self, width=30, show="*")
        self.admin_password.grid(row=7, column=1, pady=5, sticky=tk.EW)

        ttk.Label(self, text="Usuário Espelho (para copiar OU):").grid(row=8, column=0, sticky=tk.W)
        template_frame = ttk.Frame(self)
        template_frame.grid(row=8, column=1, pady=5, sticky=tk.EW)

        self.mirror_user = ttk.Combobox(template_frame, width=25)
        self.mirror_user.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.mirror_user.set("Digite para pesquisar...")
        self.mirror_user.bind("<KeyRelease>", self.filter_template_users_with_status)

        ttk.Button(template_frame, text="Limpar", width=8, command=self.clear_template_search).pack(side=tk.LEFT, padx=(5, 0))

        ttk.Button(self, text="Verificar Credenciais", command=self.verify_mass_credentials).grid(row=9, column=0, columnspan=2, pady=10)
        self.mass_connection_status = ttk.Label(self, text="", font=("Arial", 9))
        self.mass_connection_status.grid(row=10, column=0, columnspan=2)

        self.import_btn = ttk.Button(self, text="Iniciar Importação", command=self.start_mass_import, state=tk.DISABLED)
        self.import_btn.grid(row=11, column=0, columnspan=2, pady=20)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=300, mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(row=12, column=0, columnspan=2, pady=10)

        self.import_status = ttk.Label(self, text="", foreground="blue")
        self.import_status.grid(row=13, column=0, columnspan=2)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)

    def select_spreadsheet(self):
        file_path = filedialog.askopenfilename(title="Selecione a planilha Excel", filetypes=[("Excel Files", "*.xlsx *.xls")])
        if not file_path:
            return
        try:
            df = pd.read_excel(file_path)
            required_cols = {"Nome", "Sobrenome"}
            missing = required_cols - set(df.columns)
            if missing:
                messagebox.showerror("Erro", f"Faltam colunas obrigatórias: {', '.join(missing)}")
                return

            df = df.fillna('')
            self.import_data = df
            self._load_tree(df)
            self.import_status.config(text=f"Planilha carregada com {len(df)} registros", foreground="green")
        except Exception as e:
            logging.error(f"Erro ao ler planilha: {e}")
            messagebox.showerror("Erro", f"Falha ao ler planilha: {e}")

    def _load_tree(self, df):
        self.tree.delete(*self.tree.get_children())
        for _, row in df.iterrows():
            self.tree.insert("", "end", values=(row["Nome"], row["Sobrenome"], "Pendente"))

    def clear_template_search(self):
        self.mirror_user.set('')
        self.mirror_user['values'] = self.all_template_users_with_status
        if self.all_template_users_with_status:
            self.mirror_user.set("Digite para pesquisar...")

    def filter_template_users_with_status(self, event):
        search_term = self.mirror_user.get().strip().lower()
        if not search_term:
            self.mirror_user['values'] = self.all_template_users_with_status
            return
        filtered = [user for user in self.all_template_users_with_status if search_term in user.lower()]
        self.mirror_user['values'] = filtered

    def load_template_users(self):
        """Carrega todos os usuários disponíveis para usar como modelo no AD"""
        if not hasattr(self, "conn_mass") or not self.conn_mass.bound:
            messagebox.showerror("Erro", "Conecte-se com credenciais válidas antes de carregar os modelos.")
            return

        conn = self.conn_mass
        try:
            # Busca todos usuários do domínio
            search_base = conn.server.info.other["defaultNamingContext"][0]
            conn.search(
                search_base=search_base,
                search_filter="(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                attributes=["cn", "distinguishedName", "sAMAccountName"]
            )

            self.all_template_users_with_status = []
            self.template_dns = []
            self.template_ous = []
            self.template_logins = []

            for entry in conn.entries:
                cn = str(entry.cn)
                dn = str(entry.distinguishedName)
                sam = str(entry.sAMAccountName)
                ou = ",".join(dn.split(",")[1:])

                self.all_template_users_with_status.append(f"{cn} ({sam})")
                self.template_dns.append(dn)
                self.template_ous.append(ou)
                self.template_logins.append(sam)

            # Preenche combobox
            self.mirror_user["values"] = self.all_template_users_with_status

        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao carregar usuários: {e}")

    def verify_mass_credentials(self):
        username = self.admin_user.get().strip()
        password = self.admin_password.get()
        if not username or not password:
            messagebox.showerror("Erro", "Preencha usuário e senha")
            return
        
        try:
            self.conn_mass = conectar_ldap(username, password)
            if self.conn_mass.bound:
                self.mass_connection_status.config(text="✅ Credenciais válidas", foreground="green")
                self.import_btn.config(state=tk.NORMAL)
                # Carrega usuários para o combobox
                self.load_template_users()
            else:
                raise Exception("Falha na autenticação LDAP")
        except Exception as e:
            self.mass_connection_status.config(text=f"❌ {e}", foreground="red")
            self.import_btn.config(state=tk.DISABLED)

    def start_mass_import(self):
        if self.import_data is None or self.import_data.empty:
            messagebox.showwarning("Aviso", "Nenhuma planilha carregada")
            return
        if not self.conn_mass or not self.conn_mass.bound:
            messagebox.showwarning("Aviso", "Conexão LDAP não verificada")
            return

        template_input = self.mirror_user.get().strip()
        if not template_input:
            messagebox.showwarning("Aviso", "Informe o usuário espelho")
            return

        # Encontrar o modelo selecionado
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

        # Obter a OU do usuário espelho
        try:
            template_dn = self.template_dns[selected_index]
            container_dn = ",".join(template_dn.split(",")[1:])
            self.mirror_user_ou = container_dn
            
            if not self.mirror_user_ou:
                messagebox.showerror("Erro", f"Não foi possível obter a OU do usuário espelho '{template_input}'")
                return
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao obter OU do usuário espelho: {e}")
            return

        self.progress_var.set(0)
        self.progress_bar["maximum"] = len(self.import_data)
        self.import_status.config(text="Iniciando importação...", foreground="blue")
        self.import_results = []  # Limpa resultados anteriores

        threading.Thread(target=self._thread_import, daemon=True).start()

    def _thread_import(self):
        total = len(self.import_data)
        success, errors = 0, 0

        for i, row in self.import_data.iterrows():
            result = {"nome": row["Nome"].strip(), "sobrenome": row["Sobrenome"].strip(), "status": "Erro", "erro": ""}
            
            try:
                nome = row["Nome"].strip()
                sobrenome = row["Sobrenome"].strip()
                
                # Gerar login único
                full_name = f"{nome} {sobrenome}"
                login = self.generate_login(full_name)
                old_login = login
                
                # Verificar se login já existe e gerar único se necessário
                login, old_login = self.generate_unique_login(self.conn_mass, login, old_login)
                
                # Criar usuário
                if self.create_user_in_ou(nome, sobrenome, login, old_login):
                    success += 1
                    status = "Sucesso"
                    result["status"] = "Sucesso"
                    result["login"] = login
                    result["old_login"] = old_login
                else:
                    errors += 1
                    status = "Erro"
                    result["erro"] = "Falha ao criar usuário"
            except Exception as e:
                logging.error(f"Erro criando usuário {row}: {e}")
                errors += 1
                status = "Erro"
                result["erro"] = str(e)

            self.import_results.append(result)
            self.root.after(0, lambda cur=i+1, s=success, er=errors, st=status, idx=i: self._update_progress_and_tree(cur, s, er, total, idx, st))

        self.root.after(0, lambda: self.import_status.config(text="✅ Importação concluída!", foreground="green"))
        self.root.after(1000, self.show_import_results)  # Mostra resultados após 1 segundo

    def _update_progress_and_tree(self, current, success, errors, total, row_index, status):
        self.progress_var.set(current)
        self.import_status.config(text=f"Processados: {current}/{total} | Sucessos: {success} | Erros: {errors}", foreground="blue")
        
        # Atualize o status na treeview
        item = self.tree.get_children()[row_index]
        current_values = self.tree.item(item, 'values')
        self.tree.item(item, values=(current_values[0], current_values[1], status))

    def generate_login(self, full_name):
        if not full_name.strip():
            return ""
        full_name = unicodedata.normalize('NFD', full_name)
        full_name = full_name.encode('ascii', 'ignore').decode('utf-8').lower()
        full_name = re.sub(r'[^a-z\s]', '', full_name)
        parts = [p for p in full_name.split() if p]

        if not parts:
            return ""

        first_letter = parts[0][0]
        login_parts = [first_letter, "_"]

        # Filtrar partes relevantes (ignorar palavras com menos de 3 letras)
        relevant_parts = [p for p in parts if len(p) >= 3]
    
        if not relevant_parts:
            # Se não há partes relevantes, usa o primeiro nome preenchendo com 'x'
            base = parts[0].ljust(6, 'x')
            login_parts.append(base[:3])
            login_parts.append(base[3:6])
        elif len(relevant_parts) < 2:
            # Se há apenas uma parte relevante, usa ela e o primeiro nome
            base = relevant_parts[0].ljust(6, 'x')
            login_parts.append(base[:3])
            login_parts.append(parts[0][:3].ljust(3, 'x'))
        else:
            # Usa o primeiro sobrenome relevante e o último sobrenome relevante
            first_relevant = relevant_parts[1][:3].ljust(3, 'x')
            last_relevant = relevant_parts[-1][:3].ljust(3, 'x')
            login_parts.append(first_relevant)
            login_parts.append(last_relevant)

        return ''.join(login_parts)[:20]

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
            conn.search(search_base=conn.server.info.other['defaultNamingContext'][0],
                        search_filter=search_filter,
                        attributes=["distinguishedName"])
            if not conn.entries:
                break
            unique_login = f"{login}{counter}"
            unique_old = f"{old_login}{counter}"
            counter += 1

        return unique_login, unique_old

    def create_user_in_ou(self, first_name, last_name, username, old_username):
        """Cria um usuário na OU especificada"""
        try:
            full_name = f"{first_name} {last_name}"
            new_dn = f"cn={full_name},{self.mirror_user_ou}"

            # Buscar modelo no AD para copiar atributos
            template_dn = self.template_dns[0]  # Usa o primeiro usuário da lista como modelo
            self.conn_mass.search(template_dn, '(objectClass=user)', attributes=['*', 'memberOf'])
            if not self.conn_mass.entries:
                raise Exception("Usuário espelho não encontrado.")
            
            template = self.conn_mass.entries[0]
            object_classes = [str(oc) for oc in template.objectClass.values]

            # Criar usuário
            attributes = {
                'objectClass': object_classes,
                'cn': full_name,
                'givenName': first_name,
                'sn': last_name,
                'displayName': full_name,
                'sAMAccountName': old_username,
                'userPrincipalName': f"{username}@motivabpo.com.br",
                'mail': f"{username}@motivabpo.com.br",
                'userAccountControl': 544,
                'name': full_name,
                'instanceType': '4',
                'accountExpires': '0',
            }

            if not self.conn_mass.add(dn=new_dn, attributes=attributes):
                raise Exception(f"Erro ao criar usuário: {self.conn_mass.last_error}")

            logging.info(f"Usuário criado: {new_dn}")

            # Definir senha
            password_value = '!@123456Aa'.encode('utf-16-le')
            self.conn_mass.modify(new_dn, {'unicodePwd': [(MODIFY_REPLACE, [password_value])]})

            # Ativar conta
            self.conn_mass.modify(new_dn, {
                'userAccountControl': [(MODIFY_REPLACE, [512])],
                'pwdLastSet': [(MODIFY_REPLACE, [0])]
            })

            # Copiar grupos do usuário modelo
            if hasattr(template, 'memberOf') and template.memberOf.values:
                for grupo_dn in template.memberOf.values:
                    self.conn_mass.modify(grupo_dn, {'member': [(MODIFY_ADD, [new_dn])]})

            return True

        except Exception as e:
            logging.error(f"Erro ao criar usuário {first_name} {last_name}: {e}")
            return False

    def show_import_results(self):
        """Exibe uma janela com os resultados detalhados da importação"""
        results_window = tk.Toplevel(self.root)
        results_window.title("Resultados da Importação")
        results_window.geometry("800x600")
        results_window.transient(self.root)
        results_window.grab_set()

        # Frame principal
        main_frame = ttk.Frame(results_window, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main_frame, text="Resultados da Importação em Massa", font=("Arial", 14)).pack(pady=10)

        # Text area com scroll
        text_frame = ttk.Frame(main_frame)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        text_area = scrolledtext.ScrolledText(text_frame, wrap=tk.WORD, width=80, height=25)
        text_area.pack(fill=tk.BOTH, expand=True)

        # Contadores
        success_count = sum(1 for r in self.import_results if r["status"] == "Sucesso")
        error_count = len(self.import_results) - success_count

        # Preencher text area com resultados
        text_area.insert(tk.END, f"RESUMO DA IMPORTAÇÃO:\n")
        text_area.insert(tk.END, f"Total de usuários processados: {len(self.import_results)}\n")
        text_area.insert(tk.END, f"Sucessos: {success_count}\n")
        text_area.insert(tk.END, f"Erros: {error_count}\n\n")
        text_area.insert(tk.END, f"OU utilizada: {self.mirror_user_ou}\n\n")

        text_area.insert(tk.END, "DETALHES POR USUÁRIO:\n")
        text_area.insert(tk.END, "="*80 + "\n")

        for i, result in enumerate(self.import_results, 1):
            text_area.insert(tk.END, f"{i}. {result['nome']} {result['sobrenome']}: {result['status']}\n")
            
            if result["status"] == "Sucesso":
                text_area.insert(tk.END, f"   Login: {result['login']}@motivabpo.com.br\n")
                text_area.insert(tk.END, f"   Login antigo: {DOMINIO_AD}\\{result['old_login']}\n")
                text_area.insert(tk.END, f"   Senha inicial: !@123456Aa\n")
            else:
                text_area.insert(tk.END, f"   Erro: {result['erro']}\n")
            
            text_area.insert(tk.END, "-"*80 + "\n")

        text_area.config(state=tk.DISABLED)  # Tornar o texto somente leitura

        # Botão de fechar
        ttk.Button(main_frame, text="Fechar", command=results_window.destroy).pack(pady=10)