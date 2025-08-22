import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import logging
import pandas as pd
import os
from datetime import datetime
from ldap3.utils.dn import escape_rdn
from config import DOMINIO_AD, BASE_DN
from ldap3 import  SUBTREE
from ldap_utils import conectar_ldap, extract_ou_from_dn, is_account_disabled

class MassUsersFrame(ttk.Frame):
    def __init__(self, parent, root):
        super().__init__(parent)
        self.root = root
        self.conn_move = None
        self.all_users = []
        self.ous_list = []
        self.mass_move_data = None
        
        self._setup_ui()

    def _setup_ui(self):
        # Título
        ttk.Label(self, text="Mover Usuários para outra OU", style="Header.TLabel").grid(row=0, column=0, columnspan=2, pady=10)

        # Seção de pesquisa de usuários
        ttk.Label(self, text="Pesquisar Usuários:").grid(row=1, column=0, sticky=tk.W)
        self.user_search_var = tk.StringVar()
        user_search_frame = ttk.Frame(self)
        user_search_frame.grid(row=1, column=1, sticky=tk.EW, pady=5)

        self.user_search_entry = ttk.Entry(user_search_frame, width=30, textvariable=self.user_search_var)
        self.user_search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.user_search_entry.bind("<KeyRelease>", self.filter_users)

        ttk.Button(user_search_frame, text="Pesquisar", width=10, command=self.load_users).pack(side=tk.LEFT, padx=(5, 0))
        ttk.Button(user_search_frame, text="Atualizar", width=10, command=self.load_users).pack(side=tk.LEFT, padx=(5, 0))

        # Lista de usuários
        self.move_users_tree = ttk.Treeview(
            self,
            columns=("selected", "username", "login", "ou", "status"),
            show="headings",
            height=8
        )
        self.move_users_tree.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=10)
        
        # Configurar colunas
        self.move_users_tree.heading("selected", text="Selecionar")
        self.move_users_tree.heading("username", text="Usuário")
        self.move_users_tree.heading("login", text="login")
        self.move_users_tree.heading("ou", text="OU Atual")
        self.move_users_tree.heading("status", text="Status")
        
        self.move_users_tree.column("selected", width=80, anchor="center")
        self.move_users_tree.column("username", width=150)
        self.move_users_tree.column("login", width=150)
        self.move_users_tree.column("ou", width=250)
        self.move_users_tree.column("status", width=80)
        
        # Configurar tags para status
        self.move_users_tree.tag_configure("disabled", foreground='grey')
        self.move_users_tree.tag_configure("active", foreground='black')
        
        # Vincular evento de clique
        self.move_users_tree.bind("<Button-1>", self.on_tree_click)

        # Seção de destino
        ttk.Label(self, text="Mover para OU:").grid(row=3, column=0, sticky=tk.W)
        self.target_ou = ttk.Combobox(self, width=40)
        self.target_ou.grid(row=3, column=1, pady=5, sticky=tk.EW)

        # Seção de credenciais
        ttk.Separator(self, orient=tk.HORIZONTAL).grid(
            row=4, column=0, columnspan=2, sticky=tk.EW, pady=10
        )

        ttk.Label(self, text="Credenciais do Grupo de TI", style="Header.TLabel").grid(row=5, column=0, columnspan=2, pady=5)

        ttk.Label(self, text="Usuário de Rede:").grid(row=6, column=0, sticky=tk.W)
        move_user_frame = ttk.Frame(self)
        move_user_frame.grid(row=6, column=1, sticky=tk.W)
        ttk.Label(move_user_frame, text=f"{DOMINIO_AD}\\", foreground="gray").pack(side=tk.LEFT)
        self.move_admin_user = ttk.Entry(move_user_frame, width=25)
        self.move_admin_user.pack(side=tk.LEFT)

        ttk.Label(self, text="Senha:").grid(row=7, column=0, sticky=tk.W)
        self.move_admin_password = ttk.Entry(self, width=30, show="*")
        self.move_admin_password.grid(row=7, column=1, pady=5, sticky=tk.EW)

        # Botão de verificação de credenciais
        self.move_test_btn = ttk.Button(
            self, 
            text="Verificar Credenciais", 
            command=self.verify_move_credentials
        )
        self.move_test_btn.grid(row=8, column=0, columnspan=2, pady=10)
        self.move_connection_status = ttk.Label(self, text="", font=("Arial", 9))
        self.move_connection_status.grid(row=9, column=0, columnspan=2)

        # Botão de mover usuários
        self.move_btn = ttk.Button(
            self,
            text="Mover Usuários Selecionados",
            command=self.start_move_thread,
            state=tk.DISABLED
        )
        self.move_btn.grid(row=10, column=0, columnspan=2, pady=20)


        # Status da operação individual
        self.move_status = ttk.Label(self, text="", foreground="blue")
        self.move_status.grid(row=12, column=0, columnspan=2)

        # Separador para seção de movimentação em massa
        ttk.Separator(self, orient=tk.HORIZONTAL).grid(
            row=13, column=0, columnspan=2, sticky=tk.EW, pady=10
        )

        # Seção de movimentação em massa
        ttk.Label(self, text="Movimentação em Massa via Planilha", style="Header.TLabel").grid(row=14, column=0, columnspan=2, pady=10)

        # Botão para selecionar planilha
        self.mass_select_btn = ttk.Button(
            self,
            text="Selecionar Planilha",
            command=self.select_mass_spreadsheet
        )
        self.mass_select_btn.grid(row=15, column=0, columnspan=2, pady=10)

        # Área de visualização da planilha
        self.mass_tree_frame = ttk.Frame(self)
        self.mass_tree_frame.grid(row=16, column=0, columnspan=2, sticky="nsew", pady=10)

        # Barra de rolagem
        scrollbar_mass = ttk.Scrollbar(self.mass_tree_frame)
        scrollbar_mass.pack(side=tk.RIGHT, fill=tk.Y)

        # Treeview para mostrar os dados da planilha
        self.mass_tree = ttk.Treeview(
            self.mass_tree_frame, 
            columns=("Usuário",),
            show="headings",
            yscrollcommand=scrollbar_mass.set,
            height=5
        )
        self.mass_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar_mass.config(command=self.mass_tree.yview)

        # Configurar colunas
        self.mass_tree.heading("Usuário", text="Usuário")
        self.mass_tree.column("Usuário", width=300)

        # Botão de mover em massa
        self.mass_move_btn = ttk.Button(
            self,
            text="Mover Usuários da Planilha",
            command=self.start_mass_move,
            state=tk.DISABLED
        )
        self.mass_move_btn.grid(row=17, column=0, columnspan=2, pady=10)

        # Barra de progresso para operação em massa
        self.mass_progress_var = tk.DoubleVar()
        self.mass_progress_bar = ttk.Progressbar(
            self, 
            orient=tk.HORIZONTAL, 
            length=300, 
            mode='determinate',
            variable=self.mass_progress_var
        )
        self.mass_progress_bar.grid(row=18, column=0, columnspan=2, pady=5)

        # Status da operação em massa
        self.mass_status = ttk.Label(self, text="", foreground="blue")
        self.mass_status.grid(row=19, column=0, columnspan=2)

        # Ajustar layout
        self.columnconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)
        self.rowconfigure(16, weight=1)

    def on_tree_click(self, event):
        """Lida com cliques na coluna de seleção"""
        try:
            region = self.move_users_tree.identify("region", event.x, event.y)
            if region == "cell":
                column = self.move_users_tree.identify_column(event.x)
                item = self.move_users_tree.identify_row(event.y)
                if column == "#1" and item:
                    values = list(self.move_users_tree.item(item, "values"))
                    tags = self.move_users_tree.item(item, "tags")
                    # Só permitir seleção se não estiver desativado
                    if not tags or "disabled" not in tags:
                        values[0] = "[X]" if values[0] == "[ ]" else "[ ]"
                        self.move_users_tree.item(item, values=values)
        except Exception as e:
            logging.error(f"Erro ao processar clique na treeview: {str(e)}")

    def filter_users(self, event=None):
        """Filtra a lista de usuários conforme o texto digitado"""
        search_term = self.user_search_var.get().lower()
        
        if not search_term:
            # Mostrar todos os usuários
            self.move_users_tree.delete(*self.move_users_tree.get_children())
            for user in self.all_users:
                cn, samaccount, ou, status, is_disabled = user
                tags = ("disabled",) if is_disabled else ("active",)
                self.move_users_tree.insert("", "end", values=("[ ]", cn, samaccount, ou, status), tags=tags)
            return
        
        # Filtrar usuários
        filtered = [user for user in self.all_users if search_term in user[0].lower() or search_term in user[1].lower()]
        
        self.move_users_tree.delete(*self.move_users_tree.get_children())
        for user in filtered:
            cn, samaccount, ou, status, is_disabled = user
            tags = ("disabled",) if is_disabled else ("active",)
            self.move_users_tree.insert("", "end", values=("[ ]", cn, samaccount, ou, status), tags=tags)

    def load_users(self):
        """Carrega todos os usuários do AD"""
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
                attributes=['cn', 'sAMAccountName', 'distinguishedName', 'userAccountControl'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn_move.entries:
                cn = entry.cn.value
                samaccount = entry.sAMAccountName.value
                dn = entry.distinguishedName.value
                uac = entry.userAccountControl.value if hasattr(entry, "userAccountControl") else None
                
                # Extrair OU do DN
                ou = extract_ou_from_dn(dn)
                is_disabled = is_account_disabled(uac)
                status = "Desativado" if is_disabled else "Ativo"
                
                self.all_users.append((cn, samaccount, ou, status, is_disabled))
            
            # Atualizar treeview
            self.filter_users()
            self.move_status.config(text=f"{len(self.all_users)} usuários carregados", foreground="green")
            
        except Exception as e:
            error_msg = f"Erro ao carregar usuários: {str(e)}"
            logging.error(error_msg)
            self.move_status.config(text=error_msg, foreground="red")

    def load_ous(self):
        """Carrega todas as OUs do AD"""
        if not hasattr(self, 'conn_move') or not self.conn_move.bound:
            return False
        
        try:
            self.ous_list = ["Domínio Raiz"]  # Adicionar opção para raiz
            
            # Buscar todas as OUs
            self.conn_move.search(
                search_base=BASE_DN,
                search_filter='(objectClass=organizationalUnit)',
                attributes=['distinguishedName'],
                search_scope=SUBTREE
            )
            
            for entry in self.conn_move.entries:
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
            self.conn_move = conectar_ldap(username, password)
            
            # Carregar OUs
            if self.load_ous():
                self.move_connection_status.config(
                    text=f"✅ Credenciais validadas com sucesso!",
                    foreground="green"
                )
                self.move_btn.config(state=tk.NORMAL)
                self.mass_move_btn.config(state=tk.NORMAL)
                self.move_status.config(text="Credenciais validadas - Pronto para mover usuários", foreground="green")
                logging.info("Credenciais validadas para mover usuários")
                
                # Carregar usuários automaticamente após conexão
                self.load_users()
            
        except Exception as e:
            error_msg = f"Erro: {str(e)}"
            logging.error(f"Falha na verificação de credenciais (mover usuários): {error_msg}")
            self.move_connection_status.config(text=f"❌ {error_msg}", foreground="red")
            self.move_btn.config(state=tk.DISABLED)
            self.mass_move_btn.config(state=tk.DISABLED)
            self.move_status.config(text=error_msg, foreground="red")

    def start_move_thread(self):
        """Inicia a thread para mover usuários selecionados"""
        threading.Thread(target=self.move_selected_users, daemon=True).start()

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
                selected_users.append((values[1], values[2], values[3]))  # (cn, samaccount, current_ou)

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

        # Configurar progresso
        self.progress_var.set(0)
        self.progress_bar["maximum"] = len(selected_users)
        self.move_status.config(text="Iniciando movimentação...", foreground="blue")

        success_count = 0
        error_count = 0
        log_details = []

        for i, (cn, login, current_ou) in enumerate(selected_users, 1):
            try:
                # Buscar DN completo do usuário
                self.conn_move.search(
                    search_base=BASE_DN,
                    search_filter=f"(sAMAccountName={escape_rdn(login)})",
                    attributes=['distinguishedName'],
                    search_scope=SUBTREE,
                    size_limit=1
                )
                
                if not self.conn_move.entries:
                    raise Exception(f"Usuário não encontrado: {login}")
                
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
                log_details.append(f"✅ {login}: Movido com sucesso para {new_parent}")
                
            except Exception as e:
                error_count += 1
                error_msg = str(e)
                log_details.append(f"❌ {login}: {error_msg}")
                logging.error(f"Erro ao mover {login}: {error_msg}")
            
            # Atualizar progresso
            self.root.after(0, lambda c=i, s=success_count, e=error_count: 
                           self.update_progress(c, s, e, len(selected_users)))
        
        # Resultado final
        self.root.after(0, lambda: self.finish_move(success_count, error_count, log_details, len(selected_users)))

    def update_progress(self, current, success, errors, total):
        """Atualiza a barra de progresso e status"""
        self.progress_var.set(current)
        self.move_status.config(
            text=f"Processando: {current}/{total} | Sucessos: {success} | Erros: {errors}",
            foreground="blue"
        )

    def finish_move(self, success_count, error_count, log_details, total):
        """Finaliza a operação de movimentação"""
        result_msg = (
            f"Movimentação concluída!\n\n"
            f"Total de usuários: {total}\n"
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

    def select_mass_spreadsheet(self):
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
            for item in self.mass_tree.get_children():
                self.mass_tree.delete(item)
            
            # Adicionar dados à treeview
            for _, row in df.iterrows():
                username = str(row['Usuário']).strip()
                self.mass_tree.insert("", "end", values=(username,))
            
            # Armazenar os dados para processamento
            self.mass_move_data = df
            self.mass_status.config(text=f"Planilha carregada com {len(df)} usuários", foreground="green")
            
        except Exception as e:
            error_msg = f"Falha ao ler a planilha: {str(e)}"
            messagebox.showerror("Erro", error_msg)
            logging.error(f"Erro ao ler planilha (mover em massa): {error_msg}")
            self.mass_status.config(text=error_msg, foreground="red")

    def start_mass_move(self):
        """Inicia o processo de mover usuários em massa"""
        if not hasattr(self, 'mass_move_data') or self.mass_move_data.empty:
            messagebox.showwarning("Aviso", "Nenhuma planilha carregada ou dados vazios")
            return
        
        target_ou = self.target_ou.get()
        if not target_ou:
            messagebox.showerror("Erro", "Selecione uma OU de destino")
            return
        
        # Desabilitar botões durante a operação
        self.mass_select_btn.config(state=tk.DISABLED)
        self.mass_move_btn.config(state=tk.DISABLED)
        self.move_test_btn.config(state=tk.DISABLED)
        
        # Configurar progresso
        total_users = len(self.mass_move_data)
        self.mass_progress_var.set(0)
        self.mass_progress_bar["maximum"] = total_users
        self.mass_status.config(text=f"Iniciando movimentação de {total_users} usuários...", foreground="blue")
        
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
                    # Buscar DN do usuário
                    self.conn_move.search(
                        search_base=BASE_DN,
                        search_filter=f"(|(cn={username})(sAMAccountName={username}))",
                        attributes=['distinguishedName'],
                        search_scope=SUBTREE
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
                
                # Atualizar progresso
                progress = i + 1
                self.root.after(100, self.update_mass_progress, progress, success_count, error_count, len(self.mass_move_data))
            
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
            
            self.mass_status.config(
                text=result_msg + f"\nLog salvo em: {os.path.abspath(log_filename)}", 
                foreground="green" if error_count == 0 else "orange"
            )
            messagebox.showinfo("Concluído", result_msg + f"\n\nVerifique o log completo em:\n{os.path.abspath(log_filename)}")
        
        except Exception as e:
            error_msg = f"Erro na movimentação em massa: {str(e)}"
            logging.error(error_msg)
            self.mass_status.config(text=error_msg, foreground="red")
        finally:
            # Reabilitar botões
            self.mass_select_btn.config(state=tk.NORMAL)
            self.mass_move_btn.config(state=tk.NORMAL)
            self.move_test_btn.config(state=tk.NORMAL)

    def update_mass_progress(self, current, success, errors, total):
        """Atualiza a barra de progresso e status da movimentação em massa"""
        self.mass_progress_var.set(current)
        self.mass_status.config(
            text=f"Processando: {current}/{total} | Sucessos: {success} | Erros: {errors}",
            foreground="blue"
        )