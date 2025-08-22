import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import logging
import pandas as pd
import os
from datetime import datetime
import ssl

from ldap3 import Server, Connection, Tls, SUBTREE, SIMPLE, NTLM
from ldap3.utils.dn import escape_rdn

# --- Configurações ---
# Adapte estas variáveis para o seu ambiente
DOMINIO_AD = "SEU_DOMINIO"  # Ex: "motiva"
SERVIDOR_AD = "seu_servidor_ad"  # Ex: "10.100.0.10" ou "dc01.dominio.com"
BASE_DN = "dc=seu,dc=dominio"  # Ex: "dc=motiva,dc=matriz"

# Configuração do logging para salvar em um arquivo
logging.basicConfig(
    filename='mass_move_app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    encoding='utf-8'
)

class MassMoveFrame(ttk.Frame):
    """
    Frame principal da aplicação para mover usuários em massa no Active Directory.
    """
    def __init__(self, parent):
        super().__init__(parent, padding="10")
        self.parent = parent
        self.conn_mass_move = None
        self.mass_move_data = None
        self.ous_list = []

        self._setup_ui()

    def _setup_ui(self):
        """
        Configura a interface gráfica da aplicação.
        """
        # Título
        ttk.Label(self, text="Mover Usuários em Massa", font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=10)

        # Instruções
        instructions = (
            "Instruções:\n"
            "1. Prepare uma planilha Excel com a coluna 'Usuário' (nome completo ou login).\n"
            "2. Insira suas credenciais e clique em 'Verificar Credenciais'.\n"
            "3. Selecione a OU de destino para onde os usuários serão movidos.\n"
            "4. Clique em 'Selecionar Planilha' para carregar os dados.\n"
            "5. Clique em 'Mover Usuários da Planilha' para iniciar a operação."
        )
        ttk.Label(self, text=instructions, justify=tk.LEFT).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=10)

        # --- Seção de Credenciais ---
        cred_frame = ttk.LabelFrame(self, text="1. Credenciais do Administrador", padding=10)
        cred_frame.grid(row=2, column=0, columnspan=2, sticky="ew", pady=10)
        cred_frame.columnconfigure(1, weight=1)

        ttk.Label(cred_frame, text="Usuário de Rede:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        user_frame = ttk.Frame(cred_frame)
        user_frame.grid(row=0, column=1, sticky=tk.EW)
        ttk.Label(user_frame, text=f"{DOMINIO_AD.upper()}\\", foreground="gray").pack(side=tk.LEFT)
        self.mass_move_admin_user = ttk.Entry(user_frame)
        self.mass_move_admin_user.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Label(cred_frame, text="Senha:").grid(row=1, column=0, sticky=tk.W, padx=5, pady=5)
        self.mass_move_admin_password = ttk.Entry(cred_frame, show="*")
        self.mass_move_admin_password.grid(row=1, column=1, pady=5, sticky=tk.EW)

        self.mass_move_test_btn = ttk.Button(
            cred_frame,
            text="Verificar Credenciais",
            command=self.verify_mass_move_credentials
        )
        self.mass_move_test_btn.grid(row=2, column=0, columnspan=2, pady=10)
        self.mass_move_connection_status = ttk.Label(cred_frame, text="", font=("Arial", 9))
        self.mass_move_connection_status.grid(row=3, column=0, columnspan=2)

        # --- Seção de Destino e Planilha ---
        data_frame = ttk.LabelFrame(self, text="2. Destino e Dados", padding=10)
        data_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=10)
        data_frame.columnconfigure(1, weight=1)

        ttk.Label(data_frame, text="Mover para OU:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.mass_move_target_ou = ttk.Combobox(data_frame, state="readonly")
        self.mass_move_target_ou.grid(row=0, column=1, pady=5, sticky=tk.EW)

        self.mass_move_select_btn = ttk.Button(
            data_frame,
            text="Selecionar Planilha",
            command=self.select_mass_move_spreadsheet,
            state=tk.DISABLED
        )
        self.mass_move_select_btn.grid(row=1, column=0, columnspan=2, pady=10)

        # --- Seção de Visualização e Ação ---
        action_frame = ttk.LabelFrame(self, text="3. Visualização e Execução", padding=10)
        action_frame.grid(row=4, column=0, columnspan=2, sticky="nsew", pady=10)
        action_frame.columnconfigure(0, weight=1)
        action_frame.rowconfigure(0, weight=1)

        # Treeview para mostrar os dados da planilha
        tree_frame = ttk.Frame(action_frame)
        tree_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", pady=5)
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        scrollbar = ttk.Scrollbar(tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.mass_move_tree = ttk.Treeview(
            tree_frame,
            columns=("Usuário",),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=8
        )
        self.mass_move_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.mass_move_tree.yview)
        self.mass_move_tree.heading("Usuário", text="Usuário da Planilha")
        self.mass_move_tree.column("Usuário", width=300)

        # Botão de mover
        self.mass_move_btn = ttk.Button(
            action_frame,
            text="Mover Usuários da Planilha",
            command=self.start_mass_move,
            state=tk.DISABLED
        )
        self.mass_move_btn.grid(row=1, column=0, columnspan=2, pady=10)

        # Barra de progresso
        self.mass_move_progress_var = tk.DoubleVar()
        self.mass_move_progress_bar = ttk.Progressbar(
            action_frame,
            orient=tk.HORIZONTAL,
            length=300,
            mode='determinate',
            variable=self.mass_move_progress_var
        )
        self.mass_move_progress_bar.grid(row=2, column=0, columnspan=2, pady=5, sticky="ew")

        # Status da movimentação
        self.mass_move_status = ttk.Label(action_frame, text="Aguardando ação...", foreground="blue")
        self.mass_move_status.grid(row=3, column=0, columnspan=2, pady=5)

        # Ajustar layout principal
        self.columnconfigure(1, weight=1)
        self.rowconfigure(4, weight=1)

    def verify_mass_move_credentials(self):
        """
        Verifica as credenciais fornecidas, conecta-se ao AD de forma segura
        e carrega as OUs disponíveis.
        """
        username = self.mass_move_admin_user.get().strip()
        password = self.mass_move_admin_password.get()

        if not username or not password:
            messagebox.showerror("Erro de Validação", "Preencha os campos de usuário e senha.")
            return

        self.mass_move_connection_status.config(text="Verificando...", foreground="orange")
        self.update_idletasks()

        try:
            # Configuração de TLS para conexão segura na porta 636
            tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(SERVIDOR_AD, use_ssl=True, tls=tls_config, port=636)

            # Tenta autenticação. Primeiro com formato UPN (user@domain), depois NTLM (DOMAIN\user)
            try:
                conn = Connection(server, user=f"{username}@{DOMINIO_AD}.matriz", password=password, authentication=SIMPLE, auto_bind=True)
            except Exception:
                logging.warning("Autenticação SIMPLE falhou. Tentando NTLM.")
                conn = Connection(server, user=f"{DOMINIO_AD}\\{username}", password=password, authentication=NTLM, auto_bind=True)

            self.conn_mass_move = conn
            logging.info(f"Conexão bem-sucedida para o usuário: {username}")

            # Se a conexão for bem-sucedida, carrega as OUs
            if self.load_ous_for_mass_move():
                self.mass_move_connection_status.config(text="✅ Credenciais validadas com sucesso!", foreground="green")
                self.mass_move_select_btn.config(state=tk.NORMAL) # Habilita o botão de selecionar planilha
                self.mass_move_status.config(text="Pronto para carregar a planilha e mover usuários.", foreground="blue")
            else:
                raise Exception("Falha ao carregar as OUs do Active Directory.")

        except Exception as e:
            error_msg = f"Erro de conexão: {str(e)}"
            logging.error(f"Falha na verificação de credenciais para '{username}': {error_msg}")
            self.mass_move_connection_status.config(text=f"❌ {error_msg}", foreground="red")
            self.mass_move_select_btn.config(state=tk.DISABLED)
            self.mass_move_btn.config(state=tk.DISABLED)

    def load_ous_for_mass_move(self):
        """
        Carrega todas as Unidades Organizacionais (OUs) do AD e as popula no combobox.
        """
        if not self.conn_mass_move or not self.conn_mass_move.bound:
            messagebox.showerror("Erro de Conexão", "A conexão com o AD não está ativa.")
            return False

        try:
            self.mass_move_status.config(text="Carregando OUs...", foreground="orange")
            self.update_idletasks()

            self.ous_list = ["Domínio Raiz"]  # Opção para mover para a raiz do domínio

            self.conn_mass_move.search(
                search_base=BASE_DN,
                search_filter='(objectClass=organizationalUnit)',
                attributes=['distinguishedName'],
                search_scope=SUBTREE
            )

            # Adiciona os DNs das OUs encontradas na lista
            for entry in self.conn_mass_move.entries:
                self.ous_list.append(entry.distinguishedName.value)
            
            self.ous_list.sort()

            # Atualiza o combobox com a lista de OUs
            self.mass_move_target_ou['values'] = self.ous_list
            if self.ous_list:
                self.mass_move_target_ou.current(0)
            
            logging.info(f"{len(self.ous_list)} OUs carregadas com sucesso.")
            return True
        except Exception as e:
            error_msg = f"Erro ao carregar OUs: {str(e)}"
            logging.error(error_msg)
            self.mass_move_status.config(text=error_msg, foreground="red")
            return False

    def select_mass_move_spreadsheet(self):
        """
        Abre uma janela para o usuário selecionar uma planilha Excel (.xlsx, .xls).
        Lê os dados e os exibe na treeview.
        """
        file_path = filedialog.askopenfilename(
            title="Selecione a planilha Excel",
            filetypes=[("Excel Files", "*.xlsx *.xls")]
        )
        if not file_path:
            return

        try:
            df = pd.read_excel(file_path, dtype=str) # Lê tudo como string para evitar problemas de tipo

            if 'Usuário' not in df.columns:
                messagebox.showerror("Erro de Formato", "A planilha deve conter uma coluna chamada 'Usuário'.")
                return

            # Limpa dados: remove linhas onde 'Usuário' é nulo e preenche outros nulos com string vazia
            df.dropna(subset=['Usuário'], inplace=True)
            df.fillna('', inplace=True)

            # Limpa a visualização anterior
            for item in self.mass_move_tree.get_children():
                self.mass_move_tree.delete(item)

            # Popula a treeview com os usuários da planilha
            for _, row in df.iterrows():
                username = str(row['Usuário']).strip()
                if username:
                    self.mass_move_tree.insert("", "end", values=(username,))

            self.mass_move_data = df
            self.mass_move_status.config(text=f"Planilha carregada com {len(df)} usuários.", foreground="green")
            self.mass_move_btn.config(state=tk.NORMAL) # Habilita o botão de mover
            logging.info(f"Planilha '{file_path}' carregada com {len(df)} usuários.")

        except Exception as e:
            error_msg = f"Falha ao ler a planilha: {str(e)}"
            messagebox.showerror("Erro de Leitura", error_msg)
            logging.error(error_msg)
            self.mass_move_status.config(text=error_msg, foreground="red")
            self.mass_move_btn.config(state=tk.DISABLED)

    def start_mass_move(self):
        """
        Valida as seleções e inicia a thread para a movimentação em massa.
        """
        if not self.mass_move_data or self.mass_move_data.empty:
            messagebox.showwarning("Aviso", "Nenhuma planilha carregada ou a planilha está vazia.")
            return

        target_ou = self.mass_move_target_ou.get()
        if not target_ou:
            messagebox.showerror("Erro de Validação", "Selecione uma OU de destino.")
            return

        confirm = messagebox.askyesno(
            "Confirmar Movimentação",
            f"Você tem certeza que deseja mover {len(self.mass_move_data)} usuário(s) para a OU:\n{target_ou}?"
        )
        if not confirm:
            return

        # Desabilita botões para evitar ações concorrentes
        self.mass_move_select_btn.config(state=tk.DISABLED)
        self.mass_move_btn.config(state=tk.DISABLED)
        self.mass_move_test_btn.config(state=tk.DISABLED)

        # Configura a barra de progresso
        total_users = len(self.mass_move_data)
        self.mass_move_progress_var.set(0)
        self.mass_move_progress_bar["maximum"] = total_users
        self.mass_move_status.config(text=f"Iniciando movimentação de {total_users} usuários...", foreground="blue")

        # Inicia a operação em uma thread separada para não travar a UI
        threading.Thread(
            target=self.mass_move_thread,
            args=(target_ou,),
            daemon=True
        ).start()

    def mass_move_thread(self, target_ou):
        """
        Thread que executa a lógica de movimentação para cada usuário da planilha.
        """
        success_count = 0
        error_count = 0
        log_details = []

        total_users = len(self.mass_move_data)

        for i, row in self.mass_move_data.iterrows():
            username = str(row['Usuário']).strip()
            if not username:
                continue

            try:
                # Busca o usuário pelo CN (nome completo) ou sAMAccountName (login)
                search_filter = f"(|(cn={escape_rdn(username)})(sAMAccountName={escape_rdn(username)}))"
                self.conn_mass_move.search(
                    search_base=BASE_DN,
                    search_filter=search_filter,
                    attributes=['distinguishedName'],
                    search_scope=SUBTREE,
                    size_limit=1
                )

                if not self.conn_mass_move.entries:
                    raise Exception(f"Usuário não encontrado no AD.")

                user_dn = self.conn_mass_move.entries[0].distinguishedName.value

                # Define o novo container pai (a OU de destino)
                new_parent = BASE_DN if target_ou == "Domínio Raiz" else target_ou

                # Extrai o RDN (Relative Distinguished Name), ex: "CN=John Doe"
                rdn = user_dn.split(',', 1)[0]

                # Executa a modificação do DN (a movimentação)
                was_moved = self.conn_mass_move.modify_dn(user_dn, rdn, new_superior=new_parent)

                if not was_moved:
                    raise Exception(f"Falha na API do LDAP: {self.conn_mass_move.last_error}")

                success_count += 1
                log_details.append(f"✅ SUCESSO: '{username}' movido para '{new_parent}'.")
                logging.info(f"Usuário '{username}' (DN: {user_dn}) movido com sucesso para '{new_parent}'.")

            except Exception as e:
                error_count += 1
                error_msg = str(e)
                log_details.append(f"❌ ERRO: Falha ao mover '{username}'. Motivo: {error_msg}")
                logging.error(f"Erro ao mover '{username}': {error_msg}")

            # Atualiza a UI a partir da thread
            self.parent.after(0, self.update_mass_move_progress, i + 1, success_count, error_count, total_users)

        # Finaliza a operação e gera o log
        self.parent.after(0, self.finish_mass_move, success_count, error_count, total_users, log_details)

    def update_mass_move_progress(self, current, success, errors, total):
        """
        Atualiza a barra de progresso e o texto de status na UI.
        """
        self.mass_move_progress_var.set(current)
        self.mass_move_status.config(
            text=f"Processando: {current}/{total} | Sucessos: {success} | Erros: {errors}",
            foreground="blue"
        )

    def finish_mass_move(self, success, errors, total, log_details):
        """
        Executado ao final da thread. Salva o log, exibe um resumo
        e reabilita os botões da UI.
        """
        # Monta a mensagem de resumo
        result_summary = (
            f"Movimentação em Massa Concluída!\n\n"
            f"Total de Usuários Processados: {total}\n"
            f"Sucessos: {success}\n"
            f"Erros: {errors}"
        )

        # Salva o log detalhado em um arquivo de texto
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_filename = f"log_movimentacao_{timestamp}.txt"
            
            with open(log_filename, 'w', encoding='utf-8') as f:
                f.write(result_summary + "\n\n" + "="*50 + "\n\n")
                f.write("\n".join(log_details))
            
            log_path = os.path.abspath(log_filename)
            final_message = result_summary + f"\n\nUm log detalhado foi salvo em:\n{log_path}"
            self.mass_move_status.config(text=f"Operação concluída. Log salvo em: {log_path}", foreground="green" if errors == 0 else "orange")
            messagebox.showinfo("Operação Concluída", final_message)

        except Exception as e:
            logging.error(f"Falha ao salvar o arquivo de log: {e}")
            messagebox.showerror("Erro de Log", f"Não foi possível salvar o arquivo de log: {e}")

        # Reabilita os botões
        self.mass_move_select_btn.config(state=tk.NORMAL)
        self.mass_move_btn.config(state=tk.NORMAL)
        self.mass_move_test_btn.config(state=tk.NORMAL)