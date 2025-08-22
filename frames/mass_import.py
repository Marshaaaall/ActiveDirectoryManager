import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import threading
import logging
from config import DOMINIO_AD
from ldap_utils import conectar_ldap, create_user


class MassImportFrame(ttk.Frame):
    def __init__(self, parent, root):  # Corrigido: removido o parâmetro 'notebook'
        super().__init__(parent)
        self.root = root
        
        # Removido a criação do frame adicional
        self.import_data = None
        self.conn_mass = None

        self._setup_ui()

    def _setup_ui(self):
        ttk.Label(self, text="Importação em Massa via Excel", font=("Arial", 14)).grid(row=0, column=0, columnspan=2, pady=10)

        instructions = (
            "Instruções:\n"
            "1. Prepare uma planilha Excel com as colunas: 'Nome', 'Sobrenome', 'OU'\n"
            "2. Clique em 'Selecionar Planilha' para carregar os dados\n"
            "3. Clique em 'Iniciar Importação' para criar todos os usuários"
        )
        ttk.Label(self, text=instructions, justify=tk.LEFT).grid(row=1, column=0, columnspan=2, sticky=tk.W, pady=10)

        ttk.Button(self, text="Selecionar Planilha", command=self.select_spreadsheet).grid(row=2, column=0, columnspan=2, pady=10)

        self.tree_frame = ttk.Frame(self)
        self.tree_frame.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=10)

        scrollbar = ttk.Scrollbar(self.tree_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree = ttk.Treeview(
            self.tree_frame,
            columns=("Nome", "Sobrenome", "OU", "Status"),
            show="headings",
            yscrollcommand=scrollbar.set,
            height=10
        )
        self.tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.tree.yview)

        for col in ("Nome", "Sobrenome", "OU", "Status"):
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

        ttk.Button(self, text="Verificar Credenciais", command=self.verify_mass_credentials).grid(row=8, column=0, columnspan=2, pady=10)
        self.mass_connection_status = ttk.Label(self, text="", font=("Arial", 9))
        self.mass_connection_status.grid(row=9, column=0, columnspan=2)

        self.import_btn = ttk.Button(self, text="Iniciar Importação", command=self.start_mass_import, state=tk.DISABLED)
        self.import_btn.grid(row=10, column=0, columnspan=2, pady=20)

        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=300, mode='determinate', variable=self.progress_var)
        self.progress_bar.grid(row=11, column=0, columnspan=2, pady=10)

        self.import_status = ttk.Label(self, text="", foreground="blue")
        self.import_status.grid(row=12, column=0, columnspan=2)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(3, weight=1)

    def select_spreadsheet(self):
        file_path = filedialog.askopenfilename(title="Selecione a planilha Excel", filetypes=[("Excel Files", "*.xlsx *.xls")])
        if not file_path:
            return
        try:
            df = pd.read_excel(file_path)
            required_cols = {"Nome", "Sobrenome", "OU"}
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
            self.tree.insert("", "end", values=(row["Nome"], row["Sobrenome"], row["OU"], "Pendente"))

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

        self.progress_var.set(0)
        self.progress_bar["maximum"] = len(self.import_data)
        self.import_status.config(text="Iniciando importação...", foreground="blue")

        threading.Thread(target=self._thread_import, daemon=True).start()

    def _thread_import(self):
        total = len(self.import_data)
        success, errors = 0, 0

        for i, row in self.import_data.iterrows():
            try:
                nome = row["Nome"].strip()
                sobrenome = row["Sobrenome"].strip()
                ou = row["OU"].strip()
                if create_user(self.conn_mass, f"{nome} {sobrenome}", nome, sobrenome, ou):
                    success += 1
                else:
                    errors += 1
            except Exception as e:
                logging.error(f"Erro criando usuário {row}: {e}")
                errors += 1

            self.root.after(0, lambda cur=i+1, s=success, er=errors: self._update_progress(cur, s, er, total))

        self.root.after(0, lambda: self.import_status.config(text="✅ Importação concluída!", foreground="green"))

    def _update_progress(self, current, success, errors, total):
        self.progress_var.set(current)
        self.import_status.config(text=f"Processados: {current}/{total} | Sucessos: {success} | Erros: {errors}", foreground="blue")