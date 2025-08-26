import tkinter as tk
from tkinter import ttk
from frames.dashboard import DashboardFrame
from frames.individual import IndividualFrame
from frames.mass_import import MassImportFrame
from frames.move_users import MoveUsersFrame
from frames.mass_move import MassUsersFrame
from frames.settings import SettingsFrame

class App:
    def __init__(self, root):
        root.title("Gerenciamento de Usuários LDAP - MOTIVA")
        root.geometry("1000x700")
        root.resizable(False, False)

        main_frame = ttk.Frame(root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)

       
        dashboard_tab = DashboardFrame(self.notebook)
        self.notebook.add(dashboard_tab, text="Dashboard")
        
        individual_tab = IndividualFrame(self.notebook, root)
        self.notebook.add(individual_tab.frame, text="Usuário Individual")
        
        mass_import_tab = MassImportFrame(self.notebook, root)
        self.notebook.add(mass_import_tab, text="Importação em Massa")
        
        move_users_tab = MoveUsersFrame(self.notebook, root)
        self.notebook.add(move_users_tab, text="Mover Usuários")
        
        mass_move_tab = MassUsersFrame(self.notebook, root)
        self.notebook.add(mass_move_tab, text="Movimento em Massa")

        setting_tab = SettingsFrame(self.notebook, root)
        self.notebook.add(setting_tab, text="Configurações")

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()