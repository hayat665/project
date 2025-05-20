import threading
import paramiko
import time
from tkinter import filedialog
from network_tool.utils.log_utils import LogManager
from network_tool.selection_dialog import SelectionDialog
import tkinter as tk
from tkinter import ttk


class DeploymentOperation:
    def __init__(self, app):
        self.app = app

    def start(self):
        if not self.app.devices:
            self.app.log_manager.show_error("Veuillez d'abord charger les équipements")
            return

        if not self.app.auth_manager.credentials['username'] or not self.app.auth_manager.credentials['password']:
            self.app.log_manager.show_error("Veuillez d'abord entrer les identifiants SSH")
            return

        dialog = SelectionDialog(self.app.root, "Sélection pour Déploiement")
        selection = dialog.show()

        self.devices_to_deploy = {}
        if selection == "excel":
            for ip, device in self.app.devices.items():
                if device.get('deployment', 'N').upper() == 'Y':
                    self.devices_to_deploy[ip] = device
            if not self.devices_to_deploy:
                self.app.log_manager.show_error(
                    "Aucun équipement sélectionné pour le déploiement dans le fichier Excel")
                return
        else:
            self.devices_to_deploy = self.app.devices

        config_file = filedialog.askopenfilename(
            title="Sélectionner le fichier de configuration",
            filetypes=[("Fichiers texte", "*.txt"), ("Tous fichiers", "*.*")]
        )

        if not config_file:
            return

        try:
            with open(config_file, 'r', encoding='utf-8') as f:
                self.config_commands = [line.strip() for line in f if line.strip()]
        except Exception as e:
            self.app.log_manager.show_error(f"Impossible de lire le fichier:\n{str(e)}")
            return

        self.create_deployment_console()

    def create_deployment_console(self):
        console_window = tk.Toplevel(self.app.root)
        console_window.title("Console de Déploiement")
        console_window.geometry("900x700")

        console_text = tk.Text(
            console_window,
            wrap=tk.WORD,
            font=("Consolas", 10),
            bg="black",  # fond noir
            fg="white",  # texte blanc par défaut
            padx=10,
            pady=10
        )
        console_text.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(console_window, command=console_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        console_text.config(yscrollcommand=scrollbar.set)

        console_text.tag_config("header", foreground="blue", font=("Consolas", 11, "bold"))
        console_text.tag_config("command", foreground="purple")
        console_text.tag_config("output", foreground="#cccccc")
        console_text.tag_config("success", foreground="green")
        console_text.tag_config("error", foreground="red")
        console_text.tag_config("info", foreground="white")

        control_frame = ttk.Frame(console_window)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        start_btn = ttk.Button(control_frame, text="Démarrer le déploiement",
                               command=lambda: self.start_deployment_thread(console_text, control_frame))
        start_btn.pack(side=tk.LEFT, padx=5)

        close_btn = ttk.Button(control_frame, text="Fermer",
                               command=console_window.destroy)
        close_btn.pack(side=tk.RIGHT, padx=5)

        console_text.insert(tk.END, "=== Déploiement de configuration ===\n\n", "header")
        console_text.insert(tk.END, f"Commandes à déployer ({len(self.config_commands)}):\n", "info")

        for cmd in self.config_commands:
            console_text.insert(tk.END, f"  {cmd}\n", "command")

        console_text.insert(tk.END, "\nPrêt à démarrer...\n", "info")
        console_text.config(state=tk.DISABLED)

    def start_deployment_thread(self, console_text, control_frame):
        for widget in control_frame.winfo_children():
            if isinstance(widget, ttk.Button) and "Démarrer" in widget.cget("text"):
                widget.config(state=tk.DISABLED)

        cancel_btn = ttk.Button(control_frame, text="Annuler",
                                command=lambda: setattr(self.app, 'running_operation', False))
        cancel_btn.pack(side=tk.LEFT, padx=5)

        self.app.running_operation = True

        threading.Thread(
            target=self.deploy_config,
            args=(console_text, control_frame),  # ← CORRECTION ici : ajout de control_frame
            daemon=True
        ).start()

    def deploy_config(self, console_text, control_frame):  # ← CORRECTION ici : ajout de control_frame
        total_devices = len(self.devices_to_deploy)
        username = self.app.auth_manager.credentials['username']
        password = self.app.auth_manager.credentials['password']
        success_count = 0
        fail_count = 0

        def write_to_console(message, tag="info"):
            console_text.config(state=tk.NORMAL)
            console_text.insert(tk.END, message, tag)
            console_text.see(tk.END)
            console_text.config(state=tk.DISABLED)

        write_to_console("\n=== Début du déploiement ===\n\n", "header")

        for i, (ip, device) in enumerate(self.devices_to_deploy.items(), 1):
            if not self.app.running_operation:
                write_to_console("\nDéploiement annulé par l'utilisateur\n", "error")
                break

            hostname = device['hostname']
            device_type = device.get('device_type', 'inconnu')

            write_to_console(f"\nDéploiement sur {hostname} ({ip}) - {device_type} ({i}/{total_devices})\n", "info")

            try:
                ssh = paramiko.SSHClient()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(ip, username=username, password=password, timeout=10)

                shell = ssh.invoke_shell()
                shell.settimeout(2)

                time.sleep(1)
                output = shell.recv(1000).decode('utf-8', 'ignore')
                write_to_console(f"Connexion établie. Prompt:\n{output}\n", "output")

                for cmd in self.config_commands:
                    if not self.app.running_operation:
                        break

                    shell.send(cmd + "\n")
                    time.sleep(0.5)

                    output = ""
                    while True:
                        if shell.recv_ready():
                            data = shell.recv(1024).decode('utf-8', 'ignore')
                            output += data
                        else:
                            break

                    write_to_console(f"$ {cmd}\n", "command")
                    write_to_console(output, "output")

                if self.app.running_operation:
                    write_to_console(f"\n✅ Déploiement réussi sur {hostname}\n", "success")
                    success_count += 1
            except Exception as e:
                write_to_console(f"\n❌ Erreur sur {hostname}: {str(e)}\n", "error")
                fail_count += 1
            finally:
                if 'ssh' in locals() and ssh.get_transport() is not None:
                    ssh.close()

        write_to_console("\n=== Résultats du déploiement ===\n", "header")
        write_to_console(f"Équipements traités: {total_devices}\n", "info")
        write_to_console(f"Succès: {success_count}\n", "success")
        write_to_console(f"Échecs: {fail_count}\n\n", "error" if fail_count > 0 else "info")

        for widget in control_frame.winfo_children():
            if isinstance(widget, ttk.Button) and "Fermer" in widget.cget("text"):
                widget.config(state=tk.NORMAL)

        for widget in control_frame.winfo_children():
            if isinstance(widget, ttk.Button) and "Annuler" in widget.cget("text"):
                widget.destroy()
