import os
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox 

class MSSQLConfiguratorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("MSSQL Configurator & EXE Generator")
        self.root.geometry("550x450")  # Increased window size
        self.root.configure(bg="#f4f4f4")  # Light gray background

        # Paths
        self.base_directory = os.path.dirname(os.path.abspath(__file__))
        self.sunwell_project_path = os.path.join(self.base_directory, "Sunwell")
        self.settings_file_path = os.path.join(self.sunwell_project_path, "Core", "settings.py")
        self.env_path = os.path.join(self.sunwell_project_path, "myenv", "Scripts", "activate.bat")
        self.generate_exe_script = os.path.join(self.sunwell_project_path, "generate_exe.py")

        # Frame for Form Inputs
        frame = tk.Frame(root, bg="#ffffff", padx=10, pady=10, relief="solid", borderwidth=1)
        frame.pack(padx=20, pady=20, fill="both", expand=True)

        ttk.Label(frame, text="🔹 Select MSSQL ODBC Driver", font=("Arial", 10, "bold")).pack(pady=5)
        self.driver_var = tk.StringVar(value="ODBC Driver 17 for SQL Server")
        self.driver_dropdown = ttk.Combobox(frame, textvariable=self.driver_var, state="readonly", width=40)
        self.driver_dropdown['values'] = ("ODBC Driver 17 for SQL Server", "ODBC Driver 18 for SQL Server")
        self.driver_dropdown.pack(pady=5)

        ttk.Label(frame, text="🔹 Enter Database Details", font=("Arial", 10, "bold")).pack(pady=5)

        self.hostname_var = tk.StringVar()
        ttk.Label(frame, text="Hostname").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.hostname_var, width=45).pack()

        self.username_var = tk.StringVar()
        ttk.Label(frame, text="Username").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.username_var, width=45).pack()

        self.password_var = tk.StringVar()
        ttk.Label(frame, text="Password").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.password_var, show="*", width=45).pack()

        self.database_var = tk.StringVar()
        ttk.Label(frame, text="Database Name").pack(anchor="w")
        ttk.Entry(frame, textvariable=self.database_var, width=45).pack()

        # Buttons
        self.build_button = ttk.Button(frame, text="🚀 Build EXE", command=self.update_settings, style="TButton")
        self.build_button.pack(pady=15)

        # Status Label
        self.status_label = ttk.Label(frame, text="Status: Ready", foreground="blue", font=("Arial", 10, "bold"))
        self.status_label.pack(pady=10)

        # Button Styles
        style = ttk.Style()
        style.configure("TButton", font=("Arial", 10, "bold"), padding=5)

    def update_settings(self):
        """Updates the settings.py file with the provided database credentials and disables the button."""
        driver = self.driver_var.get()
        hostname = self.hostname_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get().strip()
        database = self.database_var.get().strip()

        if not all([hostname, username, password, database]):
            messagebox.showerror("Error", "⚠️ Please fill in all fields.")
            return

        # Disable the button to prevent multiple clicks
        self.build_button.config(state=tk.DISABLED)

        # MSSQL Configuration
        engine = "mssql"

        # Path to settings.py
        settings_file_path = os.path.join(self.sunwell_project_path, "Core", "settings.py")

        # Check if settings.py exists before modifying
        if os.path.exists(settings_file_path):
            print(f"🔍 Found settings.py at: {settings_file_path}")

            # Read the existing settings file
            with open(settings_file_path, "r") as file:
                settings_content = file.readlines()

            # New database settings for MSSQL
            new_db_settings = f"""
DATABASES = {{
    'default': {{
        'ENGINE': '{engine}',
        'NAME': '{database}',
        'USER': '{username}',
        'PASSWORD': '{password}',
        'HOST': '{hostname}',
        'PORT': '',
        'OPTIONS': {{
            'driver': '{driver}',
            'extra_params': 'TrustServerCertificate=yes;',
            'Encrypt': 'no',
        }},
    }}
}}
"""

            inside_databases = False
            bracket_count = 0  
            new_lines = []    
            for line in settings_content:
                stripped_line = line.strip()
                if stripped_line.startswith("DATABASES = {"):
                    inside_databases = True
                    bracket_count = 1 
                    new_lines.append(new_db_settings) 
                    continue
                if inside_databases:
                    bracket_count += stripped_line.count("{") 
                    bracket_count -= stripped_line.count("}") 
                    if bracket_count == 0:  
                        inside_databases = False
                        continue  
                    continue 
                new_lines.append(line) 

            # Write the updated settings to settings.py
            with open(settings_file_path, "w") as file:
                file.writelines(new_lines)
            self.status_label.config(text="✅ settings.py updated successfully!", foreground="green")
            print(f"✅ settings.py updated successfully in '{settings_file_path}'")
        else:
            print("❌ settings.py not found. Make sure the Sunwell project is correctly structured.")

        # Run PyInstaller after modifying settings
        self.run_pyinstaller()

    def run_pyinstaller(self):
        """Runs PyInstaller inside the virtual environment."""
        if not os.path.exists(self.env_path):
            messagebox.showerror("Error", f"❌ Virtual environment not found at {self.env_path}.\nCreate it using:\npython -m venv myenv")
            self.build_button.config(state=tk.NORMAL)  # Re-enable button
            return

        



        

        pyinstaller_command_generate = (
            f'cmd.exe /c "{self.env_path} && '
            f'pyinstaller --onefile --add-data \"App1/migrations;App1/migrations\" '
            f'--hidden-import=whitenoise.storage '
            f'--hidden-import=whitenoise.runserver_nostatic '
            f'--hidden-import=whitenoise.middleware '
            f'--hidden-import=whitenoise.base '
            f'--hidden-import=whitenoise.django '
            f'--hidden-import=apscheduler '
            f'--hidden-import=apscheduler.schedulers.background '
            f'--hidden-import=App1.scheduler '  
            f'--hidden-import=pyodbc '          
            f'--paths=myenv/Lib/site-packages '
            f'--hidden-import=requests ' 
            f'--hidden-import=threading ' 
            f'--hidden-import=serial '
            f'--add-data \"templates;templates\" '
            f'--add-data \"media;media\" '
            f'--add-data \"staticfiles;staticfiles\" '
            f'--add-data \"Activity.log;Activity.log\" '
            f'--add-data \"Error.log;Error.log\" '
            f'--add-data \"myenv/Lib/site-packages/snap7;snap7\" '
            f'generate_exe.py"'  # Ensure the script name is correctly included
        )                   
        
        pyinstaller_command_run = (
            f'cmd.exe /c "{self.env_path} && '
            f'pyinstaller --onefile --noconsole --windowed '
            f'--hidden-import=whitenoise.storage '
            f'--hidden-import=whitenoise.runserver_nostatic '
            f'--hidden-import=whitenoise.middleware '
            f'--hidden-import=whitenoise.base '
            f'--hidden-import=whitenoise.django '
            f'--hidden-import=apscheduler '
            f'--hidden-import=apscheduler.schedulers.background '
            f'--hidden-import=App1.scheduler '  
            f'--hidden-import=pyodbc '          
            f'--paths=myenv/Lib/site-packages '
            f'--hidden-import=requests ' 
            f'--hidden-import=threading ' 
            f'--hidden-import=serial '
            f'--add-data \"templates;templates\" '
            f'--add-data \"media;media\" '
            f'--add-data \"staticfiles;staticfiles\" '
            f'--add-data \"Activity.log;Activity.log\" '
            f'--add-data \"Error.log;Error.log\" '
            f'--add-data \"myenv/Lib/site-packages/snap7;snap7\" '
            f'ESTDAS_V1.py"'  # Ensure the script name is correctly included
        )   
         
        try:            
            self.status_label.config(text="🚀 Running PyInstaller for generate_exe.py...", foreground="blue")
            subprocess.run(pyinstaller_command_generate, shell=True, check=True, cwd=self.sunwell_project_path)
            self.status_label.config(text="✅ generate_exe.exe successfully built!", foreground="green")
            
            self.status_label.config(text="🚀 Running PyInstaller for ESTDAS_V1.py...", foreground="blue")
            subprocess.run(pyinstaller_command_run, shell=True, check=True, cwd=self.sunwell_project_path)
            self.status_label.config(text="✅ ESTDAS_V1.exe successfully built!", foreground="green")
            
            messagebox.showinfo("Success", "✅ Both EXE files successfully generated!")

        except subprocess.CalledProcessError as e:
            self.status_label.config(text=f"❌ EXE generation failed: {e}", foreground="red")
            messagebox.showerror("Error", f"❌ PyInstaller Error: {e}")

        # Re-enable button after execution
        self.build_button.config(state=tk.NORMAL)

# Run the Tkinter App
if __name__ == "__main__":
    root = tk.Tk()
    app = MSSQLConfiguratorApp(root)
    root.mainloop()
