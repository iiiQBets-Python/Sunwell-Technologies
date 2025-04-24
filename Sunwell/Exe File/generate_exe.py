import os
import webbrowser
import time
import threading
import pyodbc
from waitress import serve  # type: ignore
from django.core.wsgi import get_wsgi_application
import django
from django.conf import settings
from django.core.management import call_command
from apscheduler.schedulers.background import BackgroundScheduler
from django.conf import settings

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Core.settings")
django.setup()
 
DB_CONFIG = settings.DATABASES['default']
DB_NAME = DB_CONFIG['NAME']
DB_USER = DB_CONFIG['USER']
DB_PASSWORD = DB_CONFIG['PASSWORD']
DB_HOST = DB_CONFIG['HOST']
DB_DRIVER = DB_CONFIG['OPTIONS'].get('driver', 'ODBC Driver 17 for SQL Server')  # Default to Driver 17
EXTRA_PARAMS = DB_CONFIG['OPTIONS'].get('extra_params', 'TrustServerCertificate=yes;Encrypt=no')

def create_database_if_not_exists():
    try:
    
        conn = pyodbc.connect(
            f"DRIVER={DB_DRIVER};SERVER={DB_HOST};UID={DB_USER};PWD={DB_PASSWORD};{EXTRA_PARAMS}",
            autocommit=True
        )
        cursor = conn.cursor()

        # Check if the database exists
        cursor.execute(f"SELECT name FROM master.dbo.sysdatabases WHERE name = '{DB_NAME}'")
        db_exists = cursor.fetchone()

        if not db_exists:
            print(f"Database '{DB_NAME}' not found. Creating it now...")
            cursor.execute(f"CREATE DATABASE {DB_NAME}")
            print(f"✅ Database '{DB_NAME}' created successfully!")
        else:
            print(f"✅ Database '{DB_NAME}' already exists. Using existing database.")

        cursor.close()
        conn.close()
    except Exception as e:
        print(f"❌ Error checking/creating database: {e}")
        with open("error_log.txt", "a") as f:
            f.write(str(e) + "\n")
        exit(1)  
create_database_if_not_exists()

time.sleep(10) 

try:
    print("Applying database migrations...")
    call_command('makemigrations')
    call_command('migrate')
except Exception as e:
    print(f"❌ Error during migrations: {e}")
    with open("error_log.txt", "a") as f:
        f.write(str(e) + "\n")
    exit(1)  

from django.apps import apps

equip_config = apps.get_app_config('App1') 
equip_config.start_background_task()

from App1.scheduler import start_notification_scheduler  # Ensure scheduler is imported

scheduler = BackgroundScheduler()
scheduler.add_job(start_notification_scheduler, 'interval', minutes=2)
scheduler.start()

application = get_wsgi_application()

DEFAULT_HOST = "localhost"
DEFAULT_PORT = "8080"

host = getattr(settings, "HOST", DEFAULT_HOST)
port = str(getattr(settings, "PORT", DEFAULT_PORT))

def open_browser():
    """Wait for the server to start, then open the browser automatically."""
    time.sleep(5) 
    webbrowser.open(f"http://{host}:{port}/")

if __name__ == "__main__":
    try:              
        threading.Thread(target=open_browser, daemon=True).start()        
        serve(application, host="0.0.0.0", port=8080)
    except Exception as e:        
        with open("error_log.txt", "a") as f:
            f.write(str(e) + "\n")
