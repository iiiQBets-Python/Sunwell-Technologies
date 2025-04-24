import os
import webbrowser
import time
import threading
import django
from django.core.wsgi import get_wsgi_application
from django.core.management import call_command
from waitress import serve  # type: ignore
from apscheduler.schedulers.background import BackgroundScheduler
from django.conf import settings

os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "Core.settings")

django.setup()

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
    time.sleep(2) 
    webbrowser.open(f"http://{host}:{port}/")

if __name__ == "__main__":
    try:               
        threading.Thread(target=open_browser, daemon=True).start()        
        serve(application, host="0.0.0.0", port=8080)
    except Exception as e:        
        with open("error_log.txt", "a") as f:
            f.write(str(e) + "\n")