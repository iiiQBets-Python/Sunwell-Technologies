from django.apps import AppConfig
import threading

# class App1Config(AppConfig):
#     default_auto_field = 'django.db.models.BigAutoField'
#     name = 'App1'


#     def ready(self):
#         import App1.user_activity_log

class EquipSettingsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'App1'  # Change to your actual app name

    def ready(self):
        print("[INFO] App is ready, starting background task.")
        from .views import background_task_for_all_equipment, stop_event
        interval = 2  # Interval in minutes
        thread = threading.Thread(target=background_task_for_all_equipment, args=(interval,), daemon=True)
        thread.start()
        print("[INFO] Background thread for all equipment started.")
