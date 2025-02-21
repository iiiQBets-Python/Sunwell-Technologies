from django.core.cache import cache
from django.conf import settings
import threading
from django.apps import AppConfig
import os


class EquipSettingsConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'App1'  # Change to your actual app name

    def ready(self):

        if os.environ.get('RUN_MAIN') != 'true':
            return

        # Set a cache key to check if the task is already running
        if not cache.get('is_background_task_running'):
            cache.set('is_background_task_running', True, timeout=None)
            self.start_background_task()

            if not hasattr(
                    self, 'scheduler_started'):  # Ensure scheduler is started only once

                from .scheduler import start_notification_scheduler
                # Start the single scheduler for both email & SMS
                start_notification_scheduler()
                self.scheduler_started = True

        else:
            pass

    def start_background_task(self):
        from .views import background_task_for_all_equipment, stop_event
        interval = 2  # Interval in minutes
        # background_task_for_all_equipment(interval)
        thread = threading.Thread(
            target=background_task_for_all_equipment, args=(
                interval,), daemon=True)
        thread.start()

    def stop_background_task(self):
        # When shutting down, clear the cache
        cache.delete('is_background_task_running')
