import os
import sys
import logging
from django.db.models.signals import post_save, post_delete
from threading import local

if getattr(sys, 'frozen', False): 
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_DIR = os.path.join(BASE_DIR)
os.makedirs(LOG_DIR, exist_ok=True)

activity_log_path = os.path.join(LOG_DIR, "Activity.log")
error_log_path = os.path.join(LOG_DIR, "Error.log")

activity_logger = logging.getLogger('view_logger')
activity_handler = logging.FileHandler(activity_log_path, mode='a', encoding='utf-8')  # Append mode
activity_formatter = logging.Formatter('%(asctime)s - %(message)s')
activity_handler.setFormatter(activity_formatter)
activity_logger.addHandler(activity_handler)
activity_logger.setLevel(logging.INFO)

error_logger = logging.getLogger('error_logger')
error_handler = logging.FileHandler(error_log_path, mode='a', encoding='utf-8')  # Append mode
error_formatter = logging.Formatter('%(asctime)s - %(message)s')
error_handler.setFormatter(error_formatter)
error_logger.addHandler(error_handler)
error_logger.setLevel(logging.ERROR)
_thread_locals = local()


class UserActivityLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        post_save.connect(self.log_save_action, dispatch_uid="log_save_action")
        post_delete.connect(self.log_delete_action, dispatch_uid="log_delete_action")

    def __call__(self, request):
        """Log user activity on each request."""
        _thread_locals.request = request  # Store the request in thread-local storage
        emp_user = request.session.get('username', 'Anonymous')
        activity_logger.info(f'{emp_user} is accessing {request.path}.')

        try:
            response = self.get_response(request)
        except Exception as e:
            self.log_exception(request, e, emp_user)
            raise  # Re-raise exception for Django's default error handling

        return response

    def process_exception(self, request, exception):
        """Log exceptions that occur during request processing."""
        emp_user = request.session.get('username', 'Anonymous')
        self.log_exception(request, exception, emp_user)

    def log_exception(self, request, exception, emp_user):
        """Log exceptions with the view name and user information."""
        view_name = request.resolver_match.view_name if request.resolver_match else 'unknown_view'
        error_logger.error(f"{emp_user} encountered {type(exception).__name__} while accessing {view_name}: {str(exception)}")

    @staticmethod
    def log_save_action(sender, instance, created, **kwargs):
        """Log database save (create/update) actions."""
        request = getattr(_thread_locals, 'request', None)
        emp_user = request.session.get('username', 'Anonymous') if request else 'Anonymous'
        action = 'created' if created else 'updated'
        activity_logger.info(f"{emp_user} {action} a record in {sender._meta.db_table}.")

    @staticmethod
    def log_delete_action(sender, instance, **kwargs):
        """Log database delete actions."""
        request = getattr(_thread_locals, 'request', None)
        emp_user = request.session.get('username', 'Anonymous') if request else 'Anonymous'
        activity_logger.info(f"{emp_user} deleted a record in {sender._meta.db_table}.")
