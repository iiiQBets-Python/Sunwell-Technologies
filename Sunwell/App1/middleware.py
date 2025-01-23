import logging
from django.db.models.signals import post_save, post_delete
from threading import local

# Configure activity logger
activity_logger = logging.getLogger('view_logger')
activity_handler = logging.FileHandler('user_activity.log')
activity_formatter = logging.Formatter('%(asctime)s - %(message)s')
activity_handler.setFormatter(activity_formatter)
activity_logger.addHandler(activity_handler)
activity_logger.setLevel(logging.INFO)

# Configure error logger
error_logger = logging.getLogger('error_logger')
error_handler = logging.FileHandler('user_error.log')
error_formatter = logging.Formatter('%(asctime)s - %(message)s')
error_handler.setFormatter(error_formatter)
error_logger.addHandler(error_handler)
error_logger.setLevel(logging.ERROR)

# Thread-local storage for storing request context
_thread_locals = local()


class UserActivityLoggingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        post_save.connect(self.log_save_action, dispatch_uid="log_save_action")
        post_delete.connect(self.log_delete_action, dispatch_uid="log_delete_action")

    def __call__(self, request):
        # Store the current request in thread-local storage
        _thread_locals.request = request

        emp_user = request.session.get('username', 'Anonymous')  # Get logged-in user or default to 'Anonymous'
        activity_logger.info(f'{emp_user} is accessing {request.path}.')
        
        try:
            response = self.get_response(request)
        except Exception as e:
            self.log_exception(request, e, emp_user)
            raise  # Re-raise the exception for Django's error handling
        
        return response

    
    def process_exception(self, request, exception):
        # This method is triggered for exceptions raised after `get_response`
        emp_user = request.session.get('username', 'Anonymous')  # Get logged-in user or default to 'Anonymous'
        self.log_exception(request, exception, emp_user)


    def log_exception(self, request, exception, emp_user):
        """Log any exceptions raised during the request lifecycle."""
        view_name = request.resolver_match.view_name if request.resolver_match else 'unknown_view'
        error_logger.error(
            f"{emp_user} is getting {type(exception).__name__} on accessing {view_name}: {str(exception)}"
        )

    @staticmethod
    def log_save_action(sender, instance, created, **kwargs):
        """Log create or update actions."""
        request = getattr(_thread_locals, 'request', None)
        emp_user = request.session.get('username', 'Anonymous') if request else 'Anonymous'
        action = 'created' if created else 'updated'
        activity_logger.info(
            f"{emp_user} is {action} record in {sender._meta.db_table}."
        )

    @staticmethod
    def log_delete_action(sender, instance, **kwargs):
        """Log delete actions."""
        request = getattr(_thread_locals, 'request', None)
        emp_user = request.session.get('username', 'Anonymous') if request else 'Anonymous'
        activity_logger.info(
            f"{emp_user} is deleting record in {sender._meta.db_table}."
        )

