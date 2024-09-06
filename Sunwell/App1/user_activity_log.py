import datetime
from django.utils.deprecation import MiddlewareMixin
from .models import UserActivityLog
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from .models import User, SuperAdmin


class UserActivityMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        # Your middleware logic
        pass

# # Middleware to track user activity
# class UserActivityMiddleware(MiddlewareMixin):
#     def process_view(self, request, view_func, view_args, view_kwargs):
#         # Check if the username exists in the session
#         username = request.session.get('username')
        
#         if username:
#             try:
#                 # Try to get the User or SuperAdmin from the session
#                 user = User.objects.filter(username=username).first()
#                 if not user:
#                     user = SuperAdmin.objects.filter(sa_username=username).first()

#                 # Log activity if the user exists and is not a superuser
#                 if user and not isinstance(user, SuperAdmin):  # Assuming SuperAdmin is a type of superuser
#                     print(f"Logging activity for user: {user.username}")  # Debugging line
#                     UserActivityLog.objects.create(
#                         user=user,
#                         log_date=datetime.date.today(),
#                         log_time=datetime.datetime.now().time(),
#                         event_name=view_func.__name__,
#                         event_description=f"{view_func.__module__}.{view_func.__name__}"
#                     )
#             except Exception as e:
#                 print(f"Error logging activity: {str(e)}")
#         else:
#             print(f"Skipping logging for anonymous user or unauthenticated request.")  # Debugging line
#         return None


# # Signal to log user login
# @receiver(user_logged_in)
# def log_user_login(sender, request, user, **kwargs):
#     username = request.session.get('username')
    
#     if username:
#         print(f"User {username} logged in")  # Debugging line
#         user = User.objects.filter(username=username).first() or SuperAdmin.objects.filter(sa_username=username).first()
#         if user:
#             UserActivityLog.objects.create(
#                 user=user,
#                 log_date=timezone.now().date(),
#                 log_time=timezone.now().time(),
#                 event_name="Login",
#                 event_description=f"User {user.username} logged in"
#             )


# # Signal to log user logout
# @receiver(user_logged_out)
# def log_user_logout(sender, request, user, **kwargs):
#     username = request.session.get('username')
    
#     if username:
#         print(f"User {username} logged out")  # Debugging line
#         user = User.objects.filter(username=username).first() or SuperAdmin.objects.filter(sa_username=username).first()
#         if user:
#             UserActivityLog.objects.create(
#                 user=user,
#                 log_date=timezone.now().date(),
#                 log_time=timezone.now().time(),
#                 event_name="Logout",
#                 event_description=f"User {user.username} logged out"
#             )
