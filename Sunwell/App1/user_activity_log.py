import datetime
from django.utils.deprecation import MiddlewareMixin
from .models import UserActivityLog
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from .models import User, SuperAdmin


class UserActivityMiddleware(MiddlewareMixin):
    def process_view(self, request, view_func, view_args, view_kwargs):
        pass
