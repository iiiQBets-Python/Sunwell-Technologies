import atexit
from snap7.util import *
import re
from snap7.util import get_real, set_real
from .models import TemperatureHumidityRecord, Equipment, Organization, User, SuperAdmin, user_access_db
from django.db.models import Min, Max, Avg
from math import exp, log
import numpy as np
from .models import Equipment, EquipParameter
from django.views.decorators.http import require_http_methods
from datetime import date
from .models import Equipment, PLCUser, BiometricUser, UserActivityLog
from snap7 import type
from snap7.util import set_bool
from django.core.exceptions import ObjectDoesNotExist
import uuid
import requests
from .models import TemperatureHumidityRecord, Equipment
from datetime import datetime
import csv
from .models import Equipment
from django.db.models import Q
from django.db import IntegrityError
import time
import snap7
import datetime
import pytz
from .sms_queue_handler import add_to_sms_queue  # Ensure this is imported
from django.shortcuts import redirect
from datetime import datetime, timedelta, date
import json
from .models import AppSettings
from django.views.decorators.csrf import csrf_protect
from django.shortcuts import render, redirect
from django.contrib.auth.hashers import check_password
from datetime import timedelta
from datetime import datetime, time, timedelta, timezone, date
import time
import threading
from urllib import request
from django.core.serializers import serialize
from django.forms import ValidationError
from .utils import decode_from_custom_base62, decode_soft_key, generate_soft_key, get_motherboard_serial_number
from django.shortcuts import render, redirect, get_object_or_404
from django.http import HttpResponse
from django.contrib import messages
from .models import *
from django.conf import settings
from django.http import JsonResponse
import os
import subprocess
import schedule
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors
from django.shortcuts import render, HttpResponse
from django.utils.dateparse import parse_date, parse_time
from django.utils import timezone
from datetime import time as datetime_time
from django.db.models import Q, F, Value
from django.db.models.functions import Concat, Cast
from django.utils.timezone import make_aware, now, localtime
from datetime import datetime, time as datetime_time
from django.db.models import DateTimeField
from django.http import HttpResponse
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer, Paragraph, PageBreak
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from django.core.mail import send_mail
from django.shortcuts import render
from django.http import HttpResponse
from App1.emailsms import get_email_settings
from django.utils.timezone import now
from datetime import datetime, time as datetime_time
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib import colors
from datetime import datetime, timedelta
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from django.views.decorators.csrf import csrf_exempt
from concurrent.futures import ThreadPoolExecutor



def base(request):
    return render(request, 'Base/base.html', )

def superadmin(request):
    if request.method=="POST":
        username=request.POST.get('username')
        email=request.POST.get('email')
        Password=request.POST.get('password')
        superadmin=SuperAdmin(
            username=username,
            email_id=email,
            role="Super Admin",
            password=Password
        )

        superadmin.save()

        password_history = PasswordHistory.objects.filter(
                superuser=superadmin).order_by('created_at')
        if password_history.count() >= 3:
            # Replace the oldest entry if there are already 3 entries
            oldest_entry = password_history.first()
            oldest_entry.password = Password
            oldest_entry.created_at = timezone.now()
            oldest_entry.save()
        else:
            # Create a new entry if fewer than 3 entries
            PasswordHistory.objects.create(superuser=superadmin, password=Password)
        # SuperAdmin.objects.create(
        #     username=username,
        #     email_id=email,
        #     role="Super Admin",
        #     password=Password
        # )
        alarm_data = {
                "Temp 1 Low Alarm": 1001,
                "Temp 2 Low Alarm": 1002,
                "Temp 3 Low Alarm": 1003,
                "Temp 4 Low Alarm": 1004,
                "Temp 5 Low Alarm": 1005,
                "Temp 6 Low Alarm": 1006,
                "Temp 7 Low Alarm": 1007,
                "Temp 8 Low Alarm": 1008,
                "Temp 9 Low Alarm": 1009,
                "Temp 10 Low Alarm": 1010,
                "Temp 1 High Alarm": 1011,
                "Temp 2 High Alarm": 1012,
                "Temp 3 High Alarm": 1013,
                "Temp 4 High Alarm": 1014,
                "Temp 5 High Alarm": 1015,
                "Temp 6 High Alarm": 1016,
                "Temp 7 High Alarm": 1017,
                "Temp 8 High Alarm": 1018,
                "Temp 9 High Alarm": 1019,
                "Temp 10 High Alarm": 1020,
                "Temp 1 within Limit": 1021,
                "Temp 2 within Limit": 1022,
                "Temp 3 within Limit": 1023,
                "Temp 4 within Limit": 1024,
                "Temp 5 within Limit": 1025,
                "Temp 6 within Limit": 1026,
                "Temp 7 within Limit": 1027,
                "Temp 8 within Limit": 1028,
                "Temp 9 within Limit": 1029,
                "Temp 10 within Limit": 1030,
                "CS 1 Ckt Fail": 1031,
                "CS 2 Ckt Fail": 1032,
                "Dry Heater Ckt Fail": 1033,
                "Mains Power Fail": 1034,
                "Mains Power Resume": 1035,
                "LT Thermostat Trip": 1036,
                "HT Thermostat Trip": 1037,
                "Door Open": 1038,
                "Door Closed": 1039,
                "Water Level Low": 1040,
                "Water Level Ok": 1041,
                "RH 1 Low Alarm": 1042,
                "RH 2 Low Alarm": 1043,
                "RH 3 Low Alarm": 1044,
                "RH 4 Low Alarm": 1045,
                "RH 5 Low Alarm": 1046,
                "RH 6 Low Alarm": 1047,
                "RH 7 Low Alarm": 1048,
                "RH 8 Low Alarm": 1049,
                "RH 9 Low Alarm": 1050,
                "RH 10 Low Alarm": 1051,
                "RH 1 High Alarm": 1053,
                "RH 2 High Alarm": 1054,
                "RH 3 High Alarm": 1055,
                "RH 4 High Alarm": 1056,
                "RH 5 High Alarm": 1057,
                "RH 6 High Alarm": 1058,
                "RH 7 High Alarm": 1059,
                "RH 8 High Alarm": 1060,
                "RH 9 High Alarm": 1061,
                "RH 10 High Alarm": 1062,
                "RH 1 within Limit": 1063,
                "RH 2 within Limit": 1064,
                "RH 3 within Limit": 1065,
                "RH 4 within Limit": 1066,
                "RH 5 within Limit": 1067,
                "RH 6 within Limit": 1068,
                "RH 7 within Limit": 1069,
                "RH 8 within Limit": 1070,
                "RH 9 within Limit": 1071,
                "RH 10 within Limit": 1072,
                "User 1": 2001,
                "User 2": 2002,
                "User 3": 2003,
                "User 4": 2004,
                "User 5": 2005,
                "User 6": 2006,
                "User 7": 2007,
                "User 8": 2008,
                "User 9": 2009,
                "User 10": 2010,
                "User 11": 2011,
                "User 12": 2012,
                "User 13": 2013,
                "User 14": 2014,
                "User 15": 2015,
                "User 16": 2016,
                "User 17": 2017,
                "User 18": 2018,
                "User 19": 2019,
                "User 20": 2020,
            }
        for alarm_log, code in alarm_data.items():
            if not Alarm_codes.objects.filter(code=code).exists(): 
                Alarm_codes.objects.create(
                    alarm_log=alarm_log,
                    code=code,    
                )

        return redirect('login')
    password="SvReddy@0958$"
    context={"superadmin_password":password}
    return render(request, 'Base/registration.html', context)

from django.shortcuts import render

error_messages = {
    400: ("Bad Request", "The request could not be understood by the server."),
    403: ("Forbidden", "You don't have permission to access this resource."),
    404: ("Page Not Found", "The page you are looking for does not exist."),
    500: ("Server Error", "Something went wrong on our end. Please try again later."),
}

def custom_error_view(request, exception=None, error_code=500):
    error_title, error_message = error_messages.get(error_code, ("Unknown Error", "An unexpected error occurred."))
    return render(request, "errors/custom_error.html", {
        "error_code": error_code,
        "error_title": error_title,
        "error_message": error_message
    })

def error_400_view(request, exception):
    return custom_error_view(request, exception, 400)

def error_403_view(request, exception):
    return custom_error_view(request, exception, 403)

def error_404_view(request, exception):
    return custom_error_view(request, exception, 404)

def error_500_view(request):
    return custom_error_view(request, error_code=500)


def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        app_settings = AppSettings.objects.first()
        max_attempts = app_settings.lockcount if app_settings else 3

        if 'failed_attempts' not in request.session:
            request.session['failed_attempts'] = {}

        try:
            # SuperAdmin login without restrictions
            super_admin = SuperAdmin.objects.get(username__iexact=username)
            if check_password(password, super_admin.password):
                # Clear failed attempts for this username
                if username in request.session['failed_attempts']:
                    del request.session['failed_attempts'][username]
                request.session.modified = True

                request.session['username'] = super_admin.username
                messages.success(request, 'Login Successful!')

                UserActivityLog.objects.create(
                    user=super_admin.username,
                    log_date=timezone.localtime(timezone.now()).date(),
                    log_time=timezone.localtime(timezone.now()).time(),
                    event_name=f"SuperAdmin {super_admin.username} logged in"
                )
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid Username or Password!')

        except SuperAdmin.DoesNotExist:
            try:
                user = User.objects.get(username__iexact=username)

                # Reset failed attempts if user was unlocked
                if user.failed_attempts < max_attempts:
                    user.account_lock = False
                    user.save()

                if user.account_lock:
                    messages.error(
                        request, 'Your account has been locked. Please contact support.')
                    return render(request, 'Base/login.html')

                if user.status == 'Inactive':
                    messages.error(
                        request, 'Your account is inactive. Please contact support.')
                    return render(request, 'Base/login.html')

                # Check if password has expired
                password_age = (
                    timezone.now() -
                    user.last_password_change).days
                if password_age > app_settings.passwordchange:
                    messages.warning(
                        request, 'Your password has expired. Please change your password.')
                    show_change_password_modal = True
                    return render(request, 'Base/login.html',
                                  {'show_change_password_modal': show_change_password_modal})

                if user.pass_change == False:
                    success_msg = 'Please set a new password.'
                    return render(request, 'Base/login.html',
                                  {'success_msg': success_msg})

                if check_password(password, user.password):
                    # Clear failed attempts for this username
                    user.failed_attempts = 0
                    user.account_lock = False
                    user.save()

                    request.session.flush()
                    request.session['username'] = user.username
                    messages.success(request, 'Login Successful!')

                    UserActivityLog.objects.create(
                        user=user,
                        log_date=timezone.localtime(timezone.now()).date(),
                        log_time=timezone.localtime(timezone.now()).time(),
                        event_name=f"User {user.username} logged in"
                    )
                    return redirect('dashboard')
                else:

                    user.failed_attempts += 1
                    user.save()
                    attempts_left = max_attempts - user.failed_attempts

                    if user.failed_attempts >= max_attempts:
                        user.account_lock = True
                        user.save()
                        messages.error(
                            request, 'Your account has been locked due to multiple failed login attempts.')
                    else:
                        if attempts_left < 2:
                            messages.warning(
                                request, f'Warning: You have only {attempts_left} attempt(s) left.')
                        else:
                            messages.error(
                                request,
                                f'Invalid Username or Password! You have {attempts_left} attempt(s) left.')

                    request.session['failed_attempts'][username] = user.failed_attempts
                    request.session.modified = True
            except User.DoesNotExist:
                messages.error(request, 'User does not exist!')

        return render(request, 'Base/login.html')
    else:
        return render(request, 'Base/login.html')


def change_pass(request):
    # username = request.session.get('username')

    if request.method == 'POST':
        username_1 = request.POST.get('username')
        old_pass = request.POST.get('old_pass')
        new_pass = request.POST.get('new_pass')

        data = None
        for user in User.objects.all():
            if check_password(username_1, user.login_name):
                data = user
                break

        if data is None:
            error_msg = 'Invalid username. Please enter correct login name.'
            return render(request, 'Base/login.html', {'error_msg': error_msg})

        # Check if the provided username and old password are correct
        if check_password(username_1, data.login_name) and check_password(
                old_pass, data.password):
            # Check if the new password matches any of the last 3 passwords
            password_history = PasswordHistory.objects.filter(
                user=data).order_by('-created_at')[:3]
            if any(check_password(new_pass, history.password)
                   for history in password_history):
                error_msg = 'New password cannot be the same as any of the last 3 passwords.'

            # Update the password if no match is found in the last 3 entries
            user.password = new_pass
            data.password = make_password(new_pass)
            data.pass_change = True
            data.created_at = timezone.now() + timedelta(hours=5, minutes=30)
            data.last_password_change = now()
            data.save()

            # Log the password change
            UserActivityLog.objects.create(
                user=data.username,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"User {data.username} changed password"
            )

            # Check if user has 3 entries in PasswordHistory
            password_history = PasswordHistory.objects.filter(
                user=data).order_by('created_at')
            if password_history.count() >= 3:
                # If there are already 3 entries, replace the oldest entry
                oldest_entry = password_history.first()
                oldest_entry.password = data.password
                oldest_entry.created_at = timezone.now()
                oldest_entry.save()
            else:
                # If fewer than 3 entries, create a new entry
                PasswordHistory.objects.create(
                    user=data, password=data.password)

            # Flush the session
            success_msg_2 = 'Your password has been changed. Please login again'
            return render(request, 'Base/login.html',
                          {'success_msg_2': success_msg_2})
        else:
            error_msg = 'Please enter valid credentials.'
            return render(request, 'Base/login.html', {'error_msg': error_msg})


@csrf_exempt
def change_pass_2(request):
    username = request.session.get('username')
    data = User.objects.get(username=username)

    if request.method == 'POST':
        username_1 = request.POST.get('username')
        old_pass = request.POST.get('old_pass')
        new_pass = request.POST.get('new_pass')

        # Check if the provided username and old password are correct
        if check_password(username_1, data.login_name) and check_password(
                old_pass, data.password):
            # Check if the new password matches any of the last 3 passwords
            password_history = PasswordHistory.objects.filter(
                user=data).order_by('-created_at')[:3]
            if any(check_password(new_pass, history.password)
                   for history in password_history):
                return JsonResponse(
                    {'message': 'New password cannot be the same as any of the last 3 passwords.'})

            # Update the password if no match is found in the last 3 entries
            data.password = make_password(new_pass)
            data.pass_change = True
            data.created_at = timezone.now() + timedelta(hours=5, minutes=30)
            data.last_password_change = now()
            data.save()

            # Log the password change
            UserActivityLog.objects.create(
                user=username,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"User {data.username} changed password"
            )

            # Check if user has 3 entries in PasswordHistory
            password_history = PasswordHistory.objects.filter(
                user=data).order_by('created_at')
            if password_history.count() >= 3:
                # If there are already 3 entries, replace the oldest entry
                oldest_entry = password_history.first()
                oldest_entry.password = data.password
                oldest_entry.created_at = timezone.now()
                oldest_entry.save()
            else:
                # If fewer than 3 entries, create a new entry
                PasswordHistory.objects.create(
                    user=data, password=data.password)

            # Flush the session
            if username:
                request.session.flush()

            return JsonResponse(
                {'message': 'Your password has been changed. Please login again'})
        else:
            return JsonResponse({'message': 'Please enter valid credentials.'})

    emp_user = request.session.get('username', None)


def forgot_password(request):
    if request.method == 'POST':
        login_name = request.POST.get('forgot_username')
        old_password = request.POST.get('forgot_old_password')
        new_password = request.POST.get('forgot_new_password')
        confirm_password = request.POST.get('forgot_confirm_password')

        user = None
        is_superadmin = False

        for u in User.objects.all():
            if check_password(login_name, u.login_name):
                user = u
                break

        if user is None:
            for admin in SuperAdmin.objects.all():
                if admin.username == login_name:
                    user = admin
                    is_superadmin = True
                    break

        if not user:
            return JsonResponse({'message': 'User not found.'}, status=404)

        if is_superadmin:
            password_history = PasswordHistory.objects.filter(
                superuser=user).order_by('-created_at')[:3]
            user.password = new_password
            user.save()
        else:
            password_history = PasswordHistory.objects.filter(
                user=user).order_by('-created_at')[:3]

        if not any(history.check_password(old_password)
                   for history in password_history):
            return JsonResponse(
                {'message': 'The old password does not match any of the last 3 passwords.'}, status=403)

        if new_password != confirm_password:
            return JsonResponse(
                {'message': 'New password and confirm password do not match.'}, status=400)

        if any(history.check_password(new_password)
               for history in password_history):
            return JsonResponse(
                {'message': 'New password cannot be the same as any of the last 3 passwords.'}, status=400)

        if is_superadmin is False:
            hashed_new_password = make_password(new_password)
            user.password = hashed_new_password
            user.save()

        if is_superadmin:
            PasswordHistory.objects.create(
                superuser=user, password=new_password)
        else:
            PasswordHistory.objects.create(user=user, password=new_password)

        UserActivityLog.objects.create(
            user=user.username,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"User {user.username} reset password"
        )
        return JsonResponse(
            {'message': "Your password has been reset successfully. Please log in with your new password."})

    return render(request, 'Base/login.html')


def user_logout(request):
    username = request.session.get('username')

    if username:
        try:
            user = User.objects.get(username=username)

        except:
            user = SuperAdmin.objects.get(username=username)
        if user:
            # Log the logout event
            UserActivityLog.objects.create(
                user=username,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"User {user.username} logged out"
            )
    request.session.flush()
    messages.success(request, 'Logout successful!')
    return redirect('login')


# Dashboard
def dashboard(request):
    emp_user = request.session.get('username', None)

    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except User.DoesNotExist:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    organization = Organization.objects.first()
    equipment_data = []

    status = request.GET.get('status')

    equipment_queryset = Equipment.objects.filter(status='active')
    for eqp in equipment_queryset:
        alarms = Alarm_logs.objects.filter(equipment=eqp, acknowledge=False)
        pending_review_count = alarms.count()

        try:
            online = connect_to_plc(eqp.ip_address)
            if online:
                eqp.online = True
            else:
                eqp.online = False
        except Exception as e:
            eqp.online = False

        equipment_data.append({
            'id': eqp.id,
            'name': eqp.equip_name,
            'status': 'Online' if eqp.online == True else 'Offline',
            'pending_review': pending_review_count,
            'department_id': eqp.department.id if eqp.department else None,
        })

    return render(request, 'Dashboard/Dashboard.html', {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'equipment_data': equipment_data,
        'status_filter': status,
        'acc_dept':acc_dept
    })


def get_equipment_data(request):

    equipment_queryset = Equipment.objects.filter(status='active')
    equipment_data = []
    status = ""
    for eqp in equipment_queryset:
        alarms = Alarm_logs.objects.filter(equipment=eqp, acknowledge=False)
        pending_review_count = alarms.count()

        try:
            online = connect_to_plc(eqp.ip_address)
            status = "Online" if online else "Offline"
        except Exception:
            status = "Offline"

        equipment_data.append({
            'id': eqp.id,
            'name': eqp.equip_name,
            'status': status,
            'pending_review': pending_review_count,
            'department_id': eqp.department.id if eqp.department else None,
        })
    return JsonResponse({'equipment_data': equipment_data})
# Management-organization


def organization(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    if request.method == 'POST':
        # Saving the changes
        name = request.POST.get('name')
        email = request.POST.get('email')
        phoneNo = request.POST.get('phoneNo')
        address = request.POST.get('address')
        logo = request.FILES.get('logo')

        Organization_new = Organization(
            name=name,
            email=email,
            phoneNo=phoneNo,
            address=address,
            logo=logo
        )
        Organization_new.save()

        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name="Added Organization details"
        )

        messages.success(request, 'Organization details added successfully!')

        return redirect('organization')

    organization = Organization.objects.first()
    return render(request, 'Management/organization.html',
                  {'organization': organization, 'data': data, 'acc_db': acc_db, 'acc_dept':acc_dept})


def edit_organization(request, organization_id):

    emp_user = request.session.get('username', None)

    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()

    if request.method == 'POST':
        # Saving the changes
        organization.name = request.POST.get('name')
        organization.email = request.POST.get('email')
        organization.phoneNo = request.POST.get('phoneNo')
        organization.address = request.POST.get('address')

        if request.FILES.get('logo'):
            organization.logo = request.FILES['logo']

        organization.save()

        # Log the edit event
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name="Updated Organization details"
        )

        messages.success(request, 'Organization details updated successfully!')

        return redirect('organization')

    return render(request, 'Management/edit_organization.html',
                  {'organization': organization, 'data': data, 'acc_db': acc_db, 'acc_dept':acc_dept,})


def comm_group(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    soft_key = generate_soft_key()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    if request.method == "POST":
        try:
            comm_name = request.POST.get('comm_name')
            comm_code = request.POST.get('comm_code')
            soft_key = request.POST.get('softKey')
            activation_key = request.POST.get('activationKey')
            # Get validated device count from form input
            device_count = int(request.POST.get('device_count', 0))

            # Calculate the new total devices and save it to Organization’s nod
            current_nod = organization.get_nod()

            total_devices = current_nod + device_count
            organization.set_nod(total_devices)
            organization.save()

            new_commgroup = CommGroup(
                CommGroup_name=comm_name,
                CommGroup_code=comm_code,
                soft_key=soft_key,
                activation_key=activation_key,
            )
            new_commgroup.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"Added new comm.group {comm_name} details"
            )
            messages.success(request, 'Comm. Group added successfully!')
        except Exception:
            messages.error(
                request,
                "We couldn't add the Comm Group. Please check your input and try again.")
        return redirect('comm_group')

    comm_groups = CommGroup.objects.all()
    return render(request, 'Management/comm_group.html', {
        'organization': organization,
        'comm_groups': comm_groups,
        'data': data,
        'acc_db': acc_db,
        'soft_key': soft_key, 
        'acc_dept':acc_dept
    })


def validate_activation_key(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    if request.method == 'POST':
        emp_user = request.session.get('username', None)
        acc_dept=None
        if not emp_user:
            return redirect('login')
        try:
            data = User.objects.get(username=emp_user)
        except:
            data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

        entered_activation_key = request.POST.get('activation_key')
        entered_soft_key = request.POST.get('soft_key')

        try:
            if CommGroup.objects.filter(
                    activation_key=entered_activation_key).exists():
                return JsonResponse(
                    {'validation_icon': '✖', 'message': "Activation key already exists and cannot be reused"})

            current_pc_serial_no = get_motherboard_serial_number()

            if not current_pc_serial_no:
                raise ValueError("Unable to fetch motherboard serial number")

            decoded_soft_pc_serial_no = decode_soft_key(entered_soft_key)

            if decoded_soft_pc_serial_no != current_pc_serial_no:
                return JsonResponse(
                    {'validation_icon': '✖', 'message': "Soft Key's PC/Server Serial No does not match the current machine"})

            decoded_activation_string = decode_from_custom_base62(
                entered_activation_key)

            parts = decoded_activation_string.split('-')

            if len(
                    parts) != 7 or parts[1] != "IQBST" or parts[3] != "IIIQBETS" or parts[5] != "SUNWELL":
                return JsonResponse(
                    {'validation_icon': '✖', 'message': "Invalid Activation Key format"})

            decoded_activation_pc_serial_no = parts[2]
            device_count = int(parts[4])

            if decoded_activation_pc_serial_no != current_pc_serial_no:
                return JsonResponse(
                    {'validation_icon': '✖', 'message': "Activation Key's PC/Server Serial No does not match the current machine"})

            return JsonResponse(
                {'validation_icon': '✔', 'message': "Validation successful", 'device_count': device_count})

        except Exception as e:
            return JsonResponse(
                {'validation_icon': '✖', 'message': f"Validation failed, Activation Key is Invalid "})

    return JsonResponse(
        {'validation_icon': '✖', 'message': "Invalid request method"})


def edit_comm_group(request, comm_code):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    comm_group = get_object_or_404(CommGroup, CommGroup_code=comm_code)

    if request.method == "POST":
        try:
            comm_name = request.POST.get('edit_comm_name')
            soft_key = request.POST.get('edit_softKey')
            activation_key = request.POST.get('edit_activationKey')

            comm_group.CommGroup_name = comm_name
            comm_group.soft_key = soft_key
            comm_group.activation_key = activation_key
            comm_group.save()
            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"Updated {comm_name} Comm. Group details"
            )
            messages.success(
                request, f"Updated {comm_name} Comm. Group details")
        except:
            messages.error(
                request,
                f"Failed to updated {comm_name} Comm. Group details. Please check your input and try again.")

        return redirect('comm_group')

    return render(request, 'Management/comm_group.html',
                  {'organization': organization, 'comm_groups': comm_group, 'data': data, 'acc_db': acc_db, 'acc_dept':acc_dept})


def department(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    try:
        comm_group = CommGroup.objects.get(CommGroup_code=commgroup_name)
    except:
        comm_group = None

    if request.method == "POST":

        try:
            department_name = request.POST.get('departmentName')
            commgroup_name = request.POST.get('commGroup')
            header_note = request.POST.get('headerNote')
            footer_note = request.POST.get('footerNote')
            report_datetime_stamp = request.POST.get(
                'report_datetime_stamp') == 'True'

            email_sys = request.POST.get('email_status')
            delay_minutes = request.POST.get('email_delay')
            email_time = request.POST.get('email_time') or None

            email_address_1 = request.POST.get('email_address_1')
            email_address_2 = request.POST.get('email_address_2')
            email_address_3 = request.POST.get('email_address_3')
            email_address_4 = request.POST.get('email_address_4')
            email_address_5 = request.POST.get('email_address_5')
            email_address_6 = request.POST.get('email_address_6')
            email_address_7 = request.POST.get('email_address_7')
            email_address_8 = request.POST.get('email_address_8')
            email_address_9 = request.POST.get('email_address_9')
            email_address_10 = request.POST.get('email_address_10')
            sms_sys = request.POST.get('sms_sys')
            sms_delay = request.POST.get('sms_delay')
            sms_time = request.POST.get('sms_time') or None
            mobile_user1 = request.POST.get('mobile_user1') or None
            mobile_no1 = request.POST.get('mobile_no1') or None if request.POST.get(
                'mobile_no1', '').isdigit() else None

            mobile_user2 = request.POST.get('mobile_user2') or None
            mobile_no2 = request.POST.get('mobile_no2') or None if request.POST.get(
                'mobile_no2', '').isdigit() else None

            mobile_user3 = request.POST.get('mobile_user3') or None
            mobile_no3 = request.POST.get('mobile_no3') or None if request.POST.get(
                'mobile_no3', '').isdigit() else None

            mobile_user4 = request.POST.get('mobile_user4') or None
            mobile_no4 = request.POST.get('mobile_no4') or None if request.POST.get(
                'mobile_no4', '').isdigit() else None

            mobile_user5 = request.POST.get('mobile_user5') or None
            mobile_no5 = request.POST.get('mobile_no5') or None if request.POST.get(
                'mobile_no5', '').isdigit() else None

            mobile_user6 = request.POST.get('mobile_user6') or None
            mobile_no6 = request.POST.get('mobile_no6') or None if request.POST.get(
                'mobile_no6', '').isdigit() else None

            mobile_user7 = request.POST.get('mobile_user7') or None
            mobile_no7 = request.POST.get('mobile_no7') or None if request.POST.get(
                'mobile_no7', '').isdigit() else None

            mobile_user8 = request.POST.get('mobile_user8') or None
            mobile_no8 = request.POST.get('mobile_no8') or None if request.POST.get(
                'mobile_no8', '').isdigit() else None

            mobile_user9 = request.POST.get('mobile_user9') or None
            mobile_no9 = request.POST.get('mobile_no9') or None if request.POST.get(
                'mobile_no9', '').isdigit() else None

            mobile_user10 = request.POST.get('mobile_user10') or None
            mobile_no10 = request.POST.get('mobile_no10') or None if request.POST.get(
                'mobile_no10', '').isdigit() else None
            # sms_alert = True if sms_status == 'Enable' else False
            try:
                comm_group = CommGroup.objects.get(
                    CommGroup_code=commgroup_name)
            except CommGroup.DoesNotExist:
                messages.error(
                    request, "Selected Communication Group does not exist.")
                return redirect('department')

            new_department = Department(
                department_name=department_name,
                commGroup=comm_group,
                header_note=header_note,
                footer_note=footer_note,
                report_datetime_stamp=report_datetime_stamp,

                email_sys=email_sys,
                email_delay=delay_minutes,
                email_time=email_time,
                alert_email_address_1=email_address_1,
                alert_email_address_2=email_address_2,
                alert_email_address_3=email_address_3,
                alert_email_address_4=email_address_4,
                alert_email_address_5=email_address_5,
                alert_email_address_6=email_address_6,
                alert_email_address_7=email_address_7,
                alert_email_address_8=email_address_8,
                alert_email_address_9=email_address_9,
                alert_email_address_10=email_address_10,
                sms_sys=sms_sys,
                sms_delay=sms_delay,
                sms_time=sms_time,
                user1=mobile_user1,
                user1_num=mobile_no1,
                user2=mobile_user2,
                user2_num=mobile_no2,
                user3=mobile_user3,
                user3_num=mobile_no3,
                user4=mobile_user4,
                user4_num=mobile_no4,
                user5=mobile_user5,
                user5_num=mobile_no5,
                user6=mobile_user6,
                user6_num=mobile_no6,
                user7=mobile_user7,
                user7_num=mobile_no7,
                user8=mobile_user8,
                user8_num=mobile_no8,
                user9=mobile_user9,
                user9_num=mobile_no9,
                user10=mobile_user10,
                user10_num=mobile_no10

            )
            new_department.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"Added new department {department_name} details"
            )
            messages.success(
                request, f'Department {department_name} Saved Successfully!')
        except:
            messages.error(
                request,
                "We couldn't add the Department. Please check your input and try again.")

        return redirect('department')

    departments = Department.objects.all()
    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups,
        'organization': organization, 'data': data, 'acc_db': acc_db, 'acc_dept':acc_dept
    }

    return render(request, 'Management/department.html', context)


def edit_department(request, department_id):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    departments = get_object_or_404(Department, id=department_id)
    if request.method == "POST":
        try:
            department_name = request.POST.get(
                'edit_dept_name')  # Correct field name
            commgroup_name = request.POST.get('edit_commGroup')
            header_note = request.POST.get('edit_headerNote')
            footer_note = request.POST.get('edit_footerNote')
            report_datetime_stamp = request.POST.get(
                'edit_report_datetime_stamp') == 'True'

            email_sys = request.POST.get('edit_email_status')
            delay_minutes = request.POST.get('edit_email_delay')
            email_time = request.POST.get('edit_email_time') or None

            email_address_1 = request.POST.get('edit_email_address_1')
            email_address_2 = request.POST.get('edit_email_address_2')
            email_address_3 = request.POST.get('edit_email_address_3')
            email_address_4 = request.POST.get('edit_email_address_4')
            email_address_5 = request.POST.get('edit_email_address_5')
            email_address_6 = request.POST.get('edit_email_address_6')
            email_address_7 = request.POST.get('edit_email_address_7')
            email_address_8 = request.POST.get('edit_email_address_8')
            email_address_9 = request.POST.get('edit_email_address_9')
            email_address_10 = request.POST.get('edit_email_address_10')
            sms_sys = request.POST.get('edit_sms_sys')
            sms_delay = request.POST.get('edit_sms_delay')
            sms_time = request.POST.get('edit_sms_time')
            mobile_user1 = request.POST.get('edit_mobile_user1') or None
            mobile_no1 = request.POST.get('edit_mobile_no1') or None if request.POST.get(
                'edit_mobile_no1').isdigit() else None
            mobile_user2 = request.POST.get('edit_mobile_user2') or None
            mobile_no2 = request.POST.get('edit_mobile_no2') or None if request.POST.get(
                'edit_mobile_no2').isdigit() else None
            mobile_user3 = request.POST.get('edit_mobile_user3') or None
            mobile_no3 = request.POST.get('edit_mobile_no3') or None if request.POST.get(
                'edit_mobile_no3').isdigit() else None
            mobile_user4 = request.POST.get('edit_mobile_user4') or None
            mobile_no4 = request.POST.get('edit_mobile_no4') or None if request.POST.get(
                'edit_mobile_no4').isdigit() else None
            mobile_user5 = request.POST.get('edit_mobile_user5') or None
            mobile_no5 = request.POST.get('edit_mobile_no5') or None if request.POST.get(
                'edit_mobile_no5').isdigit() else None
            mobile_user6 = request.POST.get('edit_mobile_user6') or None
            mobile_no6 = request.POST.get('edit_mobile_no6') or None if request.POST.get(
                'edit_mobile_no6').isdigit() else None
            mobile_user7 = request.POST.get('edit_mobile_user7') or None
            mobile_no7 = request.POST.get('edit_mobile_no7') or None if request.POST.get(
                'edit_mobile_no7').isdigit() else None
            mobile_user8 = request.POST.get('edit_mobile_user8') or None
            mobile_no8 = request.POST.get('edit_mobile_no8') or None if request.POST.get(
                'edit_mobile_no8').isdigit() else None
            mobile_user9 = request.POST.get('edit_mobile_user9') or None
            mobile_no9 = request.POST.get('edit_mobile_no9') or None if request.POST.get(
                'edit_mobile_no9').isdigit() else None
            mobile_user10 = request.POST.get('edit_mobile_user10') or None
            mobile_no10 = request.POST.get('edit_mobile_no10') or None if request.POST.get(
                'edit_mobile_no10').isdigit() else None
            email_time = parse_time(email_time) if email_time else None
            sms_time = parse_time(sms_time) if sms_time else None
            if not department_name:
                # Handle the missing department name error
                return render(request, 'Management/department.html', {
                    'department': department,
                    'groups': CommGroup.objects.all(),
                    'error': 'Department name is required.'
                })

            commgroup = get_object_or_404(
                CommGroup, CommGroup_name=commgroup_name)

            # Update the department
            departments.department_name = department_name
            departments.commGroup = commgroup
            departments.header_note = header_note
            departments.footer_note = footer_note
            departments.report_datetime_stamp = report_datetime_stamp

            departments.email_sys = email_sys
            departments.email_delay = delay_minutes
            departments.email_time = email_time
            departments.alert_email_address_1 = email_address_1
            departments.alert_email_address_2 = email_address_2
            departments.alert_email_address_3 = email_address_3
            departments.alert_email_address_4 = email_address_4
            departments.alert_email_address_5 = email_address_5
            departments.alert_email_address_6 = email_address_6
            departments.alert_email_address_7 = email_address_7
            departments.alert_email_address_8 = email_address_8
            departments.alert_email_address_9 = email_address_9
            departments.alert_email_address_10 = email_address_10
            departments.sms_sys = sms_sys
            departments.sms_delay = sms_delay
            departments.sms_time = sms_time
            departments.user1 = mobile_user1
            departments.user1_num = mobile_no1
            departments.user2 = mobile_user2
            departments.user2_num = mobile_no2
            departments.user3 = mobile_user3
            departments.user3_num = mobile_no3
            departments.user4 = mobile_user4
            departments.user4_num = mobile_no4
            departments.user5 = mobile_user5
            departments.user5_num = mobile_no5
            departments.user6 = mobile_user6
            departments.user6_num = mobile_no6
            departments.user7 = mobile_user7
            departments.user7_num = mobile_no7
            departments.user8 = mobile_user8
            departments.user8_num = mobile_no8
            departments.user9 = mobile_user9
            departments.user9_num = mobile_no9
            departments.user10 = mobile_user10
            departments.user10_num = mobile_no10

            departments.save()

            # Log the edit event
            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"Edited Department {department_name} details"
            )

            messages.success(
                request, f"Updated {department_name} Department details")
        except:
            messages.error(
                request,
                f"Failed to updated {department_name} Department details. Please check your input and try again.")

        return redirect('department')

    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups,
        'data': data,
        'acc_db': acc_db,
        'acc_dept':acc_dept
    }

    return render(request, 'Management/department.html', context)


def users(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    try:
        role_data = User_role.objects.all()
    except:
        role_data = None

    app_settings = AppSettings.objects.first()
    password_duration = app_settings.passwordchange if app_settings else None

    if request.method == 'POST':
        try:
            username = request.POST.get('userName')
            login_name = request.POST.get('loginName')
            password = request.POST.get('password')
            password_duration = request.POST.get('passwordDuration')
            role = request.POST.get('role')
            comm_group = request.POST.get('commGroup')
            departmentname = request.POST.get('departmentName')
            status = request.POST.get('status')
            accessible_departments = request.POST.getlist(
                'accessibleDepartment')

            # Check if the user already exists
            if User.objects.filter(username=username).exists():
                messages.error(
                    request,
                    f"The username '{username}' already exists. Please choose a different username.")
                return redirect('users')

            commgroup = CommGroup.objects.get(CommGroup_code=comm_group)
            department = Department.objects.get(id=departmentname)

            # Create a new user
            newuser = User(
                username=username,
                login_name=login_name,
                password=password,
                password_duration=password_duration,
                role=role,
                commGroup=commgroup,
                department=department,
                status=status,
                created_at=timezone.now() + timedelta(hours=5, minutes=30)
            )
            newuser.save()

            if accessible_departments:
                selected_departments = Department.objects.filter(
                    id__in=accessible_departments)
                newuser.accessible_departments.set(selected_departments)

            # Handle password history
            password_history = PasswordHistory.objects.filter(
                user=newuser).order_by('created_at')
            if password_history.count() >= 3:
                # Replace the oldest entry if there are already 3 entries
                oldest_entry = password_history.first()
                oldest_entry.password = password
                oldest_entry.created_at = timezone.now()
                oldest_entry.save()
            else:
                # Create a new entry if fewer than 3 entries
                PasswordHistory.objects.create(user=newuser, password=password)

            # Log the add event
            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"Added new user {username} details"
            )

            messages.success(request, f"User '{username}' added successfully!")
        except:
            messages.error(
                request,
                "We couldn't add the User. Please check your input and try again.")

        return redirect('users')

    # Get the status and department filters from the query parameters
    status_filter = request.GET.get('status', 'Active')  # Default to "Active"
    department_filter = request.GET.get(
        'department', 'all')  # Default to "all"

    # Convert "all" to "All Status" for display
    if status_filter == "all":
        status_filter = "All Status"

    # Filter users based on status and department
    users = User.objects.all()

    if status_filter != "All Status":
        users = users.filter(status=status_filter)

    if department_filter != "all":
        users = users.filter(department_id=department_filter)

    # Count active, inactive, and total users for the current department filter
    active_count = User.objects.filter(status="Active", department_id=department_filter).count(
    ) if department_filter != "all" else User.objects.filter(status="Active").count()
    inactive_count = User.objects.filter(status="Inactive", department_id=department_filter).count(
    ) if department_filter != "all" else User.objects.filter(status="Inactive").count()
    total_count = User.objects.filter(department_id=department_filter).count(
    ) if department_filter != "all" else User.objects.count()

    # Precompute the count for the current filter
    current_count = total_count if status_filter == "All Status" else (
        active_count if status_filter == "Active" else inactive_count
    )

    departments = Department.objects.all()
    groups = CommGroup.objects.all()

    app_settings = AppSettings.objects.first()
    password_duration = app_settings.passwordchange if app_settings else None

    context = {
        'departments': departments,
        'groups': groups,
        'users': users,
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'role_data': role_data,
        'active_count': active_count,
        'password_duration': password_duration,
        'inactive_count': inactive_count,
        'total_count': total_count,
        'current_count': current_count,  # Pass the current count for the selected filter
        'status_filter': status_filter,
        # Pass the current department filter to the template
        'department_filter': department_filter,
        'acc_dept':acc_dept
    }
    return render(request, 'Management/user.html', context)


def edit_user(request, user_id):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    try:
        role_data = User_role.objects.all()
    except:
        role_data = None

    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        try:
            username = request.POST.get('editUsername')
            login_name = request.POST.get('editLoginName')
            password = request.POST.get('editPassword')
            password_duration = request.POST.get('editpasswordDuration')
            role = request.POST.get('editRole')
            comm_group_code = request.POST.get('editCommGroup')
            department_id = request.POST.get('editdepartmentName')
            status = request.POST.get('editstatus')
            accessible_departments = request.POST.getlist(
                'editaccessibleDepartment')
            account_lock = request.POST.get('editAccountLock') == 'on'

            comm_group = get_object_or_404(
                CommGroup, CommGroup_code=comm_group_code)
            department = get_object_or_404(Department, id=department_id)

            user.username = username
            user.password = password
            user.password_duration = password_duration
            user.role = role
            user.commGroup = comm_group
            user.department = department
            user.status = status
            user.account_lock = account_lock
            user.save()

            if not account_lock:
                user.failed_attempts = 0  # Reset failed attempts
                user.account_lock = False
                user.save()

            if accessible_departments:
                selected_departments = Department.objects.filter(
                    id__in=accessible_departments)
                user.accessible_departments.set(selected_departments)
            else:
                user.accessible_departments.clear()

            password_history = PasswordHistory.objects.filter(
                user=user).order_by('created_at')
            if password_history.count() >= 3:
                # Replace the oldest entry if there are already 3 entries
                oldest_entry = password_history.first()
                oldest_entry.password = password
                oldest_entry.created_at = timezone.now()
                oldest_entry.save()
            else:
                # Create a new entry if fewer than 3 exist
                PasswordHistory.objects.create(user=user, password=password)

            try:
                UserActivityLog.objects.create(
                    user=emp_user,
                    log_date=timezone.localtime(timezone.now()).date(),
                    log_time=timezone.localtime(timezone.now()).time(),
                    event_name=f"Updated {username} user details"
                )
            except User.DoesNotExist:
                pass
            messages.success(request, f"Updated {username} User details")
        except:
            messages.error(
                request,
                f"Failed to updated {username} User details. Please check your input and try again.")

        return redirect('users')

    departments = Department.objects.all()
    groups = CommGroup.objects.all()

    context = {
        'user': user,
        'departments': departments,
        'groups': groups,
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'role_data': role_data,
        'acc_dept':acc_dept
    }

    return render(request, 'Management/user.html', context)


def role_permission(request):

    emp_user = request.session.get('username', None)
    acc_dept= None
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    try:
        role_data = User_role.objects.all()
    except:
        role_data = None

    if request.method == 'POST':
        try:
            role = request.POST.get('role')
            description = request.POST.get('description')

            if role_data:
                for i in role_data:
                    if i.role == role:
                        error_msg = 'This {} has already in use.'.format(role)
                        return render(request, 'Management/role_permission.html', {
                                      'data': data, 'organization': organization, 'acc_db': acc_db, 'role_data': role_data, 'error_msg': error_msg})

            role_new = User_role(
                role=role,
                description=description,
            )
            role_new.save()

            user_access_new = user_access_db(
                role=role,
                org_v=True,
                c_group_v=True,
                dep_v=True,
                role_v=True,
                user_v=True,
                app_v=True,
                back_v=True,
                sys_v=True,
                res_v=True
            )
            user_access_new.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"Added new {role} role"
            )
            messages.success(request, f'Role is added successfully.!')
        except:
            messages.error(
                request,
                "We couldn't add the Role. Please check your input and try again.")
        return redirect('role_permission')

    return render(request, 'Management/role_permission.html',
                  {'organization': organization, 'data': data, 'acc_db': acc_db, 'acc_dept':acc_dept, 'role_data': role_data})


def edit_role(request, id):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    try:
        role_data = User_role.objects.all()
    except:
        role_data = None

    role_instance = get_object_or_404(User_role, id=id)

    if request.method == 'POST':
        try:
            role_instance = get_object_or_404(User_role, id=id)

            role_name = request.POST.get('role')
            description = request.POST.get('description')

            role_instance.role = role_name
            role_instance.description = description
            role_instance.save()

            try:
                access_instance = user_access_db.objects.get(
                    role=role_instance.role)
            except user_access_db.DoesNotExist:
                access_instance = None

            if access_instance:
                access_instance.role = role_name
                access_instance.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"Updated {role_name} role"
            )
            messages.success(request, f"Updated {role_name} role details")
        except:
            messages.error(
                request,
                f"Failed to updated {role_name} role details. Please check your input and try again.")

        return redirect('role_permission')

    return render(request, 'Management/role_permission.html',
                  {'organization': organization, 'data': data, 'acc_db': acc_db, 'role_data': role_data, 'acc_dept':acc_dept})


def user_access(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    role = request.GET.get('role', None)

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    try:
        role_dt = user_access_db.objects.get(role=role)
    except:
        role_dt = None

    success_msg = None

    if request.method == 'POST':

        def get_bool(value):
            return value == 'on'

        org_v = get_bool(request.POST.get('org_v'))
        org_a = get_bool(request.POST.get('org_a'))
        org_e = get_bool(request.POST.get('org_e'))
        org_d = get_bool(request.POST.get('org_d'))
        org_p = get_bool(request.POST.get('org_p'))

        c_group_v = get_bool(request.POST.get('c_group_v'))
        c_group_a = get_bool(request.POST.get('c_group_a'))
        c_group_e = get_bool(request.POST.get('c_group_e'))
        c_group_d = get_bool(request.POST.get('c_group_d'))
        c_group_p = get_bool(request.POST.get('c_group_p'))

        dep_v = get_bool(request.POST.get('dep_v'))
        dep_a = get_bool(request.POST.get('dep_a'))
        dep_e = get_bool(request.POST.get('dep_e'))
        dep_d = get_bool(request.POST.get('dep_d'))
        dep_p = get_bool(request.POST.get('dep_p'))

        role_v = get_bool(request.POST.get('role_v'))
        role_a = get_bool(request.POST.get('role_a'))
        role_e = get_bool(request.POST.get('role_e'))
        role_d = get_bool(request.POST.get('role_d'))
        role_p = get_bool(request.POST.get('role_p'))

        user_v = get_bool(request.POST.get('user_v'))
        user_a = get_bool(request.POST.get('user_a'))
        user_e = get_bool(request.POST.get('user_e'))
        user_d = get_bool(request.POST.get('user_d'))
        user_p = get_bool(request.POST.get('user_p'))

        app_v = get_bool(request.POST.get('app_v'))
        app_a = get_bool(request.POST.get('app_a'))
        app_e = get_bool(request.POST.get('app_e'))
        app_d = get_bool(request.POST.get('app_d'))
        app_p = get_bool(request.POST.get('app_p'))

        back_v = get_bool(request.POST.get('back_v'))
        back_a = get_bool(request.POST.get('back_a'))
        back_e = get_bool(request.POST.get('back_e'))
        back_d = get_bool(request.POST.get('back_d'))
        back_p = get_bool(request.POST.get('back_p'))

        sys_v = get_bool(request.POST.get('sys_v'))
        sys_a = get_bool(request.POST.get('sys_a'))
        sys_e = get_bool(request.POST.get('sys_e'))
        sys_d = get_bool(request.POST.get('sys_d'))
        sys_p = get_bool(request.POST.get('sys_p'))

        res_v = get_bool(request.POST.get('res_v'))
        res_a = get_bool(request.POST.get('res_a'))
        res_e = get_bool(request.POST.get('res_e'))
        res_d = get_bool(request.POST.get('res_d'))
        res_p = get_bool(request.POST.get('res_p'))

        e_conf_v = get_bool(request.POST.get('e_conf_v'))
        e_conf_a = get_bool(request.POST.get('e_conf_a'))
        e_conf_e = get_bool(request.POST.get('e_conf_e'))
        e_conf_d = get_bool(request.POST.get('e_conf_d'))

        e_set_v = get_bool(request.POST.get('e_set_v'))
        e_set_a = get_bool(request.POST.get('e_set_a'))
        e_set_e = get_bool(request.POST.get('e_set_e'))
        e_set_d = get_bool(request.POST.get('e_set_d'))

        v_log_v = get_bool(request.POST.get('v_log_v'))
        v_log_p = get_bool(request.POST.get('v_log_p'))

        a_log_v = get_bool(request.POST.get('a_log_v'))
        a_log_p = get_bool(request.POST.get('a_log_p'))

        mkt_v = get_bool(request.POST.get('mkt_v'))
        mkt_p = get_bool(request.POST.get('mkt_p'))

        sum_v = get_bool(request.POST.get('sum_v'))
        dis_v = get_bool(request.POST.get('dis_v'))
        io_v = get_bool(request.POST.get('io_v'))
        comp_v = get_bool(request.POST.get('comp_v'))

        u_act_v = get_bool(request.POST.get('u_act_v'))
        u_act_p = get_bool(request.POST.get('u_act_p'))

        u_equ_v = get_bool(request.POST.get('u_equ_v'))
        u_equ_p = get_bool(request.POST.get('u_equ_p'))

        a_act_v = get_bool(request.POST.get('a_act_v'))
        a_act_p = get_bool(request.POST.get('a_act_p'))

        e_aud_v = get_bool(request.POST.get('e_aud_v'))
        e_aud_p = get_bool(request.POST.get('e_aud_p'))

        s_act_v = get_bool(request.POST.get('s_act_v'))
        s_act_p = get_bool(request.POST.get('s_act_p'))

        if role_dt:
            role_dt.org_v = org_v
            role_dt.org_a = org_a
            role_dt.org_e = org_e
            role_dt.org_d = org_d
            role_dt.org_p = org_p

            role_dt.c_group_v = c_group_v
            role_dt.c_group_a = c_group_a
            role_dt.c_group_e = c_group_e
            role_dt.c_group_d = c_group_d
            role_dt.c_group_p = c_group_p

            role_dt.dep_v = dep_v
            role_dt.dep_a = dep_a
            role_dt.dep_e = dep_e
            role_dt.dep_d = dep_d
            role_dt.dep_p = dep_p

            role_dt.role_v = role_v
            role_dt.role_a = role_a
            role_dt.role_e = role_e
            role_dt.role_d = role_d
            role_dt.role_p = role_p

            role_dt.user_v = user_v
            role_dt.user_a = user_a
            role_dt.user_e = user_e
            role_dt.user_d = user_d
            role_dt.user_p = user_p

            role_dt.app_v = app_v
            role_dt.app_a = app_a
            role_dt.app_e = app_e
            role_dt.app_d = app_d
            role_dt.app_p = app_p

            role_dt.back_v = back_v
            role_dt.back_a = back_a
            role_dt.back_e = back_e
            role_dt.back_d = back_d
            role_dt.back_p = back_p

            role_dt.sys_v = sys_v
            role_dt.sys_a = sys_a
            role_dt.sys_e = sys_e
            role_dt.sys_d = sys_d
            role_dt.sys_p = sys_p

            role_dt.res_v = res_v
            role_dt.res_a = res_a
            role_dt.res_e = res_e
            role_dt.res_d = res_d
            role_dt.res_p = res_p

            role_dt.e_conf_v = e_conf_v
            role_dt.e_conf_a = e_conf_a
            role_dt.e_conf_e = e_conf_e
            role_dt.e_conf_d = e_conf_d

            role_dt.e_set_v = e_set_v
            role_dt.e_set_a = e_set_a
            role_dt.e_set_e = e_set_e
            role_dt.e_set_d = e_set_d

            role_dt.v_log_v = v_log_v
            role_dt.v_log_p = v_log_p

            role_dt.a_log_v = a_log_v
            role_dt.a_log_p = a_log_p

            role_dt.mkt_v = mkt_v
            role_dt.mkt_p = mkt_p

            role_dt.sum_v = sum_v
            role_dt.dis_v = dis_v
            role_dt.io_v = io_v
            role_dt.comp_v = comp_v

            role_dt.u_act_v = u_act_v
            role_dt.u_act_p = u_act_p

            role_dt.u_equ_v = u_equ_v
            role_dt.u_equ_p = u_equ_p

            role_dt.a_act_v = a_act_v
            role_dt.a_act_p = a_act_p

            role_dt.e_aud_v = e_aud_v
            role_dt.e_aud_p = e_aud_p

            role_dt.s_act_v = s_act_v
            role_dt.s_act_p = s_act_p

            role_dt.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name="Role and permissions updated"
            )

            success_msg = 'Roles and permissions are updated.'
            return render(request, 'Management/user_group.html', {'organization': organization, 'data': data,
                          'acc_db': acc_db, 'role': role, 'role_dt': role_dt, 'success_msg': success_msg})

        else:
            acc_db_new = user_access_db(
                role=role,

                org_v=org_v,
                org_a=org_a,
                org_e=org_e,
                org_d=org_d,
                org_p=org_p,

                c_group_v=c_group_v,
                c_group_a=c_group_a,
                c_group_e=c_group_e,
                c_group_d=c_group_d,
                c_group_p=c_group_p,

                dep_v=dep_v,
                dep_a=dep_a,
                dep_e=dep_e,
                dep_d=dep_d,
                dep_p=dep_p,

                role_v=role_v,
                role_a=role_a,
                role_e=role_e,
                role_d=role_d,
                role_p=role_p,

                user_v=user_v,
                user_a=user_a,
                user_e=user_e,
                user_d=user_d,
                user_p=user_p,

                app_v=app_v,
                app_a=app_a,
                app_e=app_e,
                app_d=app_d,
                app_p=app_p,

                back_v=back_v,
                back_a=back_a,
                back_e=back_e,
                back_d=back_d,
                back_p=back_p,

                sys_v=sys_v,
                sys_a=sys_a,
                sys_e=sys_e,
                sys_d=sys_d,
                sys_p=sys_p,

                res_v=res_v,
                res_a=res_a,
                res_e=res_e,
                res_d=res_d,
                res_p=res_p,
            )
            acc_db_new.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name="Role and permissions updated"
            )

            success_msg = 'Roles and permissions are added.'
            return render(request, 'Management/user_group.html', {
                'organization': organization,
                'data': data,
                'acc_db': acc_db,
                'role_dt': role_dt,
                'role': role,
                'success_msg': success_msg
            })

    return render(request, 'Management/user_group.html',
                  {'organization': organization, 'data': data, 'acc_db': acc_db, 'role_dt': role_dt, 'role': role, 'acc_dept':acc_dept})


def app_settings(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    if request.method == 'POST':
        try:
            email_sys_set = request.POST.get('email_setting_status')
            smpthost = request.POST.get('smpthost')
            smtpPort = request.POST.get('smtpPort')
            smptemail = request.POST.get('smptemail')
            smptpass = request.POST.get('smptpass')
            emailsignature = request.POST.get('emailsignature')

            # Update or Create
            app_email_settings, created = AppSettings.objects.update_or_create(
                id=1,  # Assuming a single settings instance
                defaults={
                    'email_sys_set': email_sys_set,
                    'email_host': smpthost,
                    'email_port': smtpPort,
                    'email_host_user': smptemail,
                    'email_host_password': smptpass,
                    'email_signature': emailsignature
                }
            )

            # Log the settings update
            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name="Updated Application settings"
            )
            messages.success(
                request, 'Application settings saved successfully!')
        except:
            messages.error(
                request,
                "We couldn't save App Settings. Please check your input and try again.")
        return redirect('app_settings')

    # Fetch the existing settings
    app_email_settings = AppSettings.objects.first()
    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'app_settings': app_email_settings,
        'acc_dept':acc_dept
    }

    return render(request, 'Management/app_settings.html', context)


def app_sms_settings(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    acc_db = user_access_db.objects.filter(role=data.role).first()

    if request.method == 'POST':
        try:
            sms_sys_set = request.POST.get('sms_setting_status')
            comm_port = request.POST.get('commport')
            parity = request.POST.get('parity')
            baud_rate = request.POST.get('baudrate')
            data_bits = request.POST.get('databits')
            stop_bits = request.POST.get('stopbits')
            flow_control = request.POST.get('flowcontrol')
            passwordchange = request.POST.get('password_change')
            autologout = request.POST.get('system_auto_logout')
            lock = request.POST.get('user_access_lock')
            # Update or Create
            app_sms_settings, created = AppSettings.objects.update_or_create(
                id=1,  # Assuming a single settings instance
                defaults={
                    'sms_sys_set': sms_sys_set,
                    'comm_port': comm_port,
                    'parity': parity,
                    'baud_rate': baud_rate,
                    'data_bits': data_bits,
                    'stop_bits': stop_bits,
                    'flow_control': flow_control,
                    'passwordchange': passwordchange,
                    'autologouttime': autologout,
                    'lockcount': lock
                }
            )

            # Log the settings update
            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name="Updated SMS settings"
            )

            messages.success(request, 'SMS settings saved successfully!')
        except:
            messages.error(
                request,
                f"We couldn't save App Settings. Please check your input and try again.")
        return redirect('app_sms_settings')

    # Fetch the existing SMS settings
    app_sms_settings = AppSettings.objects.first()
    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'app_settings': app_sms_settings,
        'acc_dept':acc_dept
    }

    return render(request, 'Management/app_settings.html', context)


@csrf_protect
def save_app_settings(request):
    if request.method == 'POST':
        settings_data = json.loads(request.body)

        tab_name = settings_data.get('tab_name')

        try:

            app_settings, created = AppSettings.objects.get_or_create(id=1)

            if tab_name == "App Settings":
                app_settings.passwordchange = settings_data.get(
                    'password_change')
                app_settings.lockcount = settings_data.get('user_access_lock')
                app_settings.autologouttime = settings_data.get(
                    'system_auto_logout')

            elif tab_name == "Email Settings":
                status = settings_data.get('email_sys', "False")
                app_settings.email_sys_set = str(
                    status).strip().lower() == "true"
                app_settings.email_host = settings_data.get('smpthost')
                app_settings.email_host_user = settings_data.get('smptemail')
                app_settings.email_host_password = settings_data.get(
                    'smptpass')
                app_settings.email_port = settings_data.get('smtpPort')
                app_settings.email_signature = settings_data.get(
                    'emailsignature')

            elif tab_name == "SMS Settings":
                status = settings_data.get('sms_sys', "False")
                app_settings.sms_sys_set = str(
                    status).strip().lower() == "true"
                app_settings.comm_port = settings_data.get('commport')
                app_settings.baud_rate = settings_data.get('baudrate')
                app_settings.data_bits = settings_data.get('databits')
                app_settings.stop_bits = settings_data.get('stopbits')
                app_settings.parity = settings_data.get('parity')
                app_settings.flow_control = settings_data.get('flowcontrol')

            app_settings.save()

            return JsonResponse(
                {'status': 'success', 'message': f'Settings for {tab_name} updated successfully'})

        except Exception as e:
            return JsonResponse(
                {'status': 'error', 'message': 'An error occurred while updating settings'}, status=500)

    return JsonResponse(
        {'status': 'error', 'message': 'Invalid request'}, status=400)


def send_test_sms(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')

    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    if request.method == 'POST':
        try:
            # Retrieve the phone number and time from the request
            test_sms_number = request.POST.get('testsms')
            test_sms_time = request.POST.get('testsmstime')

            if not test_sms_number:
                messages.error(request, "Please provide a valid phone number.")
                return redirect('app_sms_settings')

            # Fetch SMS settings from the database
            sms_settings = AppSettings.objects.first()
            if not sms_settings:
                messages.error(request, "SMS settings not configured.")
                return redirect('app_sms_settings')

            message = "This is test SMS from ESTDAS application"

            # Check if a time is provided
            if test_sms_time:
                try:
                    # Parse and calculate the delay for scheduled SMS
                    sms_datetime = datetime.strptime(
                        test_sms_time, "%H:%M").time()
                    now = datetime.now().time()
                    delay = (
                        datetime.combine(
                            date.today(),
                            sms_datetime) -
                        datetime.now()).total_seconds()
                    if delay < 0:
                        delay += 86400  # Schedule for the next day

                    # Schedule SMS in the queue with delay
                    number = {"N/A": test_sms_number}
                    equipment = None
                    alarm_id = None
                    sys_sms = True
                    threading.Timer(
                        delay,
                        add_to_sms_queue,
                        args=[
                            number,
                            message,
                            equipment,
                            alarm_id,
                            sys_sms]).start()
                    messages.success(
                        request, f"SMS scheduled to {test_sms_number} at {test_sms_time}.")
                except ValueError:
                    messages.error(
                        request, "Invalid time format. Please use HH:MM.")
                    return redirect('app_sms_settings')
            else:
                # Send SMS immediately by adding to the queue
                number = {"N/A": test_sms_number}
                add_to_sms_queue(
                    number,
                    message,
                    equipment=None,
                    alarm_id=None,
                    sys_sms=True)
                messages.success(request, "Test SMS sent successfully!")

        except Exception as e:
            messages.error(
                request,
                f"We couldn't send the message. Error: {
                    str(e)}")

        return redirect('app_sms_settings')

    else:
        messages.error(request, "Invalid request method.")
        return redirect('app_sms_settings')


def send_test_email(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    if request.method == 'POST':
        try:
            recipient_email = request.POST.get('testemail')
            email_time = request.POST.get('testemailtime')

            # Fetch the email settings dynamically
            app_settings = AppSettings.objects.first()
            if not app_settings or not app_settings.email_sys_set:
                messages.error(
                    request, "Email is disabled or App Settings not configured.")
                return redirect('app_settings')

            email_settings = get_email_settings(request)
            if not email_settings:
                messages.error(request, "Email settings are not configured.")
                return redirect('app_settings')

            subject = 'ESTDAS Test Email'
            message = (
                f"This is test email from ESTDAS application"
                f"\n\n{app_settings.email_signature or ''}"
            )

            # Set the dynamic email settings
            settings.EMAIL_HOST = email_settings['EMAIL_HOST']
            settings.EMAIL_HOST_USER = email_settings['EMAIL_HOST_USER']
            settings.EMAIL_HOST_PASSWORD = email_settings['EMAIL_HOST_PASSWORD']
            settings.EMAIL_PORT = email_settings['EMAIL_PORT']

            ist_timezone = pytz.timezone("Asia/Kolkata")
            current_time = datetime.now(ist_timezone).time()
            # Function to send the email

            def send_email():
                try:
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=email_settings['EMAIL_HOST_USER'],
                        recipient_list=[recipient_email],
                        fail_silently=False,
                    )

                    # Log successful email attempt
                    Email_logs.objects.create(
                        time=current_time,
                        date=datetime.now(ist_timezone).date(),
                        equipment=None,  # Assuming None is set for no specific equipment
                        sys_mail=True,
                        to_email=recipient_email,
                        email_sub=subject,
                        email_body=message,
                        status='Sent'
                    )
                except Exception as e:
                    # Log failed email attempt
                    Email_logs.objects.create(
                        time=current_time,
                        date=datetime.now(ist_timezone).date(),
                        equipment=None,  # Assuming None is set for no specific equipment
                        sys_mail=True,
                        to_email=recipient_email,
                        email_sub=subject,
                        email_body=message,
                        status='Failed'
                    )

            # Calculate delay if time is provided
            if email_time:
                try:
                    # Parse the provided time
                    email_datetime = datetime.strptime(
                        email_time, "%H:%M").time()
                    now = datetime.now().time()

                    # Combine the date with the time for full datetime
                    # comparison
                    today_date = date.today()
                    email_datetime_full = datetime.combine(
                        today_date, email_datetime)
                    now_full = datetime.combine(today_date, now)

                    # Calculate delay in seconds
                    delay = (email_datetime_full - now_full).total_seconds()

                    # If delay is negative, schedule the email for the next day
                    if delay < 0:
                        email_datetime_full += timedelta(days=1)
                        delay = (
                            email_datetime_full -
                            now_full).total_seconds()

                    # Schedule email with delay
                    threading.Timer(delay, send_email).start()
                except ValueError:
                    return HttpResponse(
                        "Invalid time format. Please use HH:MM.", status=400)
            else:
                # Send email immediately if no time is provided
                send_email()
            messages.success(request, "Test Email sent Successfully!")
        except:
            messages.error(
                request,
                "We couldn't send email. Please check your input and try again.")

        return redirect('app_settings')
    else:
        return HttpResponse("Invalid request method.", status=405)


def backup(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')

    try:
        data = User.objects.get(username=emp_user)
    except User.DoesNotExist:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    if request.method == 'POST':
        local_path = request.POST.get('backup-local-path', '').strip()
        remote_path = request.POST.get('backup-remote-path', '').strip()
        backup_time_str = request.POST.get('backup-time', '').strip()

        if backup_time_str:
            try:
                backup_time = datetime.strptime(
                    backup_time_str, "%H:%M").time()
            except ValueError:
                messages.error(
                    request, "Invalid time format. Please enter a valid time.")
                return redirect('backup')
        else:
            backup_time = None

        try:
            backup_setting, created = BackupSettings.objects.get_or_create(
                defaults={
                    'local_path': local_path, 'remote_path': remote_path, 'backup_time': backup_time})
            backup_setting.local_path = local_path
            backup_setting.remote_path = remote_path
            backup_setting.backup_time = backup_time
            backup_setting.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name="Added or updated backup settings"
            )

            messages.success(request, 'Backup settings saved successfully!')
        except Exception as e:
            messages.error(
                request,
                f"We couldn't save Backup Settings due to an error: {
                    str(e)}")
        return redirect('backup')

    backup_setting = BackupSettings.objects.first()
    context = {
        'data': data,
        'acc_db': acc_db,
        'backup_setting': backup_setting,
        'acc_dept':acc_dept
    }

    return render(request, 'Management/backup.html', context)


def edit_backup(request, id):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')

    try:
        data = User.objects.get(username=emp_user)
    except User.DoesNotExist:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    backup_setting = get_object_or_404(BackupSettings, id=id)

    if request.method == 'POST':
        local_path = request.POST.get('backup-local-path', '').strip()
        remote_path = request.POST.get('backup-remote-path', '').strip()
        backup_time_str = request.POST.get('backup-time', '').strip()

        if backup_time_str:
            try:
                backup_setting.backup_time = datetime.strptime(
                    backup_time_str, "%H:%M").time()
            except ValueError:
                messages.error(
                    request, "Invalid time format. Please enter a valid time.")
                return redirect('edit_backup', id=id)

        try:
            backup_setting.local_path = local_path
            backup_setting.remote_path = remote_path
            backup_setting.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name="Updated backup settings"
            )

            messages.success(request, 'Updated Backup settings successfully!')
        except Exception as e:
            messages.error(
                request,
                f"Failed to update Backup Setting details due to an error: {
                    str(e)}")
        return redirect('backup')

    context = {
        'backup_setting': backup_setting,
        'data': data,
        'acc_db': acc_db,
        'acc_dept':acc_dept
    }

    return render(request, 'Management/edit_backup.html', context)


def download_backup(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    status, message = perform_backup()

    # Log the download event
    UserActivityLog.objects.create(
        user=emp_user,
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name=f"Downloaded database backup"
    )
    return JsonResponse({"status": status, "message": message})


def perform_backup():
    # Fetch the latest backup settings
    backup_setting = BackupSettings.objects.last()
    if not backup_setting:
        return "failure", "No backup settings found."

    # Construct the backup filename and paths
    current_time = datetime.now().strftime("%d%m%Y_%H%M")
    backup_filename = f"ESTDAS_{current_time}.bak"
    local_backup_file_path = os.path.join(
        backup_setting.local_path, backup_filename)

    # Ensure paths exist
    if not os.path.exists(backup_setting.local_path):
        return "failure", f"Local backup path '{backup_setting.local_path}' does not exist."

    if backup_setting.remote_path and not os.path.exists(
            backup_setting.remote_path):
        return "failure", f"Remote backup path '{backup_setting.remote_path}' does not exist."

    # Remove existing .bak files in the local path
    for file_name in os.listdir(backup_setting.local_path):
        if file_name.endswith(".bak"):
            os.remove(os.path.join(backup_setting.local_path, file_name))

    # Remove existing .bak files in the remote path if applicable
    if backup_setting.remote_path:
        for file_name in os.listdir(backup_setting.remote_path):
            if file_name.endswith(".bak"):
                os.remove(os.path.join(backup_setting.remote_path, file_name))

    # Database connection details
    db_settings = settings.DATABASES['default']
    db_name = db_settings['NAME']
    db_user = db_settings['USER']
    db_password = db_settings['PASSWORD']
    db_host = db_settings['HOST']

    # Local backup command
    local_backup_command = (
        f"sqlcmd -S {db_host} -U {db_user} -P {db_password} "
        f"-Q \"BACKUP DATABASE [{db_name}] TO DISK = N'{local_backup_file_path}'\""
    )

    try:
        # Execute local backup
        subprocess.run(local_backup_command, check=True, shell=True)

        # If a remote path is provided, also perform a remote backup
        if backup_setting.remote_path:
            remote_backup_file_path = os.path.join(
                backup_setting.remote_path, backup_filename)
            remote_backup_command = (
                f"sqlcmd -S {db_host} -U {db_user} -P {db_password} "
                f"-Q \"BACKUP DATABASE [{db_name}] TO DISK = N'{remote_backup_file_path}'\""
            )
            subprocess.run(remote_backup_command, check=True, shell=True)

        return "success", "Backup completed successfully."
    except subprocess.CalledProcessError as e:
        return "failure", f"Backup failed: {str(e)}"
    except Exception as e:
        return "failure", f"An unexpected error occurred: {str(e)}"


# Initialize the scheduler
scheduler = BackgroundScheduler()


def schedule_backup(backup_time):
    scheduler.remove_all_jobs()  # Clear any existing jobs

    if backup_time:
        trigger = CronTrigger(hour=backup_time.hour, minute=backup_time.minute)
        scheduler.add_job(perform_backup, trigger, id="daily_backup")


def monitor_backup_settings():
    while True:
        backup_setting = BackupSettings.objects.last()
        if backup_setting and backup_setting.backup_time:
            schedule_backup(backup_setting.backup_time)
        time.sleep(10)  # Check for updates every 10 seconds


def start_backup_scheduler():
    scheduler.start()

    monitor_thread = threading.Thread(
        target=monitor_backup_settings, daemon=True)
    monitor_thread.start()


start_backup_scheduler()


def restore(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    return render(request, 'Management/restore.html',
                  {'organization': organization, 'data': data, 'acc_db': acc_db, 'acc_dept':acc_dept})


# PLC code


PLC_RACK = 0
PLC_SLOT = 1
DB_NUMBER_TEMPS = 4
DB_NUMBER_LIMITS = 19
OFFSETS_LIMITS = {
    "LOW_ALARM_LIMIT": 4,
    "SET_TEMP": 0,
    "HIGH_ALARM_LIMIT": 8,
    "INTERVAL": 14,
    "EQUIPMENT": 66,
}


def connect_to_plc(ip_address):
    try:
        plc = snap7.client.Client()
        plc.connect(ip_address, PLC_RACK, PLC_SLOT)
        return plc
    except Exception as e:
        raise e


def write_interval_to_plc(plc, interval):

    try:

        interval_data = bytearray(4)
        snap7.util.set_int(interval_data, 0, int(interval))

        plc.db_write(
            DB_NUMBER_LIMITS,
            OFFSETS_LIMITS["INTERVAL"],
            interval_data)

        read_interval_data = plc.db_read(
            DB_NUMBER_LIMITS, OFFSETS_LIMITS["INTERVAL"], 4)
        read_interval = snap7.util.get_int(read_interval_data, 0)

    except Exception as e:
        raise e


def extract_number_of_sensors(equipment_type_description):

    match = re.search(r'\b(\d+)\b', equipment_type_description)
    if match:
        return int(match.group(1))
    else:
        return None


def plc_connect(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ipaddress')

        try:
            plc = connect_to_plc(ip_address)
            if plc.get_connected():
                interval = read_data(
                    plc, DB_NUMBER_LIMITS, OFFSETS_LIMITS["INTERVAL"])
                data = plc.db_read(
                    DB_NUMBER_LIMITS, OFFSETS_LIMITS["INTERVAL"], 4)

                read_interval = snap7.util.get_int(data, 0)

                equipment_type = plc.db_read(
                    DB_NUMBER_LIMITS, OFFSETS_LIMITS["EQUIPMENT"], 2)
                data = read_plc_data(plc, 4, 4, 4)
                pv = snap7.util.get_real(data, 0)
                data = read_plc_data(plc, 19, 8, 4)
                High_Temp = snap7.util.get_real(data, 0)
                data1 = read_plc_data(plc, 19, 4, 4)
                low_Temp = snap7.util.get_real(data1, 0)
                data2 = read_plc_data(plc, 19, 0, 4)
                sv = snap7.util.get_real(data2, 0)
                data3 = read_plc_data(plc, 19, 64, 3)
                cooling = snap7.util.get_bool(data3, 0, 0)
                data = read_plc_data(plc, 19, 776, 4)
                low = snap7.util.get_real(data, 0)
                data1 = read_plc_data(plc, 19, 780, 4)
                high = snap7.util.get_real(data1, 0)

                equipment_mapping = {
                    11: "Temperature only - No of Sensor 1",
                    12: "Temperature only - No of Sensor 2",
                    13: "Temperature only - No of Sensor 3",
                    14: "Temperature only - No of Sensor 4",
                    15: "Temperature only - No of Sensor 5",
                    16: "Temperature only - No of Sensor 6",
                    17: "Temperature only - No of Sensor 7",
                    18: "Temperature only - No of Sensor 8",
                    19: "Temperature only - No of Sensor 9",
                    210: "Temperature only - No of Sensor 10",
                    21: "Temp and Humidity - No of Sensor 1",
                    22: "Temp and Humidity - No of Sensor 2",
                    23: "Temp and Humidity - No of Sensor 3",
                    24: "Temp and Humidity - No of Sensor 4",
                    25: "Temp and Humidity - No of Sensor 5",
                    26: "Temp and Humidity - No of Sensor 6",
                    27: "Temp and Humidity - No of Sensor 7",
                    28: "Temp and Humidity - No of Sensor 8",
                    29: "Temp and Humidity - No of Sensor 9",
                    310: "Temp and Humidity - No of Sensor 10",
                    31: "Temp and LU, UV - No of Sensor 1",
                    32: "Temp and LU, UV - No of Sensor 2",
                    33: "Temp and LU, UV - No of Sensor 3",
                    34: "Temp and LU, UV - No of Sensor 4",
                    35: "Temp and LU, UV - No of Sensor 5",
                    36: "Temp and LU, UV - No of Sensor 6",
                    37: "Temp and LU, UV - No of Sensor 7",
                    38: "Temp and LU, UV - No of Sensor 8",
                }
                code = snap7.util.get_word(equipment_type, 0)
                equipment_type = equipment_mapping.get(
                    code, "Unknown Equipment Type")
                equ = extract_number_of_sensors(equipment_type)

                try:
                    equipment = Equipment.objects.get(ip_address=ip_address)
                    equipment.is_connected = True
                    equipment.save()

                except Equipment.DoesNotExist:
                    pass
                return JsonResponse({
                    'status': 'connected',
                    'interval': read_interval,
                    'equiptype': equipment_type,
                    'sensors': equ
                })
            else:
                return JsonResponse(
                    {'status': 'failed', 'error': 'Failed to connect to PLC.'})
        except Exception as e:
            return JsonResponse({'status': 'failed', 'error': str(e)})

    return JsonResponse(
        {'status': 'failed', 'error': 'Invalid request method.'})


def plc_disconnect(request):
    if request.method == 'POST':
        ip_address = request.POST.get('ipaddress')

        try:
            equipment = Equipment.objects.filter(ip_address=ip_address).first()

            if equipment and equipment.is_connected:
                # Mark equipment as disconnected
                equipment.is_connected = False
                equipment.save()

                # Trigger the stop event for this equipment's background task
                # stop_event = stop_flags.get(equipment.id)
                if stop_event:
                    stop_event.set()
                    time.sleep(2)
                    if stop_event.is_set():
                        pass

                    # del stop_flags[equipment.id]

                    plc = connect_to_plc(ip_address)
                    if plc.get_connected():
                        plc.disconnect()
                    else:
                        pass

                    return JsonResponse({'status': 'disconnected'})
                else:

                    return JsonResponse(
                        {'status': 'failed', 'error': 'No background task found.'})
            else:

                return JsonResponse(
                    {'status': 'disconnected', 'message': 'PLC was already disconnected.'})
        except Exception as e:

            return JsonResponse({'status': 'failed', 'error': str(e)})

    return JsonResponse(
        {'status': 'failed', 'error': 'Invalid request method.'})


def read_data(plc, db_number, offset):
    try:

        raw_data = plc.db_read(db_number, offset, 4)
        value = get_real(raw_data, 0)
        if value is not None and value != 0.0:
            return round(value, 2)
        return None
    except Exception as e:
        return None
    except Exception as e:
        return None


stop_event = threading.Event()  # Shared stop event for the background task


def background_task_for_all_equipment(interval):
   
    while not stop_event.is_set():  # If stop_event is not set, keep running
        try:

          
            active_equipments = Equipment.objects.filter(status='active')
            for equipment in active_equipments:
              
                try:

                    
                    download_process_logs(equipment.ip_address, equipment.id)

                except Exception as e:
                    pass

         
            time.sleep(interval * 60) 

        except Exception as e:

            break


def download_process_logs(ip_address, equipment_id):

    results = {}

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "/",
            "Connection": "keep-alive",
            "Referer": f"http://{ip_address}/Portal/Portal.mwsl?PriNav=DataLogs",
        }

        log_urls = {
            "alarm": f"http://{ip_address}/DataLogs?Path=1001_ALARM_LOG.csv&Action=DOWNLOAD",
            "data": f"http://{ip_address}/DataLogs?Path=1001_DATA_LOG.csv&Action=DOWNLOAD",
        }

        for log_type, url in log_urls.items():

            response = requests.get(
                url, headers=headers, stream=True, timeout=120)

            if response.status_code == 200:
                try:
                    eqp = Equipment.objects.get(ip_address=ip_address)
                except ObjectDoesNotExist:

                    results[log_type] = f"Equipment with IP {ip_address} not found."
                    continue
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")  
               
                unique_suffix = str(uuid.uuid4())[:8]
                folder_name = f"{log_type}_logs"
                file_name = f"{
                    log_type.capitalize()}Log_{
                    eqp.ip_address}{timestamp}{unique_suffix}.csv"
                file_path = os.path.join(
                    "media", "logs", folder_name, file_name)
                os.makedirs(os.path.dirname(file_path), exist_ok=True)

                with open(file_path, "wb") as log_file:
                    for chunk in response.iter_content(chunk_size=8192):
                        log_file.write(chunk)

                results[log_type] = f"{
                    log_type.capitalize()} logs downloaded successfully: {file_name}"
                if log_type == "alarm":
                    clear_csv_logs(
                    ip_address, log_type)
                    results["data_processing"] = process_alarm_logs(
                        file_path, equipment_id)
                elif log_type == "data":
                    clear_csv_logs(
                    ip_address, log_type)
                    results["data_processing"] = process_data_logs(
                        file_path, equipment_id)
            else:

                results[log_type] = f"Failed to download {log_type} logs. Status code: {
                    response.status_code}"

        return results

    except Exception as e:

        return {"status": False, "message": f"Error: {e}"}


download_lock = threading.Lock()



def process_data_logs(file_path, equipment_id):
    
    with download_lock:
        try:
            with open(file_path, "r") as csv_file:
                csv_reader = csv.DictReader(csv_file)
                saved_records = 0

                for row in csv_reader:
                    try:
                        date = datetime.strptime(
                            row["DATE"].strip(), "%Y-%m-%d").date()
                        time_raw = row[" TIME"].strip()
                        if not time_raw:
                            continue
                        if len(time_raw) == 5:
                            time_raw = f"{time_raw}:00"
                        elif len(time_raw) > 8 and '.' in time_raw:
                            time_raw = time_raw[:8]

                       
                        datetime.strptime(time_raw, "%H:%M:%S")

                        def safe_float(value):
                            try:
                                return float(
                                    value.strip()) if value and value.strip() else None
                            except ValueError:
                                return None

                        record_data = {
                            "equip_name_id": equipment_id,
                            "date": date,
                            "time": time_raw,
                            "t_low_alarm": safe_float(row.get(" LOW_ALARM_LIMIT")),
                            "set_temp": safe_float(row.get(" SET_TEMP")),
                            "t_high_alarm": safe_float(row.get(" HIGH_ALARM_LIMIT")),
                            "tmp_1": safe_float(row.get(" TEMP_1")),
                            "tmp_2": safe_float(row.get(" TEMP_2")),
                            "tmp_3": safe_float(row.get(" TEMP_3")),
                            "tmp_4": safe_float(row.get(" TEMP_4")),
                            "tmp_5": safe_float(row.get("TEMP_5")),
                            "tmp_6": safe_float(row.get(" TEMP_6")),
                            "tmp_7": safe_float(row.get(" TEMP_7")),
                            "tmp_8": safe_float(row.get(" TEMP_8")),
                            "tmp_9": safe_float(row.get(" TEMP_9")),
                            "tmp_10": safe_float(row.get("  TEMP_10")),
                            "rh_low_alarm": safe_float(row.get(" RH_LOW_ALM_LIMIT")),
                            "rh_high_alarm": safe_float(row.get(" RH_HIGH_ALM_LIMIT")),
                            "set_rh": safe_float(row.get(" RH_SET")),
                            "rh_1": safe_float(row.get(" RH_1")),
                            "rh_2": safe_float(row.get(" RH_2")),
                            "rh_3": safe_float(row.get(" RH_3")),
                            "rh_4": safe_float(row.get(" RH_4")),
                            "rh_5": safe_float(row.get(" RH_5")),
                            "rh_6": safe_float(row.get(" RH_6")),
                            "rh_7": safe_float(row.get(" RH_7")),
                            "rh_8": safe_float(row.get(" RH_8")),
                            "rh_9": safe_float(row.get(" RH_9")),
                            "rh_10": safe_float(row.get(" RH_10")),
                        }

                        TemperatureHumidityRecord.objects.update_or_create(
                            **record_data)
                        saved_records += 1

                    except IntegrityError:
                        pass
                    except Exception:
                        pass

            return f"Data logs processed successfully. Total records saved: {saved_records}"

        except Exception:
            return f"Error processing Data Logs"

import serial
# def process_alarm_logs(file_path, equipment_id):
#     print("alarm logs")
#     with download_lock:
#         equipment = Equipment.objects.get(id=equipment_id)
#         try:
#             with open(file_path, "r") as csv_file:
#                 csv_reader = csv.DictReader(csv_file)
#                 saved_records = 0
#                 for row in csv_reader:
#                     try:
#                         date = datetime.strptime(
#                             row["DATE"].strip(), "%Y-%m-%d").date()
#                         time = datetime.strptime(
#                             row[" TIME"].strip(), "%H:%M:%S.%f").time()
#                         alarm_code = Alarm_codes.objects.get(
#                             code=row["ALARM_CODE"].strip())
#                         alarm_log, created = Alarm_logs.objects.update_or_create(
#                             equipment=equipment,
#                             alarm_code=alarm_code,
#                             date=date,
#                             time=time,
#                         )
#                         if created:
#                             saved_records += 1
#                             dept = Department.objects.get(
#                                 id=equipment.department.id)
#                             email_fields = [
#                                 dept.alert_email_address_1, dept.alert_email_address_2,
#                                 dept.alert_email_address_3, dept.alert_email_address_4,
#                                 dept.alert_email_address_5, dept.alert_email_address_6,
#                                 dept.alert_email_address_7, dept.alert_email_address_8,
#                                 dept.alert_email_address_9, dept.alert_email_address_10,
#                             ]
#                             email_list = [
#                                 email for email in email_fields if email]
#                             user_data = {}
#                             for i in range(1, 11):
#                                 username = getattr(dept, f'user{i}', None)
#                                 usernum = getattr(dept, f'user{i}_num', None)
#                                 if username is not None and usernum is not None:
#                                     user_data[username] = usernum
#                             code = alarm_code.code
#                             email_alert = emailalert.objects.get(
#                                 equipment_name=equipment_id)
#                             sms_alert = smsalert.objects.get(
#                                 equipment_name=equipment_id)
#                             ed = 0
#                             if dept.email_delay:
#                                 int(dept.email_delay)
#                                 ed = dept.email_delay
#                             if getattr(email_alert, f'code_{code}'):
#                                 thread_email = threading.Thread(
#                                     target=send_alert_email, args=(
#                                         alarm_log.id, email_list, ed))
#                                 thread_email.start()
#                                 thread_email.join()
#                             sd = 0
#                             if dept.sms_delay:
#                                 int(dept.sms_delay)
#                                 sd = dept.sms_delay
#                             if getattr(sms_alert, f'code_{code}'):

#                                 thread_sms = threading.Thread(
#                                             target=send_alert_messages, args=(
#                                                 user_data, alarm_log.id, sd))
#                                 thread_sms.start()
#                                 thread_sms.join()
                                
#                     except IntegrityError:
#                         pass
#                     except Exception:
#                         pass
#             return f"Alarm logs processed successfully. Total records saved: {saved_records}"

#         except Exception:
#             return f"Error processing Alarm Logs"


# def send_alert_messages(numbers_list, alarm_code, delay):
   
#     time.sleep(delay * 60)
#     alarm = Alarm_logs.objects.get(id=alarm_code)
#     equipment = alarm.equipment.id
#     alarm_id = alarm.id
#     app = AppSettings.objects.first()
#     equipment_id = alarm.equipment.equip_name
#     alarm_code = alarm.alarm_code.code
#     alarm_description = alarm.alarm_code.alarm_log
#     date_field = alarm.date
#     time_field = alarm.time
#     combined_datetime = datetime.combine(date_field, time_field)
#     formatted_datetime = combined_datetime.strftime('%Y-%m-%d %H:%M:%S')
#     eqp=Equipment.objects.get(id=equipment)

#     sms_settings = AppSettings.objects.first()
#     try:
#         threads = []
#         lock = threading.Lock()
#         combined_datetime = datetime.combine(alarm.date, alarm.time)
#         alarm_codes = [code for code in range(1001, 1031)]
#         message = ""
#         if alarm_code in alarm_codes:
#             ip_address = alarm.equipment.ip_address
#             plc = connect_to_plc(ip_address)
#             if plc.get_connected():
#                 data = read_plc_data(plc, 19, 8, 4)
#                 High_Temp = snap7.util.get_real(data, 0)
#                 data = read_plc_data(plc, 19, 4, 4)
#                 low_Temp = snap7.util.get_real(data, 0)
#                 data = read_plc_data(plc, 19, 0, 4)
#                 sv = snap7.util.get_real(data, 0)
#                 if alarm_code in [1001, 1021, 1011]:
#                     data = read_plc_data(plc, 4, 4, 4)
#                     pv = snap7.util.get_real(data, 0)
#                     message = f"""PV: {pv:.1f}
# SV:{sv}
# LL:{low_Temp}
# HL:{High_Temp}
# Equipment ID: {equipment_id}
# Alarm Description: {alarm_description}
# Date and Time: {formatted_datetime}"""
#                 elif alarm_code in [1002, 1012, 1022]:
#                     data = read_plc_data(plc, 4, 8, 4)
#                     pv = snap7.util.get_real(data, 0)
#                     message = f"""PV: {pv:.1f}
# SV:{sv}
# LL:{low_Temp}
# HL:{High_Temp}
# Equipment ID: {equipment_id}
# Alarm Description: {alarm_description}
# Date and Time: {formatted_datetime}
# """
#                 elif alarm_code in [1003, 1013, 1023]:
#                     data = read_plc_data(plc, 4, 12, 4)
#                     pv = snap7.util.get_real(data, 0)
#                     message = f"""PV: {pv:.1f}
# SV:{sv}
# LL:{low_Temp}
# HL:{High_Temp}
# Equipment ID: {equipment_id}
# Alarm Description: {alarm_description}
# Date and Time: {formatted_datetime}
# """
#                 elif alarm_code in [1004, 1014, 1024]:
#                     data = read_plc_data(plc, 4, 16, 4)
#                     pv = snap7.util.get_real(data, 0)
#                     message = f"""PV: {pv:.1f}
# SV:{sv}
# LL:{low_Temp}
# HL:{High_Temp}
# Equipment ID: {equipment_id}
# Alarm Description: {alarm_description}
# Date and Time: {formatted_datetime}
# """
#                 elif alarm_code in [1005, 1015, 1025]:
#                     data = read_plc_data(plc, 4, 20, 4)
#                     pv = snap7.util.get_real(data, 0)
#                     message = f"""PV: {pv:.1f}
# Sv:{sv}
# LL:{low_Temp}
# HL:{High_Temp}
# Equipment ID: {equipment_id}
# Alarm Description: {alarm_description}
# Date and Time: {formatted_datetime}
# """
#                 elif alarm_code in [1006, 1016, 1026]:
#                     data = read_plc_data(plc, 4, 24, 4)
#                     pv = snap7.util.get_real(data, 0)
#                     message = f"""
#                     PV: {pv:.1f}
# Sv:{sv}
# LL:{low_Temp}
# HL:{High_Temp}
# Equipment ID: {equipment_id}
# Alarm Description: {alarm_description}
# Date and Time: {formatted_datetime}
# """

#         elif alarm_code in [2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015]:
#             try:
#                 plc = PLCUser.objects.get(code=alarm_code)
#                 message = f"""Equipment ID: {equipment_id}
#                 Alarm Description: Door Accessed by User {plc.username}
#                 Date and Time: {formatted_datetime}"""
#             except PLCUser.DoesNotExist:
#                 message = f"Equipment ID: {equipment_id}\nAlarm Description: Unknown User\nDate and Time: {formatted_datetime}"

#         else:
#             message = f"""Equipment ID: {equipment_id}
# Alarm Description: {alarm_description}
# Date and Time: {formatted_datetime}"""

#         try:
#             print("trying to connect to modem")
#             with serial.Serial(
#                 port=sms_settings.comm_port,
#                 baudrate=sms_settings.baud_rate,

#                 bytesize=serial.EIGHTBITS,
#                 parity=serial.PARITY_NONE,
#                 stopbits=serial.STOPBITS_ONE,
#                 timeout=2
#             ) as ser:
#                 add_to_sms_queue(numbers_list, message, equipment, alarm_id, False)
#         except Exception as e:
#             print(str(e))
#             for i, j in numbers_list.items():
              
#                 Sms_logs.objects.create(
#                 time=datetime.now().time(),
#                 date=datetime.now().date(),
#                 sys_sms=False,
#                 to_num=j,
#                 user_name=i,
#                 msg_body=message,
#                 status="Failed",
#                 equipment=eqp,
#             )

#     except Exception as e:
#         pass

def process_alarm_logs(file_path, equipment_id):
    
    equipment = Equipment.objects.get(id=equipment_id)
    saved_records = 0

    try:
        with open(file_path, "r") as csv_file:
            csv_reader = csv.DictReader(csv_file)
           
            with ThreadPoolExecutor(max_workers=100) as executor:
                futures = [] 
                for row in csv_reader:
                    futures.append(executor.submit(process_row, row, equipment))
                for future in futures:
                    future.result()  
        
        return f"Alarm logs processed successfully. Total records saved: {saved_records}"

    except Exception as e:
        return f"Error processing Alarm Logs: {str(e)}"



def process_row(row, equipment):
    try:
        
        date = datetime.strptime(row["DATE"].strip(), "%Y-%m-%d").date()
        time = datetime.strptime(row[" TIME"].strip(), "%H:%M:%S.%f").time()
        alarm_code = Alarm_codes.objects.get(code=row["ALARM_CODE"].strip())

        dept=Department.objects.get(id=equipment.department.id)
        alarm_log, created = Alarm_logs.objects.update_or_create(
            equipment=equipment,
            alarm_code=alarm_code,
            date=date,
            time=time,
        )
        if created:
            alarm_log.save() 
            
            code=alarm_log.alarm_code.code
            email_fields = [
                dept.alert_email_address_1, dept.alert_email_address_2,
                dept.alert_email_address_3, dept.alert_email_address_4,
                dept.alert_email_address_5, dept.alert_email_address_6,
                dept.alert_email_address_7, dept.alert_email_address_8,
                dept.alert_email_address_9, dept.alert_email_address_10,
            ]
            email_list = [
            email for email in email_fields if email]
            email_alert = emailalert.objects.get(
                equipment_name=equipment.id)
            sms_alert = smsalert.objects.get(
                equipment_name=equipment.id)
            ed = 0
            if dept.email_delay:
                int(dept.email_delay)
                ed = dept.email_delay
            if getattr(email_alert, f'code_{code}'):
                thread_email = threading.Thread(
                    target=send_alert_email, args=(
                        alarm_log.id, email_list, ed))
                thread_email.start()
                thread_email.join()
            send_alert_messages(alarm_log)

    except Exception as e:
        pass



def send_alert_messages(alarm_log):
    code = alarm_log.alarm_code.code
    dept = Department.objects.get(id=alarm_log.equipment.department.id)
    sms_alert = smsalert.objects.get(equipment_name=alarm_log.equipment.id)

    
    if getattr(sms_alert, f'code_{code}'):

       
        user_data = {}
        for i in range(1, 11):
            username = getattr(dept, f'user{i}', None)
            usernum = getattr(dept, f'user{i}_num', None)
            if username is not None and usernum is not None:
                user_data[username] = usernum

        alarm_codes = [code for code in range(1001, 1031)]
        message = ""
        equipment_id = alarm_log.equipment.equip_name
        alarm_description = alarm_log.alarm_code.alarm_log
        date_field = alarm_log.date
        time_field = alarm_log.time
        combined_datetime = datetime.combine(date_field, time_field)
        formatted_datetime = combined_datetime.strftime('%Y-%m-%d %H:%M:%S')
        

        if code in alarm_codes:
            ip_address = alarm.equipment.ip_address
            plc = connect_to_plc(ip_address)
            if plc.get_connected():
                data = read_plc_data(plc, 19, 8, 4)
                High_Temp = snap7.util.get_real(data, 0)
                data = read_plc_data(plc, 19, 4, 4)
                low_Temp = snap7.util.get_real(data, 0)
                data = read_plc_data(plc, 19, 0, 4)
                sv = snap7.util.get_real(data, 0)
                if code in [1001, 1021, 1011]:
                    data = read_plc_data(plc, 4, 4, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}"""
                elif code in [1002, 1012, 1022]:
                    data = read_plc_data(plc, 4, 8, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
"""
                elif code in [1003, 1013, 1023]:
                    data = read_plc_data(plc, 4, 12, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
"""
                elif code in [1004, 1014, 1024]:
                    data = read_plc_data(plc, 4, 16, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
"""
                elif code in [1005, 1015, 1025]:
                    data = read_plc_data(plc, 4, 20, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""PV: {pv:.1f}
Sv:{sv}
LL:{low_Temp}
HL:{High_Temp}
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
"""
                elif alarm_code in [1006, 1016, 1026]:
                    data = read_plc_data(plc, 4, 24, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""
                    PV: {pv:.1f}
Sv:{sv}
LL:{low_Temp}
HL:{High_Temp}
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
"""

        elif code in [2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015]:
            try:
                plc = PLCUser.objects.get(code=alarm_code)
                message = f"""Equipment ID: {equipment_id}
                Alarm Description: Door Accessed by User {plc.username}
                Date and Time: {formatted_datetime}"""
            except PLCUser.DoesNotExist:
                message = f"Equipment ID: {equipment_id}\nAlarm Description: Unknown User\nDate and Time: {formatted_datetime}"

        else:
            message = f"""Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}"""

        eqp=alarm_log.equipment.id
        delay = dept.sms_delay or 0
        time.sleep(delay * 60)  

       
        try:
           
            add_to_sms_queue(user_data, message, alarm_log.equipment.id, alarm_log.id, False)

        except Exception as e:
            log_sms_failure(user_data, message, alarm_log.equipment, alarm_log.id)
        






def log_sms_failure(user_data, message, equipment, alarm_id):
    for username, user_number in user_data.items():
        Sms_logs.objects.create(
            time=datetime.now().time(),
            date=datetime.now().date(),
            sys_sms=False,
            to_num=user_number,
            msg_body=message,
            status="Failed",
            equipment=equipment,
        )




def send_alert_email(alarm_id, email_list, delay_minutes):
    em_dly = delay_minutes

    
    try:
            
        delay=int(delay_minutes)
        time.sleep(delay * 60)
        alarm = Alarm_logs.objects.get(id=alarm_id)
        email_settings = get_email_settings(request)
        subject = 'Sun Well Alarm Alerts'
        equipment_id = alarm.equipment.equip_name
        alarm_code = alarm.alarm_code.code
        alarm_description = alarm.alarm_code.alarm_log
        date_field = alarm.date
        time_field = alarm.time
        combined_datetime = datetime.combine(date_field, time_field)
        formatted_datetime = combined_datetime.strftime('%Y-%m-%d %H:%M:%S')

        settings.EMAIL_HOST = email_settings['EMAIL_HOST']
        settings.EMAIL_HOST_USER = email_settings['EMAIL_HOST_USER']
        settings.EMAIL_HOST_PASSWORD = email_settings['EMAIL_HOST_PASSWORD']
        settings.EMAIL_PORT = email_settings['EMAIL_PORT']

        alarm_codes = [code for code in range(1001, 1031)]
        message = ""

        if alarm_code in alarm_codes:
            ip_address = alarm.equipment.ip_address
            plc = connect_to_plc(ip_address)
            if plc.get_connected():
                data = read_plc_data(plc, 19, 8, 4)
                High_Temp = snap7.util.get_real(data, 0)
                data = read_plc_data(plc, 19, 4, 4)
                low_Temp = snap7.util.get_real(data, 0)
                data = read_plc_data(plc, 19, 0, 4)
                sv = snap7.util.get_real(data, 0)
                if alarm_code in [1001, 1021, 1011]:
                    data = read_plc_data(plc, 4, 4, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}"""
                elif alarm_code in [1002, 1012, 1022]:
                    data = read_plc_data(plc, 4, 8, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}"""
                elif alarm_code in [1003, 1013, 1023]:
                    data = read_plc_data(plc, 4, 12, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}"""
                elif alarm_code in [1004, 1014, 1024]:
                    data = read_plc_data(plc, 4, 16, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
PV: {pv:.1f}
SV:{sv}
LL:{low_Temp}
HL:{High_Temp}"""
                elif alarm_code in [1005, 1015, 1025]:
                    data = read_plc_data(plc, 4, 20, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
PV: {pv:.1f}
Sv:{sv}
LL:{low_Temp}
HL:{High_Temp}"""
                elif alarm_code in [1006, 1016, 1026]:
                    data = read_plc_data(plc, 4, 24, 4)
                    pv = snap7.util.get_real(data, 0)
                    message = f"""
Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}
PV: {pv:.1f}
Sv:{sv}
LL:{low_Temp}
HL:{High_Temp}"""

        elif alarm_code in [2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, 2011, 2012, 2013, 2014, 2015]:
            try:
                plc = PLCUser.objects.get(code=alarm_code)
                message = f"""Equipment ID: {equipment_id}
                Alarm Description: Door Accessed by User {plc.username}
                Date and Time: {formatted_datetime}"""
            except PLCUser.DoesNotExist:
                message = f"Equipment ID: {equipment_id}\nAlarm Description: Unknown User\nDate and Time: {formatted_datetime}"

        else:
            message = f"""Equipment ID: {equipment_id}
Alarm Description: {alarm_description}
Date and Time: {formatted_datetime}"""

        try:
            
            send_mail(
                subject=subject,
                message=message,
                from_email=email_settings['EMAIL_HOST_USER'],
                recipient_list=email_list,
                fail_silently=False,
            )
            
            for recipient in email_list:
                Email_logs.objects.create(
                    equipment=alarm.equipment,
                    sys_mail=False,
                    to_email=recipient,
                    date=datetime.now().date(),
                    time=datetime.now().time(),
                    email_sub=subject,
                    email_body=message,
                    status="Sent"
                )
        except Exception as e:
            for recipient in email_list:
                Email_logs.objects.create(
                    equipment=alarm.equipment,
                    sys_mail=False,
                    to_email=recipient,
                    date=datetime.now().date(),
                    time=datetime.now().time(),
                    email_sub=subject,
                    email_body=message,
                    status="Failed"
                )

    except Exception as e:
        pass


def stop_background_thread():
    stop_event.set()


atexit.register(stop_background_thread)


def clear_csv_logs(ip_address, log_type):
    

    try:

        plc = snap7.client.Client()
        plc.connect(ip_address, 0, 1)

        MK_AREA = type.Areas.MK
        memory_addresses = {
            "alarm": 457 * 8 + 4,
            "data": 457 * 8 + 5,
        }

        if log_type not in memory_addresses:
            raise ValueError(
                f"Invalid log type: {log_type}. Must be 'alarm' or 'data'.")
        memory_address = memory_addresses[log_type]
        byte_index = memory_address // 8
        bit_index = memory_address % 8

        data = bytearray(1)
        snap7.util.set_bool(data, 0, bit_index, True)
        plc.write_area(MK_AREA, 0, byte_index, data)

        return f"{log_type.capitalize()} logs cleared successfully."
    except AttributeError as attr_err:

        return f"Attribute error: {attr_err}"
    except Exception as e:

        return f"Error clearing {log_type} logs: {e}"
    finally:
        if plc.get_connected():
            plc.disconnect()


def read_plc_data(plc, db_number, start_address, size):
    return plc.db_read(db_number, start_address, size)


def equipment_configure_view(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    Eqp = Equipment.objects.count()

    if request.method == 'POST':
        nod = organization.get_nod()

        if Eqp >= nod:

            messages.error(
                request,
                "Number of Equipments exceeded for Comm Group Activation key!")
            return redirect('equipment_configure')
        equip_name = request.POST.get('equipname')
        status = request.POST.get('equipStatus')
        ip_address = request.POST.get('ipaddress')
        interval = request.POST.get('interval')
        equipment_type = request.POST.get('equiptype')
        door_access_type = request.POST.get('dooracctype')
        department = request.POST.get('hiddenFieldName')
        sensor = request.POST.get('sensor')
        dept = Department.objects.get(id=department)
        equipment = Equipment(
            equip_name=equip_name,
            status=status,
            ip_address=ip_address,
            interval=interval,
            department=dept,
            equipment_type=equipment_type,
            door_access_type=door_access_type,
            total_temp_sensors=sensor

        )
        equipment.save()
        emailalert.objects.create(
            equipment_name=equipment
        )
        smsalert.objects.create(
            equipment_name=equipment
        )
        if "Humidity" in equipment_type:
            equipment.total_humidity_sensors = sensor
        else:
            equipment.total_humidity_sensors = 0
        if door_access_type == 'plc':
            code = 2001

            for i in range(1, 16):
                user = request.POST.get(f'plc_user_{i}')
                if user:
                    plc_user = PLCUser(
                        equipment=equipment, username=user, code=code)
                    plc_user.save()

                code += 1

        # Handle Biometric users if Biometric is selected
        if door_access_type == 'biometric':
            biometric_banner_text = request.POST.get('biometric_banner_text')
            biometric_ip_address = request.POST.get('biometric_ip_address')

            # Update the equipment fields for biometric
            equipment.biometric_banner_text = biometric_banner_text
            equipment.biometric_ip_address = biometric_ip_address
            equipment.save()

            for i in range(1, 16):
                user = request.POST.get(f'biometric_user_{i}')
                card = request.POST.get(f'biometric_card_{i}')
                if user and card:
                    biometric_user = BiometricUser(
                        equipment=equipment, username=user, card_number=card)
                    biometric_user.save()

        # Log the equipment addition
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new equipment {equip_name}"
        )

        try:

            plc = connect_to_plc(ip_address)
            if plc.get_connected():
                data = read_plc_data(plc, 19, 8, 4)
                High_Temp = snap7.util.get_real(data, 0)
                data1 = read_plc_data(plc, 19, 4, 4)
                low_Temp = snap7.util.get_real(data1, 0)
                data2 = read_plc_data(plc, 19, 0, 4)
                sv = snap7.util.get_real(data2, 0)
                data3 = read_plc_data(plc, 19, 64, 3)
                cooling = snap7.util.get_bool(data3, 0, 0)

                # Setting values
                equipment.set_value = sv
                equipment.low_alarm = low_Temp
                equipment.high_alarm = High_Temp
                equipment.cooling = cooling
                equipment.save()
                if "Humidity" in equipment_type:

                    data2 = read_plc_data(plc, 19, 772, 4)
                    sv = snap7.util.get_real(data2, 0)
                    data = read_plc_data(plc, 19, 776, 4)
                    low = snap7.util.get_real(data, 0)
                    data1 = read_plc_data(plc, 19, 780, 4)
                    high = snap7.util.get_real(data1, 0)
                    equipment.high_alarm_hum=high
                    equipment.low_alarm_hum=low
                    equipment.set_value_hum=sv
                    equipment.save()

                # This should call the function now
                write_interval_to_plc(plc, interval)
                messages.success(
                    request, f"Interval {interval} updated on PLC and saved!")
            else:

                messages.error(request, 'Failed to connect to PLC.')

        except Exception as e:

            messages.error(request, f"Error during PLC connection: {str(e)}")

        messages.success(request, 'Equipment saved successfully!')
        return redirect('equipment_configure')

    status_filter = request.GET.get("status", "Active")
    status_filter = str(status_filter).lower()
    department_filter = request.GET.get('department', 'all')

    # Convert "all" to "All Status" for display
    if status_filter == "all":
        status_filter = "All Status"

    # Filter users based on status and department
    equipment_list = Equipment.objects.all()
    if status_filter != "All Status":
        equipment_list = equipment_list.filter(status=status_filter)

    if department_filter != "all":
        equipment_list = equipment_list.filter(department_id=department_filter)

    plc_users_json = serialize('json', PLCUser.objects.all())
    biometric_users_json = serialize('json', BiometricUser.objects.all())

    for equipment in equipment_list:
        equipment.plc_users_json = serialize(
            'json', equipment.plc_users.all(), fields=('username'))
        equipment.biometric_users_json = serialize(
            'json', equipment.biometric_users.all(), fields=(
                'username', 'card_number'))

    context = {
        "equipment_list": equipment_list,
        "status_filter": status_filter,  # Pass the selected filter
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'plc_users': plc_users_json,
        'biometric_users': biometric_users_json,
        'acc_dept': acc_dept
    }
    return render(request, 'Equip_Settings/equip_config.html', context)


def equipment_edit(request, equipment_id):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    equipment = get_object_or_404(Equipment, id=equipment_id)

    if request.method == 'POST':
        # Update Equipment Details
        equipment.equip_name = request.POST.get('edit_equipname')
        equipment.ip_address = request.POST.get('edit_ipaddress')
        equipment.interval = int(request.POST.get('edit_interval'))
        equipment.equipment_type = request.POST.get('edit_equiptype')
        equipment.status = request.POST.get('edit_equipStatus')
        equipment.door_access_type = request.POST.get('edit_doorAccessType')

        equipment.save()

        # Handle PLC Users (Update existing or create new)
        if equipment.door_access_type == 'plc':

            try:
                biometric = BiometricUser.objects.filter(
                    equipment=equipment_id)
                if biometric.exists():
                    biometric.delete()  # Delete all matching objects in one query
                else:
                    pass
            except Exception as e:
                pass

            existing_plc_users = {
                user.username: user for user in PLCUser.objects.filter(
                    equipment=equipment)}
            form_usernames = set()  # Track new users

            code = 2001
            for i in range(1, 16):
                username = request.POST.get(
                    f'plc_user_username_{i}')  # Fix field name match
                if username and username.strip():  # Ensure it's not empty
                    form_usernames.add(username)
                    if username in existing_plc_users:
                        plc_user = existing_plc_users[username]
                        plc_user.save()
                    else:
                        PLCUser.objects.create(
                            equipment=equipment, username=username, code=code)

                    code += 1

            # Remove PLC Users that are no longer in the form
            for user in existing_plc_users.values():
                if user.username not in form_usernames:
                    user.delete()

        # Handle Biometric Users (Update existing or create new)
        elif equipment.door_access_type == 'biometric':

            try:
                plc = PLCUser.objects.filter(equipment=equipment_id)
                if plc.exists():
                    plc.delete()  # Delete all matching objects in one query
                else:
                    pass
            except Exception as e:
                pass
            biometric_banner_text = request.POST.get('biometric_banner_text')
            biometric_ip_address = request.POST.get('biometric_ip_address')

            equipment.biometric_banner_text = biometric_banner_text
            equipment.biometric_ip_address = biometric_ip_address
            equipment.save()

            existing_biometric_users = {
                (
                    user.username,
                    user.card_number): user for user in BiometricUser.objects.filter(
                    equipment=equipment)}
            form_users = set()

            for i in range(1, 16):
                username = request.POST.get(
                    f'biometric_user_username_{i}')  # Updated name
                card_number = request.POST.get(
                    f'biometric_user_card_number_{i}')  # Updated name

                if username and card_number and username.strip() and card_number.strip():
                    form_users.add((username, card_number))
                    if (username, card_number) in existing_biometric_users:
                        biometric_user = existing_biometric_users[(
                            username, card_number)]
                        biometric_user.save()
                    else:
                        BiometricUser.objects.create(
                            equipment=equipment, username=username, card_number=card_number)

            # Remove Biometric Users that are no longer in the form
            for user in existing_biometric_users.values():
                if (user.username, user.card_number) not in form_users:
                    user.delete()

        # Log the update activity
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Edited equipment {equipment.equip_name}"
        )

        messages.success(request, 'Equipment edited successfully!')
        return redirect('equipment_configure')
    context = {
        "equipment_list": equipment,
  # Pass the selected filter
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'acc_dept': acc_dept
    }
    return render(request, 'Equip_Settings/equip_config.html', context)


def equipment_setting(request, id):

    emp_user = request.session.get('username', None)
    equipmentwrite = None
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        try:
            today = timezone.localdate()

            one_day_ago = today - timedelta(days=1)

            equipmentwrite = Equipmentwrite.objects.filter(
                equipment=id, date__gte=one_day_ago)

            # equipment_parameters = EquipParameter.objects.get(equipment=id)

        except Equipmentwrite.DoesNotExist:

            equipmentwrite = None
            email = None
            sms = None
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        try:
            today = timezone.localdate()

            one_day_ago = today - timedelta(days=1)

            eq = Equipmentwrite.objects.first()

            equipmentwrite = Equipmentwrite.objects.filter(equipment=id)

            # equipment_parameters = EquipParameter.objects.get(equipment=id)

        except Equipmentwrite.DoesNotExist:

            equipmentwrite = None
            email = None
            sms = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
        equipment = Equipment.objects.get(id=id)
    except:
        acc_db = None
    equipment = Equipment.objects.get(id=id)
    logs = Alarm_codes.objects.all()
    l = logs.count()
    alert_instance = emailalert.objects.get(equipment_name=id)
    try:
        # equipmentwrite = Equipmentwrite.objects.filter(equipment=id)
        equipment_parameters = EquipParameter.objects.get(equipment=id)

    except Equipmentwrite.DoesNotExist:

        equipmentwrite = None
        email = None
        sms = None

    except EquipParameter.DoesNotExist:

        equipment_parameters = None

    else:
        pass

    temperature_settings = []
    for i in range(1, equipment.total_temp_sensors + 1):
        color_attr = f"t{i}color"
        color_value = getattr(equipment_parameters, color_attr, None)
        temperature_settings.append({
            'index': i,
            'color': color_value
        })
    humidity_settings = []
    if equipment.total_humidity_sensors > 0:
        for i in range(1, equipment.total_humidity_sensors + 1):
            color_attr = f"rh{i}color"
            color_value = getattr(equipment_parameters, color_attr, None)
            humidity_settings.append({
                'index': i,
                'color': color_value
            })
    if alert_instance:
        fields = [
            {
                'name': field.name,
                'help_text': field.help_text,
                'value': getattr(alert_instance, field.name),
                'type': field.get_internal_type(),
            }
            for field in emailalert._meta.get_fields()
            if field.get_internal_type() == 'BooleanField'
        ]
    else:
        fields = []
    sms_alert = smsalert.objects.get(equipment_name=id)
    if sms_alert:
        sms_fields = [
            {
                'name': field.name,
                'help_text': field.help_text,
                'value': getattr(sms_alert, field.name),
                'type': field.get_internal_type(),
            }
            for field in emailalert._meta.get_fields()
            if field.get_internal_type() == 'BooleanField'
        ]
    else:
        sms_fields = []
    return render(request, 'Equip_Settings/equip_settings.html', {'organization': organization, 'data': data, 'acc_db': acc_db, 'equipment': equipment, 'logs': logs, 'equipmentwrite': equipmentwrite, 'equipmentparameters': equipment_parameters,
                                                                  'temperature_settings': temperature_settings, 'humidity_settings': humidity_settings,
                                                                  'show_humidity': equipment.total_humidity_sensors > 0, 'fields': fields, 'sms_fields': sms_fields,
                                                                  'acc_dept':acc_dept

                                                                  })


@csrf_exempt
def save_alert_settings1(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email_alerts = data.get('emailData', {}).get('email', [])
        sms_alerts = data.get('smsData', {}).get('sms', [])
        ip_address = data.get('ip_address', {}).get('ip_address', '')

        equipment = Equipment.objects.get(ip_address=ip_address)
        email = emailalert.objects.get(equipment_name=equipment.id)

        for i in email_alerts:
            if hasattr(email, i):
                setattr(email, i, True)
        email.save()
        sms = smsalert.objects.get(equipment_name=equipment.id)
        for i in sms_alerts:
            if hasattr(sms, i):
                setattr(sms, i, True)
        sms.save()

        return JsonResponse(
            {"status": "success", "message": "Alert settings saved successfully."})
    return JsonResponse(
        {"status": "error", "message": "Invalid request"}, status=400)
# DATA Analysis


def view_log(request):
    emp_user = request.session.get('username', None)
    department = ""
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None
    organization = Organization.objects.first()
    equipment_list = Equipment.objects.all()

    # Get filter parameters from the request
    current_date = now()
    selected_equipment = request.GET.get('equipment')
    from_date = request.GET.get('from-date')
    to_date = request.GET.get('to-date')
    # Default to '00:00' if empty
    from_time = request.GET.get('from-time') or '00:00'
    # Default to '23:59' if empty
    to_time = request.GET.get('to-time') or '23:59'

    filter_kwargs = Q()

    # Filter by equipment if selected
    if selected_equipment:
        filter_kwargs &= Q(equip_name__equip_name=selected_equipment)

    from_date_parsed = parse_date(
        from_date) if from_date else current_date.replace(day=1).date()
    to_date_parsed = parse_date(to_date) if to_date else current_date.date()
    from_time_parsed = parse_time(
        from_time) if from_time else datetime_time(0, 0, 0)
    to_time_parsed = parse_time(
        to_time) if to_time else datetime_time(23, 59, 59)

    if from_date_parsed == to_date_parsed:
        filter_kwargs &= (
            Q(date=from_date_parsed) &
            Q(time__gte=from_time_parsed) &
            Q(time__lte=to_time_parsed)
        )
    else:
        filter_kwargs &= (
            (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
            (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
            Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
        )

    # Fetch the filtered temperature and humidity records
    data_logs = TemperatureHumidityRecord.objects.filter(
        filter_kwargs).order_by('date', 'time')
    eqp_list = Equipment.objects.filter(status='Active')

    # Handle PDF generation if requested
    if 'generate_pdf' in request.GET:
        # Determine the number of temperature and humidity columns
        equipment_records = TemperatureHumidityRecord.objects.filter(
            equip_name__equip_name=selected_equipment)
        temperature_channels = [
            'tmp_1',
            'tmp_2',
            'tmp_3',
            'tmp_4',
            'tmp_5',
            'tmp_6',
            'tmp_7',
            'tmp_8',
            'tmp_9',
            'tmp_10']
        humidity_channels = [
            'rh_1',
            'rh_2',
            'rh_3',
            'rh_4',
            'rh_5',
            'rh_6',
            'rh_7',
            'rh_8',
            'rh_9',
            'rh_10']

        equipment = Equipment.objects.get(equip_name=selected_equipment)
        total_temp_sensors = int(
            equipment.total_temp_sensors) if equipment.total_temp_sensors else 0
        total_humidity_sensors = int(
            equipment.total_humidity_sensors) if equipment.total_humidity_sensors else 0
        active_temperature_channels = temperature_channels[:total_temp_sensors]
        active_humidity_channels = humidity_channels[:total_humidity_sensors]

        # Check if both temperature and humidity columns exceed 5
        if len(active_temperature_channels) > 5 and len(
                active_humidity_channels) > 5:
            # Call the landscape mode PDF generator if both exceed 5
            return generate_log_pdf_landscape(
                request,
                data_logs,
                from_date_parsed.strftime('%d-%m-%Y'),
                to_date_parsed.strftime('%d-%m-%Y'),
                from_time_parsed.strftime('%H:%M'),
                to_time_parsed.strftime('%H:%M'),
                organization,
                department,
                data.username,
                selected_equipment
            )
        else:
            # Call the normal PDF generator
            return generate_log_pdf(
                request,
                data_logs,
                from_date_parsed.strftime('%d-%m-%Y'),
                to_date_parsed.strftime('%d-%m-%Y'),
                from_time_parsed.strftime('%H:%M'),
                to_time_parsed.strftime('%H:%M'),
                organization,
                department,
                data.username,
                selected_equipment
            )

    # Render the logs to the HTML template if no PDF generation is requested
    return render(request, 'Data_Analysis/view_logs.html', {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'data_logs': data_logs,
        'equipment_list': equipment_list,
        'eqp_list': eqp_list,
        'acc_dept':acc_dept
    })


def generate_log_pdf(request, records, from_date, to_date, from_time,
                     to_time, organization, department, username, selected_equipment):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="Data_log_report.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=160,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    # Determine "Records From" and "Records To"
    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record.date.strftime('%d-%m-%Y')
        records_from_time = first_record.time.strftime('%H:%M')
        records_to_date = last_record.date.strftime('%d-%m-%Y')
        records_to_time = last_record.time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(570, 35, page_text)

    def create_page(canvas, doc):

        page_num = canvas.getPageNumber()
        total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')

        # Set the title and logo
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization and organization.name else " "
        canvas.drawString(30, 800, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 780, department_name)

        logo_path = organization.logo.path if organization else " "
        if logo_path.strip():  # Check if the path is not empty or just whitespace
            canvas.drawImage(logo_path, 470, 780, width=80, height=30)

        # Draw the separator line under the header
        canvas.setLineWidth(0.5)
        canvas.line(30, 770, 570, 770)

        # Add the filters and records info
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(250, 750, "Data Log Report")

        canvas.setFont("Helvetica-Bold", 10)
        equipment_display = f"Equipment Name: {selected_equipment}" if selected_equipment else "Equipment Name: Unknown"
        canvas.drawString(30, 730, equipment_display)

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(30, 730, f"Equipment Name: {selected_equipment}")
        canvas.drawString(30, 710, f"Filter From: {from_date} {from_time}")
        canvas.drawString(400, 710, f"Filter To: {to_date} {to_time}")
        canvas.drawString(
            30, 690, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            400, 690, f"Records To: {records_to_date} {records_to_time}")

        # Draw separator line above the new table
        canvas.setLineWidth(0.5)
        canvas.line(30, 670, 570, 670)  # Line above the new table

        # Add a line above the footer
        canvas.setLineWidth(1)
        canvas.line(30, 60, 570, 60)  # Line just above the footer

        # Add footer with page number
        footer_left_top = "Sunwell"
        footer_left_bottom = "ESTDAS v1.0"
        footer_center = f"Printed By - {username} on {current_time}"
        footer_right_top = department.footer_note if department else " "
        # footer_right_bottom = f"Page {page_num} of {total_pages}"

        # Draw footer at the bottom of the page
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_left_top)
        canvas.drawString(30, 35, footer_left_bottom)
        canvas.drawCentredString(300, 40, footer_center)
        canvas.drawRightString(570, 45, footer_right_top)
        # canvas.drawRightString(570, 35, footer_right_bottom)

    def add_alarm_tables():
        equipment = TemperatureHumidityRecord.objects.filter(
            equip_name__equip_name=selected_equipment).first()
        
        eqp = Equipment.objects.filter(
            equip_name=selected_equipment).first()

        # Collect distinct values for alarm and alert thresholds from the records
        t_low_alarm_values = set(record.t_low_alarm for record in records if record.t_low_alarm is not None)
        t_high_alarm_values = set(record.t_high_alarm for record in records if record.t_high_alarm is not None)
        t_low_alert_values = set(record.t_low_alert for record in records if record.t_low_alert is not None)
        t_high_alert_values = set(record.t_high_alert for record in records if record.t_high_alert is not None)
        
        rh_low_alarm_values = set(record.rh_low_alarm for record in records if record.rh_low_alarm is not None)
        rh_high_alarm_values = set(record.rh_high_alarm for record in records if record.rh_high_alarm is not None)
        rh_low_alert_values = set(record.rh_low_alert for record in records if record.rh_low_alert is not None)
        rh_high_alert_values = set(record.rh_high_alert for record in records if record.rh_high_alert is not None)


        # Decide whether to use values from the records or the equipment's live data
        if len(t_low_alarm_values) > 1:
            t_low_alarm = eqp.low_alarm
        else:
            t_low_alarm = next(iter(t_low_alarm_values), None)  

        if len(t_high_alarm_values) > 1:
            t_high_alarm = eqp.high_alarm
        else:
            t_high_alarm = next(iter(t_high_alarm_values), None)

        if len(t_low_alert_values) > 1:
            t_low_alert = eqp.low_alert
        else:
            t_low_alert = next(iter(t_low_alert_values), None)

        if len(t_high_alert_values) > 1:
            t_high_alert = eqp.high_alert
            
        else:
            t_high_alert = next(iter(t_high_alert_values), None)

        if len(rh_low_alarm_values) > 1:
            rh_low_alarm = eqp.low_alarm_hum
        else:
            rh_low_alarm = next(iter(rh_low_alarm_values), None)

        if len(rh_high_alarm_values) > 1:
            rh_high_alarm = eqp.high_alarm_hum
        else:
            rh_high_alarm = next(iter(rh_high_alarm_values), None)

        if len(rh_low_alert_values) > 1:
            rh_low_alert = eqp.low_alert_hum
        else:
            rh_low_alert = next(iter(rh_low_alert_values), None)

        if len(rh_high_alert_values) > 1:
            rh_high_alert = eqp.high_alert_hum
        else:
            rh_high_alert = next(iter(rh_high_alert_values), None)
        
        
        # Data for Temperature and Humidity Alarms
        alarm_data = []

        # Check if alert data exists for temperature
        if equipment and (
                t_low_alarm is not None or t_high_alarm is not None or t_low_alert is not None or t_high_alert is not None):
            # Add the header row conditionally based on alerts
            if t_low_alert is not None or t_high_alert is not None:
                alarm_data.append(
                    ['Parameter', 'Low Alarm', 'Low Alert', 'High Alarm', 'High Alert'])
                temperature_row = [
                    'Temperature (°C)',
                    f"{t_low_alarm:.1f}" if t_low_alarm is not None else '',
                    f"{t_low_alert:.1f}" if t_low_alert is not None else '',
                    f"{t_high_alarm:.1f}" if t_high_alarm is not None else '',
                    f"{t_high_alert:.1f}" if t_high_alert is not None else ''
                ]
            else:
                alarm_data.append(['Parameter', 'Low Alarm', 'High Alarm'])
                temperature_row = [
                    'Temperature (°C)',
                    f"{t_low_alarm:.1f}" if t_low_alarm is not None else '',
                    f"{t_high_alarm:.1f}" if t_high_alarm is not None else '',
                ]

            # Remove alert columns if not available (only remove alerts, not
            # high alarm)
            if t_low_alert is None or t_high_alert is None:
                # Remove alert columns but keep high alarm
                temperature_row = temperature_row[:3]

            alarm_data.append(temperature_row)

        # Check if alert data exists for humidity
        if equipment and (
                rh_low_alarm is not None or rh_high_alarm is not None or rh_low_alert is not None or rh_high_alert is not None):
            # Add humidity alarm data
            if rh_low_alert is not None or rh_high_alert is not None:
                humidity_row = [
                    'Humidity (% RH)',
                    f"{rh_low_alarm:.1f}" if rh_low_alarm is not None else '',
                    f"{rh_low_alert:.1f}" if rh_low_alert is not None else '',
                    f"{rh_high_alarm:.1f}" if rh_high_alarm is not None else '',
                    f"{rh_high_alert:.1f}" if rh_high_alert is not None else ''
                ]
            else:
                humidity_row = [
                    'Humidity (% RH)',
                    f"{rh_low_alarm:.1f}" if rh_low_alarm is not None else '',
                    f"{rh_high_alarm:.1f}" if rh_high_alarm is not None else '',

                ]

            # Remove alert columns if not available (only remove alerts, not
            # high alarm)
            if rh_low_alert is None or rh_high_alert is None:
                # Remove alert columns but keep high alarm
                humidity_row = humidity_row[:3]

            alarm_data.append(humidity_row)

        base_col_widths = [130, 80, 80, 80, 80]

        if not alarm_data:

            alarm_data.append(['Parameter', 'Low Alarm', 'High Alarm'])

        if len(alarm_data[0]) == 3:
            col_widths = [150, 150, 150]
        else:
            col_widths = base_col_widths

        # Define table style
        alarm_table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Create the alarm table
        alarm_table = Table(alarm_data, colWidths=col_widths)
        alarm_table.setStyle(alarm_table_style)

        return alarm_table

    
    def add_temperature_table(selected_equipment):
        # Initialize lists for temperature and humidity data
        selected_equipment = Equipment.objects.get(
            equip_name=selected_equipment)
        total_temp_sensors = int(
            selected_equipment.total_temp_sensors) if selected_equipment.total_temp_sensors else 0
        total_humidity_sensors = int(
            selected_equipment.total_humidity_sensors) if selected_equipment.total_humidity_sensors else 0

        temperature_channels = [
            f'tmp_{i + 1}' for i in range(total_temp_sensors)]
        humidity_channels = [
            f'rh_{i + 1}' for i in range(total_humidity_sensors)]

        temp_data = [['Temperature (°C)', 'Minimum', 'Maximum', 'Average']]
        humidity_data = [['Humidity (% RH)', 'Minimum', 'Maximum', 'Average']]

        # Dynamically calculate min, max, and average for temperature channels
        i = 1
        for channel in temperature_channels:
            channel_values = [
                getattr(
                    record,
                    channel) for record in records if getattr(
                    record,
                    channel) is not None]

            if channel_values:

                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                temp_data.append(
                    ['T' + str(i), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])
            i = i + 1
        # Calculate min, max, and average for each humidity channel in the
        # filtered records
        j = 1
        for channel in humidity_channels:
            channel_values = [
                getattr(
                    record,
                    channel) for record in records if getattr(
                    record,
                    channel) is not None]
            if channel_values:
                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                humidity_data.append(
                    ['RH' + str(j), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])
            j = j + 1

        # Define table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Define column widths
        col_widths = [150, 100, 100, 100]  # Adjust column widths as needed

        # Create the temperature table
        temp_table = Table(temp_data, colWidths=col_widths)
        temp_table.setStyle(table_style)
        humidity_table = None
        if len(humidity_data) > 1:
            # Create the humidity table
            humidity_table = Table(humidity_data, colWidths=col_widths)
            humidity_table.setStyle(table_style)

        return [temp_table, Spacer(
            1, 0.2 * inch), humidity_table] if humidity_table else [temp_table]

    from reportlab.lib import colors
    from reportlab.platypus import Paragraph
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_RIGHT

    def add_main_table(selected_equipment):
        # Define styles for normal and bold text
        normal_style = ParagraphStyle(
            'Normal',
            fontName='Helvetica',
            fontSize=9,
            alignment=TA_RIGHT)
        bold_style = ParagraphStyle(
            'Bold',
            fontName='Helvetica-Bold',
            fontSize=9,
            alignment=TA_RIGHT)
        equipment = Equipment.objects.get(equip_name=selected_equipment)
        temperature_channels = [
            'tmp_1',
            'tmp_2',
            'tmp_3',
            'tmp_4',
            'tmp_5',
            'tmp_6',
            'tmp_7',
            'tmp_8',
            'tmp_9',
            'tmp_10']
        humidity_channels = [
            'rh_1',
            'rh_2',
            'rh_3',
            'rh_4',
            'rh_5',
            'rh_6',
            'rh_7',
            'rh_8',
            'rh_9',
            'rh_10']

        total_temp_sensors = int(
            equipment.total_temp_sensors) if equipment.total_temp_sensors else 0
        total_humidity_sensors = int(
            equipment.total_humidity_sensors) if equipment.total_humidity_sensors else 0

        active_temperature_channels = temperature_channels[:total_temp_sensors]
        active_humidity_channels = humidity_channels[:total_humidity_sensors]

        if total_temp_sensors == 0 and total_humidity_sensors == 0:  # No sensors at all
            temperature_header = [''] * 10
            humidity_header = []

        elif total_humidity_sensors == 0:  # Only temperature sensors exist
            temperature_header = ['T' + str(i + 1)
                                  for i in range(total_temp_sensors)]
            # Fill remaining slots with empty strings
            temperature_header += [''] * (10 - total_temp_sensors)
            humidity_header = []  # No humidity sensors

        else:  # Both temperature and humidity sensors exist
            temperature_header = ['T' + str(i + 1)
                                  for i in range(total_temp_sensors)]
            # Fill remaining slots with empty strings
            temperature_header += [''] * (5 - total_temp_sensors)

            humidity_header = ['RH' + str(i + 1)
                               for i in range(total_humidity_sensors)]
            # Fill remaining slots with empty strings
            humidity_header += [''] * (5 - total_humidity_sensors)

        if active_humidity_channels:
            data = [
                [' ', 'Date', 'Time', 'Set'] + ['-----Temperature(°C)-----'] + [''] * (len(temperature_header) - 1) +
                ['Set'] + ['-----Humidity(%RH)-----'] +
                [''] * (len(humidity_header) - 1),
                ['Rec No', 'DD-MM-YYYY', 'HH:MM', 'TEMP'] +
                temperature_header + ['RH'] + humidity_header
            ]
        else:
            data = [
                [' ', 'Date', 'Time', 'Set'] +
                ['-----Temperature(°C)-----'] + [''] *
                (len(temperature_header) - 1),
                ['Rec No', 'DD-MM-YYYY', 'HH:MM', 'TEMP'] + temperature_header
            ]

        # equipment = records.filter(
        #     equip_name__equip_name=selected_equipment)
        # if equipment:
        #     t_low_alarm = equipment.t_low_alarm
        #     t_high_alarm = equipment.t_high_alarm
        #     t_low_alert = equipment.t_low_alert
        #     t_high_alert = equipment.t_high_alert
        #     rh_low_alarm = equipment.rh_low_alarm
        #     rh_high_alarm = equipment.rh_high_alarm
        #     rh_low_alert = equipment.rh_low_alert
        #     rh_high_alert = equipment.rh_high_alert
        # else:
        #     t_low_alarm = t_high_alarm = rh_low_alarm = rh_high_alarm = None
        #     t_low_alert = t_high_alert = rh_low_alert = rh_high_alert = None

        for idx, record in enumerate(records, start=1):

            if record:
                t_low_alarm = record.t_low_alarm
                t_high_alarm = record.t_high_alarm
                t_low_alert = record.t_low_alert
                t_high_alert = record.t_high_alert
                rh_low_alarm = record.rh_low_alarm
                rh_high_alarm = record.rh_high_alarm
                rh_low_alert = record.rh_low_alert
                rh_high_alert = record.rh_high_alert
            else:
                t_low_alarm = t_high_alarm = rh_low_alarm = rh_high_alarm = None
                t_low_alert = t_high_alert = rh_low_alert = rh_high_alert = None

            temp_values = []
            for channel in active_temperature_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    if value <= t_low_alarm or value >= t_high_alarm:
                        # Bold for values outside alarm range
                        temp_values.append(
                            Paragraph(
                                f"<b>{
                                    value:.1f}</b>",
                                bold_style))
                    elif t_low_alert is not None and t_high_alert is not None and (t_low_alarm < value <= t_low_alert) or (t_high_alarm <= value < t_high_alert):
                        # Underline for values within alert range
                        temp_values.append(
                            Paragraph(
                                f"<u>{
                                    value:.1f}</u>",
                                normal_style))
                    else:
                        temp_values.append(
                            Paragraph(f"{value:.1f}", normal_style))
                else:
                    temp_values.append('')

            temp_values += [' '] * (5 - len(temp_values))
            humidity_values = []
            for channel in active_humidity_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    if value <= rh_low_alarm or value >= rh_high_alarm:
                        # Bold for values outside alarm range
                        humidity_values.append(
                            Paragraph(f"<b>{value:.1f}</b>", bold_style))
                    elif rh_low_alert is not None and rh_high_alert is not None and (rh_low_alarm < value <= rh_low_alert) or (rh_high_alarm <= value < rh_high_alert):
                        # Underline for values within alert range
                        humidity_values.append(
                            Paragraph(
                                f"<u>{
                                    value:.1f}</u>",
                                normal_style))
                    else:
                        humidity_values.append(
                            Paragraph(f"{value:.1f}", normal_style))
                else:
                    humidity_values.append('')

            if total_humidity_sensors > 0:
                row = [
                    str(idx),
                    record.date.strftime('%d-%m-%Y'),
                    record.time.strftime('%H:%M'),
                    Paragraph(f"{record.set_temp:.1f}",
                              normal_style) if record.set_temp is not None else ''
                ] + temp_values + [
                    Paragraph(f"{record.set_rh:.1f}",
                              normal_style) if record.set_rh is not None else ''
                ] + humidity_values

                data.append(row)
            else:
                row = [
                    str(idx),
                    record.date.strftime('%d-%m-%Y'),
                    record.time.strftime('%H:%M'),
                    Paragraph(f"{record.set_temp:.1f}",
                              normal_style) if record.set_temp is not None else ''
                ] + temp_values

                data.append(row)

        main_table_style = TableStyle([
            ('SPAN', (4, 0), (3 + len(temperature_header), 0)),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 1), 9),
            ('FONTSIZE', (0, 1), (3, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 1), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
        ])

        if active_humidity_channels:
            main_table_style.add('SPAN', (4 +
                                          len(temperature_header) +
                                          1, 0), (3 +
                                                  len(temperature_header) +
                                                  len(humidity_header) +
                                                  1, 0))

        # return current_row
        colWidths = [35, 60, 40, 35] + [35] * len(temperature_header) + (
            [35] + [35] * len(humidity_header) if active_humidity_channels else [])
        # colWidths = [40, 70, 44, 42] + [32] * len(temperature_header) + ([32] + [32] * len(humidity_header) if active_humidity_channels else [])
        main_table = Table(data, colWidths=colWidths, repeatRows=2)
        main_table.setStyle(main_table_style)

        return main_table

    content = [
        Spacer(1, 0.2 * inch),
        add_alarm_tables(),
        Spacer(1, 0.2 * inch),
        *add_temperature_table(selected_equipment),
        PageBreak(),
        add_main_table(selected_equipment),
    ]

    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response









def generate_log_pdf_landscape(request, records, from_date, to_date, from_time,
                               to_time, organization, department, username, selected_equipment):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="Data_log_report.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=landscape(A4),
        rightMargin=30,
        leftMargin=30,
        topMargin=160,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    # Determine "Records From" and "Records To"
    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record.date.strftime('%d-%m-%Y')
        records_from_time = first_record.time.strftime('%H:%M')
        records_to_date = last_record.date.strftime('%d-%m-%Y')
        records_to_time = last_record.time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(800, 35, page_text)

    def create_page(canvas, doc):

        page_num = canvas.getPageNumber()
        total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')

        # Set the title and logo
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else " "
        canvas.drawString(30, 570, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 550, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 730, 550, width=80, height=30)

        # Draw the separator line under the header
        canvas.setLineWidth(0.5)
        canvas.line(13, 540, 830, 540)

        # Add the filters and records info
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(370, 520, "Data Log Report")

        canvas.setFont("Helvetica-Bold", 10)
        equipment_display = f"Equipment Name: {selected_equipment}" if selected_equipment else "Equipment Name: Unknown"
        canvas.drawString(30, 500, equipment_display)

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(30, 480, f"Filter From: {from_date} {from_time}")
        canvas.drawString(600, 480, f"Filter To: {to_date} {to_time}")

        canvas.drawString(
            30, 460, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            600, 460, f"Records To: {records_to_date} {records_to_time}")

        # Draw separator line above the new table
        canvas.setLineWidth(0.5)
        canvas.line(13, 440, 830, 440)  # Line above the new table

        # Add a line above the footer
        canvas.setLineWidth(1)
        canvas.line(13, 60, 830, 60)  # Line just above the footer

        # Add footer with page number
        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = f"Printed By - {username} on {
            datetime.now().strftime('%d-%m-%Y %H:%M')}"  # Centered dynamic text
        footer_text_right_top = department.footer_note if department else " "
        # footer_text_right = f"Page {page_num}"

        # Draw footer at the bottom of the page
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)  # Draw "Sunwell"
        # Draw "ESTDAS v1.0" below "Sunwell"
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(420, 40, footer_text_center)  # Centered
        canvas.drawRightString(800, 45, footer_text_right_top)
        # canvas.drawRightString(800, 35, footer_text_right)  # Right side
        # (page number)

    def add_alarm_tables():
        equipment = TemperatureHumidityRecord.objects.filter(
            equip_name__equip_name=selected_equipment).first()
        
        eqp = Equipment.objects.filter(
            equip_name=selected_equipment).first()

        # Collect distinct values for alarm and alert thresholds from the records
        t_low_alarm_values = set(record.t_low_alarm for record in records if record.t_low_alarm is not None)
        t_high_alarm_values = set(record.t_high_alarm for record in records if record.t_high_alarm is not None)
        t_low_alert_values = set(record.t_low_alert for record in records if record.t_low_alert is not None)
        t_high_alert_values = set(record.t_high_alert for record in records if record.t_high_alert is not None)
        
        rh_low_alarm_values = set(record.rh_low_alarm for record in records if record.rh_low_alarm is not None)
        rh_high_alarm_values = set(record.rh_high_alarm for record in records if record.rh_high_alarm is not None)
        rh_low_alert_values = set(record.rh_low_alert for record in records if record.rh_low_alert is not None)
        rh_high_alert_values = set(record.rh_high_alert for record in records if record.rh_high_alert is not None)


        # Decide whether to use values from the records or the equipment's live data
        if len(t_low_alarm_values) > 1:
            t_low_alarm = eqp.low_alarm
        else:
            t_low_alarm = next(iter(t_low_alarm_values), None)  

        if len(t_high_alarm_values) > 1:
            t_high_alarm = eqp.high_alarm
        else:
            t_high_alarm = next(iter(t_high_alarm_values), None)

        if len(t_low_alert_values) > 1:
            t_low_alert = eqp.low_alert
        else:
            t_low_alert = next(iter(t_low_alert_values), None)

        if len(t_high_alert_values) > 1:
            t_high_alert = eqp.high_alert
            
        else:
            t_high_alert = next(iter(t_high_alert_values), None)

        if len(rh_low_alarm_values) > 1:
            rh_low_alarm = eqp.low_alarm_hum
        else:
            rh_low_alarm = next(iter(rh_low_alarm_values), None)

        if len(rh_high_alarm_values) > 1:
            rh_high_alarm = eqp.high_alarm_hum
        else:
            rh_high_alarm = next(iter(rh_high_alarm_values), None)

        if len(rh_low_alert_values) > 1:
            rh_low_alert = eqp.low_alert_hum
        else:
            rh_low_alert = next(iter(rh_low_alert_values), None)

        if len(rh_high_alert_values) > 1:
            rh_high_alert = eqp.high_alert_hum
        else:
            rh_high_alert = next(iter(rh_high_alert_values), None)

        # Data for Temperature and Humidity Alarms
        alarm_data = []

        # Check if alert data exists for temperature
        if equipment and (
                t_low_alarm is not None or t_high_alarm is not None or t_low_alert is not None or t_high_alert is not None):
            # Add the header row conditionally based on alerts
            if t_low_alert is not None or t_high_alert is not None:
                alarm_data.append(
                    ['Parameter', 'Low Alarm', 'Low Alert', 'High Alarm', 'High Alert'])
                temperature_row = [
                    'Temperature (°C)',
                    f"{t_low_alarm:.1f}" if t_low_alarm is not None else '',
                    f"{t_low_alert:.1f}" if t_low_alert is not None else '',
                    f"{t_high_alarm:.1f}" if t_high_alarm is not None else '',
                    f"{t_high_alert:.1f}" if t_high_alert is not None else ''
                ]
            else:
                alarm_data.append(['Parameter', 'Low Alarm', 'High Alarm'])
                temperature_row = [
                    'Temperature (°C)',
                    f"{t_low_alarm:.1f}" if t_low_alarm is not None else '',
                    f"{t_high_alarm:.1f}" if t_high_alarm is not None else '',
                ]

            if t_low_alert is None or t_high_alert is None:
                temperature_row = temperature_row[:3]  # Remove alert columns

            alarm_data.append(temperature_row)

        # Check if alert data exists for humidity
        if equipment and (
                rh_low_alarm is not None or rh_high_alarm is not None or rh_low_alert is not None or rh_high_alert is not None):
            # Add the header row conditionally based on alerts
            if rh_low_alert is not None or rh_high_alert is not None:
                humidity_row = [
                    'Humidity (% RH)',
                    f"{rh_low_alarm:.1f}" if rh_low_alarm is not None else '',
                    f"{rh_low_alert:.1f}" if rh_low_alert is not None else '',
                    f"{rh_high_alarm:.1f}" if rh_high_alarm is not None else '',
                    f"{rh_high_alert:.1f}" if rh_high_alert is not None else ''
                ]
            else:
                humidity_row = [
                    'Humidity (% RH)',
                    f"{rh_low_alarm:.1f}" if rh_low_alarm is not None else '',
                    f"{rh_high_alarm:.1f}" if rh_high_alarm is not None else '',
                ]

            # Add humidity alarm data

            # Remove alert columns if not available
            if rh_low_alert is None or rh_high_alert is None:
                humidity_row = humidity_row[:3]  # Remove alert columns

            alarm_data.append(humidity_row)

        base_col_widths = [210, 130, 130, 130, 130]

        if not alarm_data:

            alarm_data.append(['Parameter', 'Low Alarm', 'High Alarm'])

        if len(alarm_data[0]) == 3:
            col_widths = [322, 204, 204]
        else:
            col_widths = base_col_widths

        # Define table style
        alarm_table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Create the alarm table
        alarm_table = Table(alarm_data, colWidths=col_widths)
        alarm_table.setStyle(alarm_table_style)

        return alarm_table

    def add_temperature_table(selected_equipment):

        selected_equipment = Equipment.objects.get(
            equip_name=selected_equipment)
        total_temp_sensors = int(
            selected_equipment.total_temp_sensors) if selected_equipment.total_temp_sensors else 0
        total_humidity_sensors = int(
            selected_equipment.total_humidity_sensors) if selected_equipment.total_humidity_sensors else 0

        temperature_channels = [
            f'tmp_{i + 1}' for i in range(total_temp_sensors)]
        humidity_channels = [
            f'rh_{i + 1}' for i in range(total_humidity_sensors)]

        temp_data = [['Temperature (°C)', 'Minimum', 'Maximum', 'Average']]
        humidity_data = [['Humidity (% RH)', 'Minimum', 'Maximum', 'Average']]

        # Dynamically calculate min, max, and average for temperature channels
        i = 1
        for channel in temperature_channels:
            channel_values = [
                getattr(
                    record,
                    channel) for record in records if getattr(
                    record,
                    channel) is not None]
            if channel_values:
                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                temp_data.append(
                    ['T' + str(i), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])
            i = i + 1
        # Dynamically calculate min, max, and average for humidity channels if
        # data exists
        j = 1
        for channel in humidity_channels:
            channel_values = [
                getattr(
                    record,
                    channel) for record in records if getattr(
                    record,
                    channel) is not None]
            if channel_values:
                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                humidity_data.append(
                    ['RH' + str(j), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])
            j += 1

        # Define table style
        temp_table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Define column widths
        col_widths = [100, 80, 80, 80]  # Adjust column widths as needed

        # Create the temperature table
        temp_table = Table(temp_data, colWidths=col_widths)
        temp_table.setStyle(temp_table_style)

        # Create Humidity table
        humidity_table = Table(humidity_data, colWidths=col_widths)
        humidity_table.setStyle(temp_table_style)
        combined_table = Table(
            # Spacer to add space between the tables
            [[temp_table, Spacer(1, 0.2 * inch), humidity_table]],
            # Adjust widths to align both tables with the full width
            colWidths=[290, 100, 350]
        )

        return combined_table
    from reportlab.lib.enums import TA_RIGHT

    def add_main_table(selected_equipment):
        # Define styles for normal and bold text
        normal_style = ParagraphStyle(
            'Normal',
            fontName='Helvetica',
            fontSize=9,
            alignment=TA_RIGHT)
        bold_style = ParagraphStyle(
            'Bold',
            fontName='Helvetica-Bold',
            fontSize=9,
            alignment=TA_RIGHT)
        equipment = Equipment.objects.get(equip_name=selected_equipment)

        temperature_channels = [
            'tmp_1',
            'tmp_2',
            'tmp_3',
            'tmp_4',
            'tmp_5',
            'tmp_6',
            'tmp_7',
            'tmp_8',
            'tmp_9',
            'tmp_10']
        humidity_channels = [
            'rh_1',
            'rh_2',
            'rh_3',
            'rh_4',
            'rh_5',
            'rh_6',
            'rh_7',
            'rh_8',
            'rh_9',
            'rh_10']

        total_temp_sensors = int(
            equipment.total_temp_sensors) if equipment.total_temp_sensors else 0
        total_humidity_sensors = int(
            equipment.total_humidity_sensors) if equipment.total_humidity_sensors else 0

        temperature_channels = temperature_channels[:total_temp_sensors]
        humidity_channels = humidity_channels[:total_humidity_sensors]

        # Dynamic header generation
        temperature_header = [
            'T' + str(i + 1) for i in range(total_temp_sensors)] + [''] * (10 - total_temp_sensors)
        humidity_header = ['RH' + str(i + 1) for i in range(total_humidity_sensors)] + [
            ''] * (10 - total_humidity_sensors)

        # equipment = records.filter(
        #     equip_name__equip_name=selected_equipment).first()
        # if equipment:
        #     t_low_alarm = equipment.t_low_alarm
        #     t_high_alarm = equipment.t_high_alarm
        #     t_low_alert = equipment.t_low_alert
        #     t_high_alert = equipment.t_high_alert
        #     rh_low_alarm = equipment.rh_low_alarm
        #     rh_high_alarm = equipment.rh_high_alarm
        #     rh_low_alert = equipment.rh_low_alert
        #     rh_high_alert = equipment.rh_high_alert
        # else:
        #     t_low_alarm = t_high_alarm = rh_low_alarm = rh_high_alarm = None
        #     t_low_alert = t_high_alert = rh_low_alert = rh_high_alert = None

        # Prepare the main table headers
        data = [
            [' ', 'Date', 'Time', 'Set', '<---------Temperature(°C)--------->'] + [''] * 9 +
            ['Set', '<---------Humidity(%RH)--------->'] + [''] * 9,
            ['Rec No', 'DD-MM-YYYY', 'HH:MM', 'Temp'] +
            temperature_header + ['RH'] + humidity_header
        ]

        # Populate the table with filtered records
        for idx, record in enumerate(records, start=1):
            if record:
                t_low_alarm = record.t_low_alarm
                t_high_alarm = record.t_high_alarm
                t_low_alert = record.t_low_alert
                t_high_alert = record.t_high_alert
                rh_low_alarm = record.rh_low_alarm
                rh_high_alarm = record.rh_high_alarm
                rh_low_alert = record.rh_low_alert
                rh_high_alert = record.rh_high_alert
            else:
                t_low_alarm = t_high_alarm = rh_low_alarm = rh_high_alarm = None
                t_low_alert = t_high_alert = rh_low_alert = rh_high_alert = None

            temp_values = []
            for channel in temperature_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    # Bold for alarm values
                    if value <= t_low_alarm or value >= t_high_alarm:
                        temp_values.append(
                            Paragraph(
                                f"<b>{
                                    value:.1f}</b>",
                                bold_style))
                    # Underline for alert values
                    elif t_low_alert is not None and t_high_alert is not None and (t_low_alarm < value <= t_low_alert) or (t_high_alarm <= value < t_high_alert):
                        temp_values.append(
                            Paragraph(
                                f"<u>{
                                    value:.1f}</u>",
                                normal_style))
                    else:
                        temp_values.append(
                            Paragraph(f"{value:.1f}", normal_style))
                else:
                    temp_values.append('')
            temp_values += [' '] * (10 - len(temp_values))
            humidity_values = []
            for channel in humidity_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    # Bold for alarm values
                    if value <= rh_low_alarm or value >= rh_high_alarm:
                        humidity_values.append(
                            Paragraph(f"<b>{value:.1f}</b>", bold_style))
                    # Underline for alert values
                    elif rh_low_alert is not None and rh_high_alert is not None and (rh_low_alarm < value <= rh_low_alert) or (rh_high_alarm <= value < rh_high_alert):
                        humidity_values.append(
                            Paragraph(
                                f"<u>{
                                    value:.1f}</u>",
                                normal_style))
                    else:
                        humidity_values.append(
                            Paragraph(f"{value:.1f}", normal_style))
                else:
                    humidity_values.append('')

            # Construct the row with dynamic data
            row = [
                str(idx),
                record.date.strftime('%d-%m-%Y'),
                record.time.strftime('%H:%M'),
                Paragraph(f"{record.set_temp:.1f}",
                          normal_style) if record.set_temp is not None else ''
            ] + temp_values + [
                Paragraph(f"{record.set_rh:.1f}",
                          normal_style) if record.set_rh is not None else ''
            ] + humidity_values

            data.append(row)

        main_table_style = TableStyle([
            ('SPAN', (4, 0), (13, 0)),
            ('SPAN', (15, 0), (24, 0)),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 1), 9),
            ('FONTSIZE', (0, 1), (3, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 1), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 2),  # Reduced padding
            ('RIGHTPADDING', (0, 0), (-1, -1), 2),  #  Reduced padding
        ])

        colWidths = [29, 55, 36, 32] + [32] * 10 + [32] + [32] * 10
        main_table = Table(data, colWidths=colWidths, repeatRows=2)
        main_table.setStyle(main_table_style)

        return main_table

    content = [
        Spacer(1, 0.2 * inch),
        add_alarm_tables(),
        Spacer(1, 0.2 * inch),
        add_temperature_table(selected_equipment),
        PageBreak(),
        add_main_table(selected_equipment),
    ]

    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response


def alaram_log(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    equipments = Equipment.objects.all()
    alarm_logs_data = Alarm_logs.objects.filter(acknowledge=False)

    alarm_codes = Alarm_codes.objects.all()
    return render(request, 'Data_Analysis/alaram_log.html', {'organization': organization, 'data': data, 'acc_db': acc_db, 'equipments': equipments, 'department': department,
                                                             'alarm_logs_data': alarm_logs_data, 'acc_dept':acc_dept,
                                                             'alarm_codes': alarm_codes})


@csrf_exempt
def save_alarm_logs(request):
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            username = data.get("username")
            password = data.get("password")
            acknowledge = data.get("acknowledge")
            selected_logs = data.get("selected_logs")

            # Fetch user
            try:
                user = User.objects.get(username=username)
            except User.DoesNotExist:
                try:
                    user = SuperAdmin.objects.get(username=username)
                except SuperAdmin.DoesNotExist:
                    return JsonResponse({"message": "User or SuperAdmin not found."}, status=404)

            # Check password
            if not check_password(password, user.password):
                return JsonResponse(
                    {"message": "Invalid password."}, status=400)

            # Save selected logs
            for i in selected_logs:
                alarm_id = i.get("id") if isinstance(i, dict) else i
                try:
                    alarm = Alarm_logs.objects.get(id=alarm_id)
                    alarm.ack_time = datetime.now().time()
                    alarm.ack_date = date.today()
                    alarm.ack_user = username
                    alarm.acknowledge = True
                    alarm.comments = acknowledge
                    alarm.save()
                except Alarm_logs.DoesNotExist:
                    return JsonResponse(
                        {"message": f"Alarm log with ID {alarm_id} not found."}, status=404)

            return JsonResponse(
                {"message": "Alarm logs saved successfully!"}, status=200)

        except json.JSONDecodeError:
            return JsonResponse({"message": "Invalid JSON data."}, status=400)
        except Exception as e:
            return JsonResponse({"message": str(e)}, status=500)

    return JsonResponse({"message": "Invalid request method."}, status=405)


# Live data
def livedata_summary(request):

    emp_user = request.session.get('username', None)

    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except User.DoesNotExist:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    return render(request, 'Live Data/realtime_summary.html',
                  {'organization': organization, 'data': data, 'acc_db': acc_db, 'acc_dept':acc_dept})


def user_activity(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    filter_format = request.GET.get('format')  # "Date Wise" or "User-wise"
    from_date = request.GET.get('from-date')
    to_date = request.GET.get('to-date')
    from_time = request.GET.get('from-time')
    to_time = request.GET.get('to-time')
    users = request.GET.getlist('user-list')  # For user-wise filtering
    event_name = request.GET.get('event-name')

    filter_kwargs = Q()

    if filter_format == 'Date Wise':
        current_date = now()
        from_date_parsed = parse_date(
            from_date) if from_date else current_date.replace(day=1)
        to_date_parsed = parse_date(to_date) if to_date else current_date

        from_time_parsed = parse_time(
            from_time) if from_time else datetime_time(0, 0, 0)
        to_time_parsed = parse_time(
            to_time) if to_time else datetime_time(23, 59, 59)

        # Combine date and time into datetime objects for accurate filtering
        from_datetime = make_aware(
            datetime.combine(
                from_date_parsed,
                from_time_parsed))
        to_datetime = make_aware(
            datetime.combine(
                to_date_parsed,
                to_time_parsed))

        # Apply the datetime filter to the combined datetime field
        filter_kwargs &= Q(
            log_date__gte=from_date_parsed) & Q(
            log_date__lte=to_date_parsed)
        filter_kwargs &= Q(
            log_time__gte=from_time_parsed) & Q(
            log_time__lte=to_time_parsed)

    elif filter_format == 'User Wise':
        if users:
            user_names = User.objects.filter(
                id__in=users).values_list(
                'username', flat=True)
            filter_kwargs &= Q(user__in=user_names)

            current_date = now()
            from_date_parsed = parse_date(
                from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(
                to_date) if to_date else current_date.date()

            from_time_parsed = parse_time(
                from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(
                to_time) if to_time else datetime_time(23, 59, 59)

            # Combine date and time into datetime objects for accurate
            # filtering
            from_datetime = make_aware(
                datetime.combine(
                    from_date_parsed,
                    from_time_parsed))
            to_datetime = make_aware(
                datetime.combine(
                    to_date_parsed,
                    to_time_parsed))

            filter_kwargs &= Q(
                log_date__gte=from_date_parsed) & Q(
                log_date__lte=to_date_parsed)
            filter_kwargs &= Q(
                log_time__gte=from_time_parsed) & Q(
                log_time__lte=to_time_parsed)
        else:
            return HttpResponse(
                "User List is mandatory for User-wise format.", status=400)

    if event_name:
        filter_kwargs &= Q(event_name__icontains=event_name)

    # Directly filter on `log_date` and `log_time` without combining them into
    # a datetime
    user_logs = UserActivityLog.objects.filter(filter_kwargs)

    user_list = User.objects.filter(status='Active')

    if request.GET.get('generate_pdf'):
        if not from_date:
            from_date = now().replace(day=1).strftime('%Y-%m-%d')
        if not to_date:
            to_date = now().strftime('%Y-%m-%d')

        return generate_userActivity_pdf(
            request,
            user_logs,
            from_date,
            to_date,
            from_time,
            to_time,
            organization,
            department,
            data.username,
            filter_format
        )

    context = {
        'user_logs': user_logs,
        'user_list': user_list,
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'acc_dept':acc_dept
    }

    return render(request, 'auditlog/user_audit_log.html', context)


def generate_userActivity_pdf(request, user_logs, from_date, to_date,
                              from_time, to_time, organization, department, username, filter_format):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="user_audit_report.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=140,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    # Determine "Records From" and "Records To"
    if user_logs.exists():
        first_log = user_logs.order_by('log_date', 'log_time').first()
        last_log = user_logs.order_by('log_date', 'log_time').last()
        records_from_date = first_log.log_date.strftime('%d-%m-%Y')
        records_from_time = first_log.log_time.strftime('%H:%M')
        records_to_date = last_log.log_date.strftime('%d-%m-%Y')
        records_to_time = last_log.log_time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    from_time = from_time if from_time else "00:00"
    to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(570, 35, page_text)

    # PDF Header/Footer
    def header_footer(canvas, doc, from_date, to_date, from_time, to_time,
                      department, organization, username, page_num, total_pages):
        current_time = localtime()
        formatted_time = current_time.strftime('%d-%m-%Y %H:%M')

        from_date_formatted = datetime.strptime(
            from_date, '%Y-%m-%d').strftime('%d-%m-%Y')
        to_date_formatted = datetime.strptime(
            to_date, '%Y-%m-%d').strftime('%d-%m-%Y')

        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else ""
        canvas.drawString(30, 800, org_name)
        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 780, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 470, 780, width=80, height=30)

        canvas.setLineWidth(0.5)
        canvas.line(30, 770, 570, 770)

        canvas.setFont("Helvetica-Bold", 12)
        if filter_format == 'Date Wise':
            canvas.drawCentredString(
                300, 750, "User Audit Trail Report Date Wise")
        elif filter_format == 'User Wise':
            canvas.drawCentredString(
                300, 750, "User Audit Trail Report User Wise")

        canvas.setFont("Helvetica-Bold", 10)
        # Display filter range
        canvas.drawString(
            30, 730, "Filter From: {} {}".format(
                from_date_formatted, from_time))
        canvas.drawString(
            420, 730, "Filter To: {} {}".format(
                to_date_formatted, to_time))

        # Display records range
        canvas.drawString(
            30, 710, "Records From: {} {}".format(
                records_from_date, records_from_time))
        canvas.drawString(
            420, 710, "Records To: {} {}".format(
                records_to_date, records_to_time))

        canvas.setLineWidth(0.5)
        canvas.line(30, 60, 570, 60)

        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = "Printed By - {} on {}".format(
            username, formatted_time)
        footer_text_right_top = department.footer_note if department else " "
        # footer_text_right_bottom = f"Page {page_num} of {total_pages}"

        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(300, 40, footer_text_center)
        canvas.drawRightString(570, 45, footer_text_right_top)
        # canvas.drawRightString(570, 35, footer_text_right_bottom)

    data = [
        ['Sr No', 'Log Date', 'Log Time', 'Login Name', 'Event'],
    ]

    for idx, log in enumerate(user_logs, start=1):
        data.append([
            str(idx),
            log.log_date.strftime('%d-%m-%Y'),
            log.log_time.strftime('%H:%M:%S'),
            log.user,
            log.event_name
        ])

    table_style = TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
        ('ALIGN', (0, 0), (4, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ])

    table = Table(data, colWidths=[40, 80, 80, 100, 240], repeatRows=1)
    table.setStyle(table_style)

    first_page_spacer = Spacer(1, 0.1 * inch)
    later_pages_spacer = Spacer(1, 1 * inch)

    content = [first_page_spacer, table]

    total_pages = 1  # This will be recalculated

    def first_page(canvas, doc):
        nonlocal total_pages
        total_pages = doc.page
        header_footer(
            canvas,
            doc,
            from_date,
            to_date,
            from_time,
            to_time,
            department,
            organization,
            username,
            1,
            total_pages)

    def later_pages(canvas, doc):
        header_footer(
            canvas,
            doc,
            from_date,
            to_date,
            from_time,
            to_time,
            department,
            organization,
            username,
            doc.page,
            total_pages)

    doc.build(
        content,
        onFirstPage=first_page,
        onLaterPages=later_pages,
        canvasmaker=NumberedCanvas
    )

    return response


def equipment_Audit_log(request):

    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    users = User.objects.all()
    equipments = Equipment.objects.all()

    current_date = now()
    from_date_parsed = current_date.replace(day=1).date()
    to_date_parsed = current_date.date()
    from_time_parsed = datetime_time(0, 0, 0)
    to_time_parsed = datetime_time(23, 59, 59)

    format_type = request.GET.get('formats')
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    from_time = request.GET.get('from_time')
    to_time = request.GET.get('to_time')
    user_list = request.GET.get('user_list')
    equipment_list = request.GET.get('equipment_list')
    parameter = request.GET.get('parameter')

    filter_kwargs = Q()
    if format_type == 'Date Wise':
        from_date_parsed = parse_date(
            from_date) if from_date else current_date.replace(day=1).date()
        to_date_parsed = parse_date(
            to_date) if to_date else current_date.date()
        from_time_parsed = parse_time(
            from_time) if from_time else datetime_time(0, 0, 0)
        to_time_parsed = parse_time(
            to_time) if to_time else datetime_time(23, 59, 59)

        if from_date_parsed == to_date_parsed:
            filter_kwargs &= (
                Q(date=from_date_parsed) &
                Q(time__gte=from_time_parsed) &
                Q(time__lte=to_time_parsed)
            )
        else:
            filter_kwargs &= (
                (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
            )

    elif format_type == 'User Wise':
        if user_list:
            user_names = User.objects.filter(
                id__in=user_list).values_list(
                'username', flat=True)
            filter_kwargs &= Q(login_name__in=user_names)
            current_date = now()
            from_date_parsed = parse_date(
                from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(
                to_date) if to_date else current_date.date()
            from_time_parsed = parse_time(
                from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(
                to_time) if to_time else datetime_time(23, 59, 59)

            if from_date_parsed == to_date_parsed:
                filter_kwargs &= (
                    Q(date=from_date_parsed) &
                    Q(time__gte=from_time_parsed) &
                    Q(time__lte=to_time_parsed)
                )
            else:
                filter_kwargs &= (
                    (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                    (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                    Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
                )

            filter_kwargs &= Q(
                date__gte=from_date_parsed) & Q(
                date__lte=to_date_parsed)

        if equipment_list:
            user_names = Equipment.objects.filter(
                id=equipment_list).values_list(
                'equip_name', flat=True)

            filter_kwargs &= Q(equipment__equip_name__in=user_names)

    elif format_type == 'Equipment-wise':
        if equipment_list:
            user_names = Equipment.objects.filter(
                id=equipment_list).values_list(
                'equip_name', flat=True)
            filter_kwargs &= Q(equipment__equip_name__in=user_names)
            current_date = now()
            from_date_parsed = parse_date(
                from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(
                to_date) if to_date else current_date.date()
            from_time_parsed = parse_time(
                from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(
                to_time) if to_time else datetime_time(23, 59, 59)

            if from_date_parsed == to_date_parsed:
                filter_kwargs &= (
                    Q(date=from_date_parsed) &
                    Q(time__gte=from_time_parsed) &
                    Q(time__lte=to_time_parsed)
                )
            else:
                filter_kwargs &= (
                    (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                    (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                    Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
                )

            filter_kwargs &= Q(
                date__gte=from_date_parsed) & Q(
                date__lte=to_date_parsed)
        if user_list:
            user_names = User.objects.filter(
                id__in=user_list.split(',')).values_list(
                'username', flat=True)
            filter_kwargs &= Q(login_name__in=user_names)

    if parameter:
        filter_kwargs &= Q(label__icontains=parameter)

    eqp_write_log = Equipmentwrite.objects.filter(filter_kwargs)

    if 'generate_pdf' in request.GET:
        if not from_date:
            from_date = now().replace(day=1).strftime('%Y-%m-%d')
        if not to_date:
            to_date = now().strftime('%Y-%m-%d')

        return generate_equipment_log_pdf(
            request,
            eqp_write_log,
            from_date_parsed.strftime('%d-%m-%Y'),
            to_date_parsed.strftime('%d-%m-%Y'),
            from_time_parsed.strftime('%H:%M'),
            to_time_parsed.strftime('%H:%M'),
            organization,
            department,
            data.username,
            equipment_list,
            format_type
        )

    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'users': users,
        'equipments': equipments,
        'acc_dept':acc_dept
    }

    return render(request, 'auditlog/equipment_audit.html', context)


def generate_equipment_log_pdf(request, records, from_date, to_date, from_time,
                               to_time, organization, department, username, selected_equipment, format_type):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="Equipment_Activity_logs.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=landscape(A4),
        rightMargin=30,
        leftMargin=30,
        topMargin=130,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record.date.strftime('%d-%m-%Y')
        records_from_time = first_record.time.strftime('%H:%M')
        records_to_date = last_record.date.strftime('%d-%m-%Y')
        records_to_time = last_record.time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(800, 35, page_text)

    def create_page(canvas, doc):

        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else " "
        canvas.drawString(30, 570, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 550, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 730, 550, width=80, height=30)

        canvas.setLineWidth(0.5)
        canvas.line(13, 540, 830, 540)

        canvas.setFont("Helvetica-Bold", 12)

        if format_type == 'Date Wise':
            canvas.drawString(
                320, 520, "Equipment Audit Trail Report - Date Wise ")
        elif format_type == 'User Wise':
            canvas.drawString(
                320, 520, "Equipment Audit Trail Report -  User Wise")
        elif format_type == 'Equipment-wise':
            canvas.drawString(
                320, 520, "Equipment Audit Trail Report - Equipment Wise")

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(30, 500, f"Filter From: {from_date} {from_time}")
        canvas.drawString(670, 500, f"Filter To: {to_date} {to_time}")

        canvas.drawString(
            30, 485, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            670, 485, f"Records To: {records_to_date} {records_to_time}")

        # Draw separator line above the new table
        canvas.setLineWidth(0.5)
        canvas.line(30, 60, 820, 60)  # Line above the new table

        # Add a line above the footer
        canvas.setLineWidth(1)
        canvas.line(30, 60, 820, 60)  # Line just above the footer

        # Add footer with page number
        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = f"Printed By - {username} on {
            datetime.now().strftime('%d-%m-%Y %H:%M')}"  # Centered dynamic text
        footer_text_right_top = department.footer_note if department else " "
        # footer_text_right = f"Page {page_num}"

        # Draw footer at the bottom of the page
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)  # Draw "Sunwell"
        # Draw "ESTDAS v1.0" below "Sunwell"
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(420, 40, footer_text_center)  # Centered
        canvas.drawRightString(800, 45, footer_text_right_top)
        # canvas.drawRightString(800, 35, footer_text_right)

    # Main function to generate PDF
    def eqp_write_log_table():
        data = [
            ['Sr No', 'Log Date', 'Log Time', 'Equipment Name', 'Login Name',
                'Parameter', 'Old Status', 'New Status', 'Comments'],
        ]

        # Populate the table rows dynamically from records
        for idx, record in enumerate(records, start=1):
            equipment_name = record.equipment.equip_name if record.equipment else "N/A"
            data.append([
                str(idx),
                record.date.strftime('%d-%m-%Y') if record.date else "",
                record.time.strftime('%H:%M:%S') if record.time else "",
                Paragraph(equipment_name, styles['Normal']),
                Paragraph(record.login_name or "N/A", styles['Normal']),
                Paragraph(record.label or "N/A", styles['Normal']),
                f"{record.old_value:.1f}" if record.old_value else "N/A",
                f"{record.value:.1f}" if record.value else "N/A",
                Paragraph(record.comment or "N/A", styles['Normal']),
            ])

        # Table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (3, -1), 'CENTER'),
            ('ALIGN', (4, 1), (4, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

    # Define the table with automatic wrapping
        table = Table(
            data,
            colWidths=[
                35,
                75,
                60,
                95,
                70,
                180,
                60,
                70,
                140],
            repeatRows=1)
        table.setStyle(table_style)

        return table

    content = [
        Spacer(1, 0 * inch),
        eqp_write_log_table(),

    ]

    # Build the document
    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response


def alaram_Audit_log(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except ObjectDoesNotExist:
        acc_db = None

    organization = Organization.objects.first()
    users = User.objects.all()
    equipments = Equipment.objects.all()

    current_date = now()
    from_date_parsed = current_date.replace(day=1).date()
    to_date_parsed = current_date.date()
    from_time_parsed = datetime_time(0, 0, 0)
    to_time_parsed = datetime_time(23, 59, 59)

    format_type = request.GET.get('formats')
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    from_time = request.GET.get('from_time')
    to_time = request.GET.get('to_time')
    user_list = request.GET.get('user_list')
    equipment_list = request.GET.get('equipment_list')
    event_name = request.GET.get('event_name')

    filter_kwargs = Q()
    if format_type == 'Date Wise':
        from_date_parsed = parse_date(
            from_date) if from_date else current_date.replace(day=1).date()
        to_date_parsed = parse_date(
            to_date) if to_date else current_date.date()
        from_time_parsed = parse_time(
            from_time) if from_time else datetime_time(0, 0, 0)
        to_time_parsed = parse_time(
            to_time) if to_time else datetime_time(23, 59, 59)

        if from_date_parsed == to_date_parsed:
            filter_kwargs &= (
                Q(date=from_date_parsed) &
                Q(time__gte=from_time_parsed) &
                Q(time__lte=to_time_parsed)
            )
        else:
            filter_kwargs &= (
                (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
            )

    elif format_type == 'User Wise':
        if user_list:
            user_names = User.objects.filter(
                id__in=user_list).values_list(
                'username', flat=True)
            filter_kwargs &= Q(user__in=user_names)
            current_date = now()
            from_date_parsed = parse_date(
                from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(
                to_date) if to_date else current_date.date()
            from_time_parsed = parse_time(
                from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(
                to_time) if to_time else datetime_time(23, 59, 59)

            if from_date_parsed == to_date_parsed:
                filter_kwargs &= (
                    Q(date=from_date_parsed) &
                    Q(time__gte=from_time_parsed) &
                    Q(time__lte=to_time_parsed)
                )
            else:
                filter_kwargs &= (
                    (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                    (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                    Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
                )

            filter_kwargs &= Q(
                date__gte=from_date_parsed) & Q(
                date__lte=to_date_parsed)

    elif format_type == 'Equipment-wise':
        if equipment_list:
            user_names = Equipment.objects.filter(
                id=equipment_list).values_list(
                'equip_name', flat=True)
            filter_kwargs &= Q(equipment__equip_name__in=user_names)
            current_date = now()
            from_date_parsed = parse_date(
                from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(
                to_date) if to_date else current_date.date()
            from_time_parsed = parse_time(
                from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(
                to_time) if to_time else datetime_time(23, 59, 59)

            if from_date_parsed == to_date_parsed:
                filter_kwargs &= (
                    Q(date=from_date_parsed) &
                    Q(time__gte=from_time_parsed) &
                    Q(time__lte=to_time_parsed)
                )
            else:
                filter_kwargs &= (
                    (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                    (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                    Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
                )

            filter_kwargs &= Q(
                date__gte=from_date_parsed) & Q(
                date__lte=to_date_parsed)

    if event_name:
        filter_kwargs &= Q(event_name__icontains=event_name)

    alarm_log = Alarm_logs.objects.filter(filter_kwargs, acknowledge=True)

    if 'generate_pdf' in request.GET:
        if not from_date:
            from_date = now().replace(day=1).strftime('%Y-%m-%d')
        if not to_date:
            to_date = now().strftime('%Y-%m-%d')

        return generate_audit_alaram_log_pdf(
            request,
            alarm_log,
            from_date_parsed.strftime('%d-%m-%Y'),
            to_date_parsed.strftime('%d-%m-%Y'),
            from_time_parsed.strftime('%H:%M'),
            to_time_parsed.strftime('%H:%M'),
            organization,
            department,
            data.username,
            equipment_list,
            format_type
        )

    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'users': users,
        'equipments': equipments,
        'acc_dept':acc_dept
    }
    return render(request, 'auditlog/alaram_audit.html', context)


def generate_audit_alaram_log_pdf(request, records, from_date, to_date, from_time,
                                  to_time, organization, department, username, selected_equipment, format_type):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="Alaram_Audit_logs.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=landscape(A4),
        rightMargin=20,
        leftMargin=20,
        topMargin=140,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record.date.strftime('%d-%m-%Y')
        records_from_time = first_record.time.strftime('%H:%M')
        records_to_date = last_record.date.strftime('%d-%m-%Y')
        records_to_time = last_record.time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(800, 35, page_text)

    def create_page(canvas, doc):

        page_num = canvas.getPageNumber()
        total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')

        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else " "
        canvas.drawString(30, 570, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 550, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 730, 550, width=80, height=30)

        canvas.setLineWidth(0.5)
        canvas.line(13, 540, 830, 540)

        canvas.setFont("Helvetica-Bold", 12)

        if format_type == 'Date Wise':
            canvas.drawString(320, 520, "Alarm Audit Trail Date Wise Report")
        elif format_type == 'User Wise':
            canvas.drawString(320, 520, "Alarm Audit Trail User Wise Report")
        elif format_type == 'Equipment-wise':
            canvas.drawString(
                320, 520, "Alarm Audit Trail Equipment Wise Report")

        canvas.setFont("Helvetica-Bold", 10)
        if selected_equipment:
            equipment = Equipment.objects.get(id=selected_equipment)

            equipment_display = f"Equipment Name: {equipment.equip_name}"
            canvas.drawString(30, 500, equipment_display)

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(30, 480, f"Filter From: {from_date} {from_time}")
        canvas.drawString(670, 480, f"Filter To: {to_date} {to_time}")

        canvas.drawString(
            30, 460, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            670, 460, f"Records To: {records_to_date} {records_to_time}")

        # Draw separator line above the new table
        canvas.setLineWidth(0.5)
        canvas.line(30, 60, 820, 60)  # Line above the new table

        # Add a line above the footer
        canvas.setLineWidth(1)
        canvas.line(30, 60, 820, 60)  # Line just above the footer

        # Add footer with page number
        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = f"Printed By - {username} on {
            datetime.now().strftime('%d-%m-%Y %H:%M')}"  # Centered dynamic text
        footer_text_right_top = department.footer_note if department else " "
        # footer_text_right = f"Page {page_num}"

        # Draw footer at the bottom of the page
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)  # Draw "Sunwell"
        # Draw "ESTDAS v1.0" below "Sunwell"
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(420, 40, footer_text_center)  # Centered
        canvas.drawRightString(800, 45, footer_text_right_top)
        # canvas.drawRightString(800, 35, footer_text_right)

    # Main function to generate PDF
    def alaram_audit_log_table():
        data = [
            ['Sr No', 'Log Date', 'Log Time', 'Alarm Description',
                'Ack Date', 'Ack Time', 'Acknowledge By', 'Ack Comments'],
        ]

        # Populate the table rows dynamically from records
        for idx, record in enumerate(records, start=1):
            alarm_description = str(
                record.alarm_code.alarm_log) if record.alarm_code else ""  # Convert to string
            data.append([
                str(idx),
                record.date.strftime('%d-%m-%Y') if record.date else "",
                record.time.strftime('%H:%M:%S') if record.time else "",
                Paragraph(alarm_description, styles['Normal']),
                record.ack_date.strftime(
                    '%d-%m-%Y') if record.ack_date else "",
                record.ack_time.strftime('%H:%M') if record.ack_time else "",
                record.ack_user or "",
                Paragraph(record.comments or "", styles['Normal'])
            ])

        # Table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (3, -1), 'CENTER'),
            ('ALIGN', (4, 1), (4, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Define the table
        table = Table(
            data,
            colWidths=[
                35,
                80,
                60,
                170,
                80,
                70,
                100,
                200],
            repeatRows=1)
        table.setStyle(table_style)

        return table

    content = [
        Spacer(1, 0.2 * inch),
        alaram_audit_log_table(),

    ]

    # Build the document
    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response


def email_Audit_log(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    equipments = Equipment.objects.all()

    current_date = now()
    from_date_parsed = current_date.replace(day=1).date()
    to_date_parsed = current_date.date()
    from_time_parsed = datetime_time(0, 0, 0)
    to_time_parsed = datetime_time(23, 59, 59)

    format_type = request.GET.get('formats')
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    from_time = request.GET.get('from_time')
    to_time = request.GET.get('to_time')
    equipment_list = request.GET.get('equipment_list')
    email_status = request.GET.get('email_status')
    email_message = request.GET.get('email_message')
    email_subject = request.GET.get('email_subject')
    to_address = request.GET.get('to_address')

    filter_kwargs = Q()
    if format_type == 'Date Wise':
        from_date_parsed = parse_date(
            from_date) if from_date else current_date.replace(day=1).date()
        to_date_parsed = parse_date(
            to_date) if to_date else current_date.date()
        from_time_parsed = parse_time(
            from_time) if from_time else datetime_time(0, 0, 0)
        to_time_parsed = parse_time(
            to_time) if to_time else datetime_time(23, 59, 59)

        if from_date_parsed == to_date_parsed:
            filter_kwargs &= (
                Q(date=from_date_parsed) &
                Q(time__gte=from_time_parsed) &
                Q(time__lte=to_time_parsed)
            )
        else:
            filter_kwargs &= (
                (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
            )
        # filter_kwargs &= Q(time__gte=from_time_parsed) & Q(time__lte=to_time_parsed)

    elif format_type == 'Equipment-wise':
        if equipment_list:
            user_names = Equipment.objects.filter(
                id=equipment_list).values_list(
                'equip_name', flat=True)
            filter_kwargs &= Q(equipment__equip_name__in=user_names)
            current_date = now()
            from_date_parsed = parse_date(
                from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(
                to_date) if to_date else current_date.date()

            from_time_parsed = parse_time(
                from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(
                to_time) if to_time else datetime_time(23, 59, 59)

            if from_date_parsed == to_date_parsed:
                filter_kwargs &= (
                    Q(date=from_date_parsed) &
                    Q(time__gte=from_time_parsed) &
                    Q(time__lte=to_time_parsed)
                )
            else:
                filter_kwargs &= (
                    (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                    (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                    Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
                )
        else:
            return HttpResponse(
                "Equipment List is mandatory for Equipment-wise format.", status=400)

    elif format_type == 'System Email':
        current_date = now()
        from_date_parsed = parse_date(
            from_date) if from_date else current_date.replace(day=1).date()
        to_date_parsed = parse_date(
            to_date) if to_date else current_date.date()

        from_time_parsed = parse_time(
            from_time) if from_time else datetime_time(0, 0, 0)
        to_time_parsed = parse_time(
            to_time) if to_time else datetime_time(23, 59, 59)

        if from_date_parsed == to_date_parsed:
            filter_kwargs &= (
                Q(date=from_date_parsed) &
                Q(time__gte=from_time_parsed) &
                Q(time__lte=to_time_parsed)
            )
        else:
            filter_kwargs &= (
                (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
            )

        filter_kwargs &= Q(sys_mail=True)

    if email_status and email_status != 'email_all':
        # Correct mapping for case-sensitive status values
        status_map = {
            'email_pending': 'Pending',
            'email_sent': 'Sent',
            'email_failed': 'Failed',
        }
        db_status = status_map.get(email_status)
        if db_status:
            filter_kwargs &= Q(status=db_status)

    if email_message:
        filter_kwargs &= Q(email_body__icontains=email_message)

    if email_subject:
        filter_kwargs &= Q(email_sub__icontains=email_subject)

    if to_address:
        filter_kwargs &= Q(to_email__icontains=to_address)

    email_logs = Email_logs.objects.filter(
        filter_kwargs).order_by('date', 'time')

    if 'generate_pdf' in request.GET:
        if not from_date:
            from_date = now().replace(day=1).strftime('%Y-%m-%d')
        if not to_date:
            to_date = now().strftime('%Y-%m-%d')

        return generate_email_log_pdf(
            request,
            email_logs,
            from_date_parsed.strftime('%d-%m-%Y'),
            to_date_parsed.strftime('%d-%m-%Y'),
            from_time_parsed.strftime('%H:%M'),
            to_time_parsed.strftime('%H:%M'),
            organization,
            department,
            data.username,
            equipment_list,
            format_type
        )

    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'equipments': equipments,
        'acc_dept':acc_dept
    }
    return render(request, 'auditlog/email_audit.html', context)


def generate_email_log_pdf(request, records, from_date, to_date, from_time,
                           to_time, organization, department, username, selected_equipment, format_type):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="Email_Audit_logs.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=landscape(A4),
        rightMargin=30,
        leftMargin=30,
        topMargin=130,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record.date.strftime('%d-%m-%Y')
        records_from_time = first_record.time.strftime('%H:%M')
        records_to_date = last_record.date.strftime('%d-%m-%Y')
        records_to_time = last_record.time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(800, 35, page_text)

    def create_page(canvas, doc):

        # page_num = canvas.getPageNumber()
        # total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')

        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else " "
        canvas.drawString(30, 570, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 550, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 730, 550, width=80, height=30)

        canvas.setLineWidth(0.2)
        canvas.line(30, 540, 820, 540)

        canvas.setFont("Helvetica-Bold", 12)
        if format_type == 'Date Wise':
            canvas.drawString(320, 520, "Email Audit Trail Date Wise Report")
        elif format_type == 'Equipment-wise':
            canvas.drawString(
                320, 520, "Email Audit Trail Equipment Wise Report")
        elif format_type == 'System Email':
            canvas.drawString(320, 520, "Email Audit Trail System Wise Report")

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(30, 500, f"Filter From: {from_date} {from_time}")
        canvas.drawString(670, 500, f"Filter To: {to_date} {to_time}")

        canvas.drawString(
            30, 480, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            670, 480, f"Records To: {records_to_date} {records_to_time}")

        canvas.setLineWidth(0.5)
        canvas.line(30, 60, 820, 60)

        # canvas.setLineWidth(1)
        # canvas.line(30, 60, 820, 60)

        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = f"Printed By - {username} on {
            datetime.now().strftime('%d-%m-%Y %H:%M')}"
        footer_text_right_top = department.footer_note if department else " "
        # footer_text_right = f"Page {page_num}"

        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(425, 40, footer_text_center)
        canvas.drawRightString(800, 45, footer_text_right_top)
        # canvas.drawRightString(800, 35, footer_text_right)

    # Main function to generate PDF
    def Email_log_table():
        # Table Data
        data = [
            ['Sl No', 'Date', 'Time', 'Equipment Name', 'Email From',
                'Email To', 'Subject', 'Email Message', 'Status'],
        ]

        for idx, record in enumerate(records, start=1):
            equipment_name = str(
                record.equipment.equip_name) if record.equipment and record.equipment.equip_name else "System EMAIL"
            settings = AppSettings.objects.first()
            email_from = settings.email_host_user
            email_to = record.to_email or ""
            email_subject = record.email_sub or ""
            email_body = record.email_body or ""
            status = record.status or ""

            data.append([
                str(idx),
                record.date.strftime('%d-%m-%Y') if record.date else "",
                record.time.strftime('%H:%M:%S') if record.time else "",
                Paragraph(equipment_name, styles['Normal']),
                Paragraph(email_from, styles['Normal']),
                Paragraph(email_to, styles['Normal']),
                Paragraph(email_subject, styles['Normal']),
                Paragraph(email_body, styles['Normal']),
                status,
            ])
        # Table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            # ('ALIGN', (4, 1), (4, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Define the table with automatic wrapping
        table = Table(
            data,
            colWidths=[
                35,
                60,
                45,
                160,
                102,
                102,
                101,
                160,
                50],
            repeatRows=1)
        table.setStyle(table_style)

        return table

    content = [
        Spacer(1, 0.2 * inch),
        Email_log_table(),
    ]

    # Build the document with customized spacer for page 1 and larger spacer
    # for later pages
    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response


def sms_Audit_log(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    equipments = Equipment.objects.all()

    current_date = now()
    from_date_parsed = current_date.replace(day=1).date()
    to_date_parsed = current_date.date()
    from_time_parsed = datetime_time(0, 0, 0)
    to_time_parsed = datetime_time(23, 59, 59)

    format_type = request.GET.get('formats')
    from_date = request.GET.get('from_date')
    to_date = request.GET.get('to_date')
    from_time = request.GET.get('from_time')
    to_time = request.GET.get('to_time')
    equipment_list = request.GET.get('equipment_list')
    sms_status = request.GET.get('sms_status')
    sms_message = request.GET.get('sms_message')

    filter_kwargs = Q()
    if format_type == 'Date Wise':
        from_date_parsed = parse_date(
            from_date) if from_date else current_date.replace(day=1).date()
        to_date_parsed = parse_date(
            to_date) if to_date else current_date.date()
        from_time_parsed = parse_time(
            from_time) if from_time else datetime_time(0, 0, 0)
        to_time_parsed = parse_time(
            to_time) if to_time else datetime_time(23, 59, 59)

        if from_date_parsed == to_date_parsed:
            filter_kwargs &= (
                Q(date=from_date_parsed) &
                Q(time__gte=from_time_parsed) &
                Q(time__lte=to_time_parsed)
            )
        else:
            filter_kwargs &= (
                (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
            )
        # filter_kwargs &= Q(time__gte=from_time_parsed) & Q(time__lte=to_time_parsed)
        if equipment_list:
            user_names = Equipment.objects.filter(
                id=equipment_list).values_list(
                'equip_name', flat=True)

            filter_kwargs &= Q(equipment__equip_name__in=user_names)

    elif format_type == 'Equipment-wise':
        if equipment_list:
            user_names = Equipment.objects.filter(
                id=equipment_list).values_list(
                'equip_name', flat=True)
            filter_kwargs &= Q(equipment__equip_name__in=user_names)
            current_date = now()
            from_date_parsed = parse_date(
                from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(
                to_date) if to_date else current_date.date()

            from_time_parsed = parse_time(
                from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(
                to_time) if to_time else datetime_time(23, 59, 59)

            if from_date_parsed == to_date_parsed:
                filter_kwargs &= (
                    Q(date=from_date_parsed) &
                    Q(time__gte=from_time_parsed) &
                    Q(time__lte=to_time_parsed)
                )
            else:
                filter_kwargs &= (
                    (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                    (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                    Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
                )
        else:
            return HttpResponse(
                "Equipment List is mandatory for Equipment-wise format.", status=400)

    elif format_type == 'System SMS':
        current_date = now()
        from_date_parsed = parse_date(
            from_date) if from_date else current_date.replace(day=1).date()
        to_date_parsed = parse_date(
            to_date) if to_date else current_date.date()

        from_time_parsed = parse_time(
            from_time) if from_time else datetime_time(0, 0, 0)
        to_time_parsed = parse_time(
            to_time) if to_time else datetime_time(23, 59, 59)

        if from_date_parsed == to_date_parsed:
            filter_kwargs &= (
                Q(date=from_date_parsed) &
                Q(time__gte=from_time_parsed) &
                Q(time__lte=to_time_parsed)
            )
        else:
            filter_kwargs &= (
                (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
                (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
                Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
            )
        # Add sys_sms=True condition
        filter_kwargs &= Q(sys_sms=True)

    if sms_status and sms_status != 'sms_all':
        # Correct mapping for SMS status values
        status_map = {
            'sms_pending': 'Pending',  # Matches "Pending" in the database
            'sms_sent': 'Sent',        # Matches "Sent" in the database
            'sms_failed': 'Failed',    # Matches "Failed" in the database
        }

        # Get the corresponding database value
        db_status = status_map.get(sms_status)
        if db_status:
            filter_kwargs &= Q(status=db_status)

    if sms_message:
        filter_kwargs &= Q(msg_body__icontains=sms_message)

    sms_logs = Sms_logs.objects.filter(filter_kwargs)

    if 'generate_pdf' in request.GET:
        if not from_date:
            from_date = now().replace(day=1).strftime('%Y-%m-%d')
        if not to_date:
            to_date = now().strftime('%Y-%m-%d')

        return generate_sms_log_pdf(
            request,
            sms_logs,
            from_date_parsed.strftime('%d-%m-%Y'),
            to_date_parsed.strftime('%d-%m-%Y'),
            from_time_parsed.strftime('%H:%M'),
            to_time_parsed.strftime('%H:%M'),
            organization,
            department,
            data.username,
            equipment_list,
            format_type
        )

    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'equipments': equipments,
        'acc_dept':acc_dept
    }
    return render(request, 'auditlog/sms_audit.html', context)


def generate_sms_log_pdf(request, records, from_date, to_date, from_time, to_time,
                         organization, department, username, selected_equipment, format_type):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="SMS_Audit_logs.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=landscape(A4),
        rightMargin=30,
        leftMargin=30,
        topMargin=130,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record.date.strftime('%d-%m-%Y')
        records_from_time = first_record.time.strftime('%H:%M')
        records_to_date = last_record.date.strftime('%d-%m-%Y')
        records_to_time = last_record.time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(800, 35, page_text)

    def create_page(canvas, doc):

        page_num = canvas.getPageNumber()
        total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')

        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else " "
        canvas.drawString(30, 570, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 550, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 730, 550, width=80, height=30)

        canvas.setLineWidth(0.5)
        canvas.line(30, 540, 820, 540)

        canvas.setFont("Helvetica-Bold", 12)
        if format_type == 'Date Wise':
            canvas.drawString(320, 520, "SMS Audit Trail Date Wise Report")
        elif format_type == 'Equipment-wise':
            canvas.drawString(
                320, 520, "SMS Audit Trail Equipment Wise Report")
        elif format_type == 'System SMS':
            canvas.drawString(320, 520, "SMS Audit Trail System Wise Report")

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(30, 500, f"Filter From: {from_date} {from_time}")
        canvas.drawString(670, 500, f"Filter To: {to_date} {to_time}")

        canvas.drawString(
            30, 480, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            670, 480, f"Records To: {records_to_date} {records_to_time}")

        canvas.setLineWidth(0.5)
        canvas.line(30, 60, 820, 60)

        # canvas.setLineWidth(1)
        # canvas.line(30, 60, 820, 60)

        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = f"Printed By - {username} on {
            datetime.now().strftime('%d-%m-%Y %H:%M')}"
        footer_text_right_top = department.footer_note if department else " "
        # footer_text_right = f"Page {page_num}"

        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(425, 40, footer_text_center)
        canvas.drawRightString(800, 45, footer_text_right_top)
        # canvas.drawRightString(820, 40, footer_text_right)

    def SMS_log_table():

        data = [
            ['Sl No',
             'Date',
             'Time',
             'Equipment Name',
             'Mobile User Name',
             'Mobile No',
             'SMS Message',
             'SMS Status'],
        ]

        for idx, record in enumerate(records, start=1):
            equipment_name = str(
                record.equipment.equip_name) if record.equipment and record.equipment.equip_name else "System SMS"
            user_name = record.user_name or "N/A"
            mobile_no = record.to_num or "N/A"
            sms_message = record.msg_body or ""
            status = record.status or "N/A"

            data.append([
                str(idx),
                record.date.strftime('%d-%m-%Y') if record.date else "",
                record.time.strftime('%H:%M:%S') if record.time else "",
                Paragraph(equipment_name, styles['Normal']),
                Paragraph(user_name, styles['Normal']),
                Paragraph(str(mobile_no), styles['Normal']),
                Paragraph(sms_message, styles['Normal']),
                status,
            ])

        # Table Style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            # ('ALIGN', (4, 1), (4, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Define the table with automatic wrapping
        table = Table(
            data,
            colWidths=[
                40,
                65,
                50,
                160,
                120,
                120,
                160,
                80],
            repeatRows=1)
        table.setStyle(table_style)

        return table

    content = [
        Spacer(1, 0.2 * inch),
        SMS_log_table(),
    ]

    # Build the document with customized spacer for page 1 and larger spacer
    # for later pages
    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response


def view_alarm_log(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    organization = Organization.objects.first()
    # Get filter parameters from the request
    selected_equipment = request.GET.get('equipment')
    from_date = request.GET.get('from-date')
    to_date = request.GET.get('to-date')
    from_time = request.GET.get('from-time') or '00:00'
    to_time = request.GET.get('to-time') or '23:59'
    filter_kwargs = Q()
    # Filter by equipment if selected
    if selected_equipment:
        filter_kwargs &= Q(equipment__id=selected_equipment)

    # Handle missing dates - default to the 1st of the current month and
    # today's date
    current_date = now().date()
    if not from_date:
        from_date = current_date.replace(day=1).strftime('%Y-%m-%d')
    if not to_date:
        to_date = current_date.strftime('%Y-%m-%d')

    # Parse the from_date and to_date
    from_date_parsed = datetime.strptime(from_date, '%Y-%m-%d').date()
    to_date_parsed = datetime.strptime(to_date, '%Y-%m-%d').date()

    from_time_parsed = datetime.strptime(from_time, '%H:%M').time()
    to_time_parsed = datetime.strptime(to_time, '%H:%M').time()

    if from_date_parsed == to_date_parsed:
        filter_kwargs &= (
            Q(date=from_date_parsed) &
            Q(time__gte=from_time_parsed) &
            Q(time__lte=to_time_parsed)
        )
    else:
        filter_kwargs &= (
            (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |
            (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |
            Q(date__gt=from_date_parsed, date__lt=to_date_parsed)
        )

    alaram_log = Alarm_logs.objects.filter(
        filter_kwargs).order_by('date', 'time')
    eqp_list = Equipment.objects.filter(status='Active')

    return generate_alaram_log_pdf(
        request,
        alaram_log,
        from_date_parsed.strftime('%d-%m-%Y'),
        to_date_parsed.strftime('%d-%m-%Y'),
        from_time_parsed.strftime('%H:%M'),
        to_time_parsed.strftime('%H:%M'),
        organization,
        department,
        data.username,
        selected_equipment
    )


def generate_alaram_log_pdf(request, records, from_date, to_date, from_time,
                            to_time, organization, department, username, selected_equipment):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="Alaram_logs.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=A4,
        rightMargin=30,
        leftMargin=30,
        topMargin=160,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record.date.strftime('%d-%m-%Y')
        records_from_time = first_record.time.strftime('%H:%M')
        records_to_date = last_record.date.strftime('%d-%m-%Y')
        records_to_time = last_record.time.strftime('%H:%M')
    else:
        records_from_date = from_date
        records_from_time = from_time if from_time else "00:00"
        records_to_date = to_date
        records_to_time = to_time if to_time else "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(570, 35, page_text)

    def create_page(canvas, doc):

        page_num = canvas.getPageNumber()
        total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')
        # Header
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else ""
        canvas.drawString(30, 800, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 780, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 470, 780, width=80, height=30)

        # Draw the separator line under the header
        canvas.setLineWidth(0.5)
        canvas.line(30, 770, 570, 770)

        # Add the filters and records info
        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(250, 750, "Alarm Log Report")

        canvas.setFont("Helvetica-Bold", 10)
        equipment = Equipment.objects.get(id=selected_equipment)
        equipment_display = f"Equipment Name: {equipment.equip_name}"
        canvas.drawString(30, 730, equipment_display)

        canvas.setFont("Helvetica-Bold", 10)
        # canvas.drawString(30, 730, f"Equipment Name: {selected_equipment}")
        canvas.drawString(30, 710, f"Filter From: {from_date} {from_time}")
        canvas.drawString(400, 710, f"Filter To: {to_date} {to_time}")
        canvas.drawString(
            30, 690, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            400, 690, f"Records To: {records_to_date} {records_to_time}")

        # Draw separator line above the new table
        canvas.setLineWidth(0.5)
        canvas.line(30, 670, 570, 670)  # Line above the new table

        # Add a line above the footer
        canvas.setLineWidth(1)
        canvas.line(30, 60, 570, 60)  # Line just above the footer

        # Add footer with page number
        footer_left_top = "Sunwell"
        footer_left_bottom = "ESTDAS v1.0"
        footer_center = f"Printed By - {username} on {current_time}"
        footer_text_right_top = department.footer_note if department else " "
        # footer_right_bottom = f"Page {page_num} of {total_pages}"

        # Draw footer at the bottom of the page
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_left_top)
        canvas.drawString(30, 35, footer_left_bottom)
        canvas.drawCentredString(300, 40, footer_center)
        canvas.drawRightString(570, 45, footer_text_right_top)
        # canvas.drawRightString(570, 35, footer_right_bottom)

    # Main function to generate PDF
    def alaram_log_table():
        data = [
            ['Sr No', 'Log Date', 'Log Time', 'Alarm Description'],
        ]

        # Populate the table rows dynamically from records
        for idx, record in enumerate(records, start=1):
            alarm_description = str(
                record.alarm_code.alarm_log) if record.alarm_code else "N/A"  # Convert to string
            data.append([
                str(idx),
                record.date.strftime('%d-%m-%Y') if record.date else "N/A",
                record.time.strftime('%H:%M:%S') if record.time else "N/A",
                Paragraph(alarm_description, styles['Normal']),
            ])

        # Table style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.black),
            ('ALIGN', (0, 0), (4, -1), 'CENTER'),
            ('ALIGN', (3, 1), (3, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
        ])

        # Define the table
        # repeatRows=1 to repeat the first row
        table = Table(data, colWidths=[60, 110, 110, 260], repeatRows=1)
        table.setStyle(table_style)

        return table

    content = [
        Spacer(1, 0.2 * inch),
        alaram_log_table(),

    ]

    # Build the document
    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response


def connect_to_plc1(ip_address):
    try:
        plc = snap7.client.Client()
        plc.connect(ip_address, PLC_RACK, PLC_SLOT)
        return plc
    except Exception as e:
        return False


def eqp_stngs_safe_float(value, default=0.0):
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


@csrf_exempt
def save_equipment_settings(request):
    data = json.loads(request.body)
    tab_name = data.get('tab_name')
    username = data.get('username')
    password = data.get('password')
    ackn = data.get('acknowledge')
    try:
        user = User.objects.get(username=username)
    except User.DoesNotExist:
        try:
            user = SuperAdmin.objects.get(username=username)
        except SuperAdmin.DoesNotExist:
            return JsonResponse({"message": "User or SuperAdmin not found."}, status=404)

    if not check_password(password, user.password):
        return JsonResponse(
            {"status": "error", "message": "Invalid password."}, status=400)

    if tab_name == "settings":
        ip = data.get('equipment_ip')
        ip_address = Equipment.objects.get(ip_address=ip)
        temp_set_value = eqp_stngs_safe_float(data.get('temp_set_value'))
        temp_low_alarm = eqp_stngs_safe_float(data.get('temp_low_alarm'))
        temp_high_alarm = eqp_stngs_safe_float(data.get('temp_high_alarm'))
        temp_sensor = eqp_stngs_safe_float(data.get('temp_sensor'))
        temp_high_alert = eqp_stngs_safe_float(data.get('temp_high_alert'))
        temp_low_alert = eqp_stngs_safe_float(data.get('temp_low_alert'))
        humidity_set_value = eqp_stngs_safe_float(
            data.get('humidity_set_value'))
        humidity_low_alarm = eqp_stngs_safe_float(
            data.get('humidity_low_alarm'))
        humidity_high_alarm = eqp_stngs_safe_float(
            data.get('humidity_high_alarm'))
        humidity_sensor = eqp_stngs_safe_float(data.get('humidity_sensor'))
        humidity_high_alert = eqp_stngs_safe_float(
            data.get('humidity_high_alert'))
        humidity_low_alert = eqp_stngs_safe_float(
            data.get('humidity_low_alert'))
        

        plc = connect_to_plc1(ip)
        if plc == False:

            return JsonResponse(
                {"status": "error", "message": "Equipment Not connected! Please check "})
        if plc.get_connected():
            if ip_address.set_value != temp_set_value:

                data = bytearray(4)
                set_real(data, 0, temp_set_value)
                plc.db_write(19, 0, data)
                Equipmentwrite.objects.create(
                    equipment=ip_address,
                    label="Temperature Set Value Updated",
                    old_value=ip_address.set_value,
                    value=temp_set_value,
                    status='Done',
                    time=datetime.now().time(),
                    date=datetime.now().date(),
                    login_name=username,
                    comment=ackn
                )
                ip_address.set_value = temp_set_value

            if ip_address.low_alarm != temp_low_alarm:

                data = bytearray(4)
                set_real(data, 0, temp_low_alarm)
                plc.db_write(19, 4, data)
                Equipmentwrite.objects.create(
                    equipment=ip_address,
                    label="Temperature Low Alarm Value Updated",
                    old_value=ip_address.low_alarm,
                    value=temp_low_alarm,
                    status='Done',
                    time=datetime.now().time(),
                    date=datetime.now().date(),
                    login_name=username,
                    comment=ackn
                )
                ip_address.low_alarm = temp_low_alarm

            if ip_address.high_alarm != temp_high_alarm:

                data = bytearray(4)
                set_real(data, 0, temp_high_alarm)
                plc.db_write(19, 8, data)
                Equipmentwrite.objects.create(
                    equipment=ip_address,
                    label="Temperature High Alarm Value Updated",
                    old_value=ip_address.high_alarm,
                    value=temp_high_alarm,
                    status='Done',
                    time=datetime.now().time(),
                    date=datetime.now().date(),
                    login_name=username,
                    comment=ackn
                )
                ip_address.high_alarm = temp_high_alarm
            if ip_address.total_humidity_sensors > 0:
                if ip_address.set_value_hum != humidity_set_value:

                    data = bytearray(4)
                    set_real(data, 0, humidity_set_value)
                    plc.db_write(19, 772, data)
                    Equipmentwrite.objects.create(
                        equipment=ip_address,
                        label="Humidity Set Value Updated",
                        old_value=ip_address.set_value_hum,
                        value=humidity_set_value,
                        status='Done',
                        time=datetime.now().time(),
                        date=datetime.now().date(),
                        login_name=username,
                        comment=ackn
                    )
                    ip_address.set_value_hum = humidity_set_value

                if ip_address.low_alarm_hum != humidity_low_alarm:

                    data = bytearray(4)
                    set_real(data, 0, humidity_low_alarm)
                    plc.db_write(19, 776, data)
                    Equipmentwrite.objects.create(
                        equipment=ip_address,
                        label="Humidity Low Alarm Value Updated",
                        value=humidity_low_alarm,
                        old_value=ip_address.low_alarm_hum,
                        status='Done',
                        time=datetime.now().time(),
                        date=datetime.now().date(),
                        login_name=username,
                        comment=ackn
                    )
                    ip_address.low_alarm_hum = humidity_low_alarm

                if ip_address.high_alarm_hum != humidity_high_alarm:

                    data = bytearray(4)
                    set_real(data, 0, humidity_high_alarm)
                    plc.db_write(19, 780, data)
                    Equipmentwrite.objects.create(
                        equipment=ip_address,
                        label="Humidity High Alarm Value Updated",
                        value=humidity_high_alarm,
                        old_value=ip_address.high_alarm_hum,
                        status='Done',
                        time=datetime.now().time(),
                        date=datetime.now().date(),
                        login_name=username,
                        comment=ackn
                    )
                    ip_address.high_alarm_hum = humidity_high_alarm

        ip_address.total_temp_sensors = temp_sensor
        ip_address.high_alert = temp_high_alert
        ip_address.low_alert = temp_low_alert
        ip_address.save()
        if ip_address.total_humidity_sensors > 0:
            ip_address.total_humidity_sensors = humidity_sensor
            ip_address.high_alert_hum = humidity_high_alert
            ip_address.low_alert_hum = humidity_low_alert

            ip_address.save()

    return JsonResponse(
        {"status": "success", "message": "Data saved successfully!"})

@csrf_exempt
def save_parameters(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        parameters = data.get('parameters', [])
        ip_address = data.get('ip_address')

        try:
            equipment = Equipment.objects.get(ip_address=ip_address)
        except Equipment.DoesNotExist:
            return JsonResponse(
                {'status': 'error', 'message': 'Equipment not found'}, status=404)

        equip_params, created = EquipParameter.objects.get_or_create(
            equipment=equipment)

        for i in range(1, int(equipment.total_temp_sensors) + 1):
            param_name = f'Temperature {i}'

            color = next(
                (item['color'] for item in parameters if item['name'] == param_name), None)
            if color:
                setattr(equip_params, f't{i}color', color)

        for i in range(1, int(equipment.total_humidity_sensors) + 1):
            param_name = f'Humidity {i}'

            color = next(
                (item['color'] for item in parameters if item['name'] == param_name), None)
            if color:
                setattr(equip_params, f'rh{i}color', color)

        equip_params.save()

        return JsonResponse(
            {'status': 'success', 'message': 'Parameters updated successfully!'})
    return JsonResponse(
        {'status': 'error', 'message': 'Invalid request'}, status=400)


@csrf_exempt
def save_alert_settings(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        email_alerts = data.get('emailData', {}).get('email', [])
        sms_alerts = data.get('smsData', {}).get('sms', [])
        ip_address = data.get('ip_address', {}).get('ip_address', '')
        

        equipment = Equipment.objects.get(ip_address=ip_address)
        email = emailalert.objects.get(equipment_name=equipment.id)

        for i in email_alerts:
            alert_id = i.get('id')
            alert_checked = i.get('checked')
            if hasattr(email, alert_id):
                setattr(email, alert_id, alert_checked)
            else:
                print(f"Attribute {alert_id} not found on EmailAlert")
        email.save()
        sms = smsalert.objects.get(equipment_name=equipment.id)
        for i in sms_alerts:
            alert_id = i.get('id')
            alert_checked = i.get('checked')
            if hasattr(sms, alert_id):
                setattr(sms, alert_id, alert_checked)
        sms.save()

        return JsonResponse(
            {"status": "success", "message": "Alert settings saved successfully."})
    return JsonResponse(
        {"status": "error", "message": "Invalid request"}, status=400)

# Constants
ACTIVATION_ENERGY = 83144  # J/mol (approx. 83.144 kJ/mol)
GAS_CONSTANT = 8.314  # J/mol·K


def calculate_mkt(temp_values):
    """
    Calculate Mean Kinetic Temperature (MKT) using the Arrhenius equation.
    """
    if not temp_values:
        return None  # Return None if no values are available

    # Convert °C to K
    kelvin_temps = [t + 273.15 for t in temp_values if t is not None]
    exponentials = [exp(-ACTIVATION_ENERGY / (GAS_CONSTANT * T))
                    for T in kelvin_temps]

    try:
        mkt_kelvin = - (ACTIVATION_ENERGY / GAS_CONSTANT) / \
            log(sum(exponentials) / len(exponentials))
        mkt_celsius = mkt_kelvin - 273.15  # Convert K back to °C
        return round(mkt_celsius, 1)
    except ValueError:
        return None  # Handle log(0) error


def Mkt_analysis(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')

    try:
        data = User.objects.get(username=emp_user)
        department = data.department
    except:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()
        department = None

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    organization = Organization.objects.first()
    equipments = Equipment.objects.all()
    for equipment in equipments:
        equipment.sensor_range = range(equipment.total_temp_sensors or 0)

    # Default date range: first day of the month to today
    current_date = now()
    from_date = request.GET.get('from-date')
    to_date = request.GET.get('to-date')

    from_date_parsed = datetime.strptime(
        from_date, '%Y-%m-%d').date() if from_date else current_date.replace(day=1).date()
    to_date_parsed = datetime.strptime(
        to_date, '%Y-%m-%d').date() if to_date else current_date.date()

    selected_equipment = request.GET.get('equipment', None)

    filter_kwargs = Q(date__range=(from_date_parsed, to_date_parsed))

    if request.method == 'GET':
        selected_sensors = request.GET.getlist('selected_sensors[]')
        selected_sensors = [
            int(sensor) for sensor in selected_sensors] if selected_sensors else []

    if selected_equipment:
        filter_kwargs &= Q(equip_name_id=selected_equipment)

    # Fetch temperature records
    temp_records = (
        TemperatureHumidityRecord.objects.filter(filter_kwargs)
        .values("date")
        .annotate(
            **{f"min_tmp_{i}": Min(f"tmp_{i}") for i in range(1, 11)},
            **{f"max_tmp_{i}": Max(f"tmp_{i}") for i in range(1, 11)},
            **{f"avg_tmp_{i}": Avg(f"tmp_{i}") for i in range(1, 11)},
        )
        .order_by("date")
    )

    # Format Data for PDF
    if selected_equipment:
        eqp = Equipment.objects.get(id=selected_equipment)
        no_of_sensors = eqp.total_temp_sensors + 1
    else:
        no_of_sensors = 10 + 1

    results = []
    for record in temp_records:
        row = {
            "date": record["date"],
            "channels": [],
        }
        for i in range(1, no_of_sensors):
            if i in selected_sensors:
                row["channels"].append({
                    "channel": f"CH-{i}",
                    "min": round(record.get(f"min_tmp_{i}", 0), 1) if record.get(f"min_tmp_{i}") is not None else None,
                    "max": round(record.get(f"max_tmp_{i}", 0), 1) if record.get(f"max_tmp_{i}") is not None else None,
                    "mean": round(record.get(f"avg_tmp_{i}", 0), 1) if record.get(f"avg_tmp_{i}") is not None else None,
                })
            else:
                row["channels"].append({
                    "channel": f"CH-{i}",
                    "min": None,
                    "max": None,
                    "mean": None,
                })
        results.append(row)

    channel_aggregated_means = {}
    for i in range(1, no_of_sensors):
        channel_means = [record["channels"][i - 1]["mean"]
                         for record in results if record["channels"][i - 1]["mean"] is not None]
        avg_mean = np.mean(channel_means) if channel_means else None
        mkt = calculate_mkt(channel_means) if channel_means else None
        deviation = round(
            mkt - avg_mean,
            1) if mkt is not None and avg_mean is not None else None

        channel_aggregated_means[f"CH-{i}"] = {
            "avg_mean": round(avg_mean, 1) if avg_mean else "",
            "mkt": mkt if mkt is not None else "",
            "deviation": deviation if deviation is not None else ""
        }

    # PDF Generation
    if 'generate_pdf' in request.GET:
        return generate_mkt_log_pdf(
            request,
            temp_records,
            from_date_parsed.strftime('%d-%m-%Y'),
            to_date_parsed.strftime('%d-%m-%Y'),
            organization,
            department,
            data.username,
            selected_equipment,
            results,
            channel_aggregated_means,
            no_of_sensors,
            selected_sensors,
        )

    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'equipments': equipments,
        'results': results,
        'acc_dept':acc_dept
    }

    return render(request, 'Data_Analysis/Mkt.html', context)


def generate_mkt_log_pdf(request, records, from_date, to_date, organization, department, username,
                         selected_equipment, results, channel_aggregated_means, no_of_sensors, selected_sensors):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="MKT_Analysis.pdf"'

    doc = SimpleDocTemplate(
        response,
        pagesize=landscape(A4),
        rightMargin=4,
        leftMargin=2,
        topMargin=150,
        bottomMargin=60)
    styles = getSampleStyleSheet()

    from_time = "00:00"
    to_time = "23:59"
    if records.exists():
        first_record = records.order_by('date', 'time').first()
        last_record = records.order_by('date', 'time').last()
        records_from_date = first_record['date'].strftime('%d-%m-%Y')
        records_from_time = "00:00"
        records_to_date = last_record['date'].strftime('%d-%m-%Y')
        records_to_time = "23:59"
    else:
        records_from_date = from_date
        records_from_time = "00:00"
        records_to_date = to_date
        records_to_time = "23:59"

    class NumberedCanvas(canvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.pages = []

        def showPage(self):
            self.pages.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total_pages = len(self.pages)
            for i, page in enumerate(self.pages):
                self.__dict__.update(page)
                self.draw_page_number(i + 1, total_pages)
                super().showPage()
            super().save()

        def draw_page_number(self, page_number, total_pages):
            self.setFont("Helvetica", 10)
            page_text = f"Page {page_number} of {total_pages}"
            self.drawRightString(800, 35, page_text)

    def create_page(canvas, doc):

        current_time = localtime().strftime('%d-%m-%Y %H:%M')
        # Header
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        org_name = organization.name if organization else ""
        canvas.drawString(30, 570, org_name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        department_name = department.header_note if department else " "
        canvas.drawString(30, 550, department_name)

        logo_path = organization.logo.path if organization and organization.logo else " "
        if logo_path.strip():
            canvas.drawImage(logo_path, 730, 550, width=80, height=30)

        canvas.setLineWidth(0.2)
        canvas.line(25, 535, 820, 535)

        canvas.setFont("Helvetica-Bold", 12)
        canvas.drawString(320, 520, "Mean Kinetic Temperature")

        canvas.setFont("Helvetica-Bold", 10)
        canvas.drawString(30, 500, f"Filter From: {from_date} {from_time}")
        canvas.drawString(670, 500, f"Filter To: {to_date} {to_time}")

        canvas.drawString(
            30, 480, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(
            670, 480, f"Records To: {records_to_date} {records_to_time}")

        canvas.setFont("Helvetica-Bold", 10)
        equipment = Equipment.objects.get(id=selected_equipment)
        equipment_display = f"Equipment Name: {equipment.equip_name}"
        canvas.drawString(30, 460, equipment_display)

        # canvas.drawString(670, 440, "Parameter Name: kinemtic")

        canvas.setLineWidth(0.5)
        canvas.line(30, 670, 570, 670)  # Line above the new table

        canvas.setLineWidth(0.5)
        canvas.line(20, 60, 820, 60)
        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = f"Printed By - {username} on {current_time}"
        footer_text_right_top = department.footer_note if department else " "
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(420, 40, footer_text_center)
        canvas.drawRightString(800, 45, footer_text_right_top)

    def mkt_table():

        # Table Data
        temperature_headers = []
        for i in range(1, no_of_sensors):
            temperature_headers.append('')  # Empty column before
            temperature_headers.append(f'T{i}')  # Sensor column
            temperature_headers.append('')  # Empty column after

        # Fill remaining slots to maintain 10 sensors
        temperature_headers += [''] * \
            (3 * (10 - len(temperature_headers) // 3))

        sub_headers = []
        for i in range(1, no_of_sensors):
            sub_headers.extend(['Max', 'Min', 'Mean'])
        # Fill remaining columns with empty values
        sub_headers += [''] * (3 * (10 - len(temperature_headers)))

        # **Table Header**
        data = [
            ['Rec No', 'Start Date', 'End Date'] +
            temperature_headers,  # Main header row
            ['', '', ''] + sub_headers  # Sub header row
        ]

        rec_no = 1
        for record in results:
            row = [rec_no,
                   record["date"].strftime('%d-%m-%Y'),
                   record["date"].strftime('%d-%m-%Y')] + ["",
                                                           "",
                                                           ""] * 10
            for channel in record["channels"]:
                # Extract sensor number (e.g., 2, 6, 10)
                channel_number = int(channel["channel"].split('-')[1])
                if channel_number in selected_sensors:
                    # Calculate the starting index for this sensor's data
                    index = 3 + (channel_number - 1) * 3
                    row[index] = str(
                        channel["max"]) if channel["max"] is not None else ""
                    row[index + 1] = str(channel["min"]
                                         ) if channel["min"] is not None else ""
                    row[index + 2] = str(channel["mean"]
                                         ) if channel["mean"] is not None else ""

            data.append(row)

            rec_no += 1

        mkt_row = ["", "MKT (°C)", ""]
        avg_temp_row = ["", "AVG TEMP (°C)", ""]
        dev_temp_row = ["", "DEV AVG TEMP (°C)", ""]
        for i in range(1, no_of_sensors):
            stats = channel_aggregated_means.get(f"CH-{i}", {})
            mkt_row.extend(["", "", str(stats.get("mkt", ""))])
            avg_temp_row.extend(["", "", str(stats.get("avg_mean", ""))])
            dev_temp_row.extend(["", "", str(stats.get("deviation", ""))])
        data.append(mkt_row)
        data.append(avg_temp_row)
        data.append(dev_temp_row)

        # Updated Table Style
        table_style = TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7.5),
            ('ALIGN', (3, -3), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, -3), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, -3), (-1, -1), 8),
            ('SPAN', (1, -3), (2, -3)),  # Merge for MKT
            ('SPAN', (1, -2), (2, -2)),  # Merge for AVG TEMP
            ('SPAN', (1, -1), (2, -1)),  # Merge for DEV TEMP
            ('ALIGN', (1, -3), (2, -1), 'CENTER'),
            ('VALIGN', (1, -3), (2, -1), 'MIDDLE'),
            ('LINEABOVE', (0, 0), (-1, 0), 0.5, colors.black),
            ('LINEBELOW', (0, 0), (-1, 0), 0.5, colors.black),
            ('LINEBELOW', (0, 1), (-1, 1), 0.5, colors.black),
            ('LINEBELOW', (0, -4), (-1, -4), 0.5, colors.black),
            ('LINEBELOW', (0, -1), (-1, -1), 0.5, colors.black),
            ('TEXTCOLOR', (1, -3), (2, -1), colors.black),
            ('FONTNAME', (1, -3), (2, -1), 'Helvetica'),
            ('FONTSIZE', (1, -3), (2, -1), 9),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('GRID', (0, 0), (-1, -1), 0, colors.transparent),

            # Vertical line thickness adjustment
            # Thicker line before sl.no
            ('LINEBEFORE', (0, 0), (0, -1), 0.5, colors.black),
            # Thicker line after sl.no
            ('LINEBEFORE', (1, 0), (1, -1), 0.5, colors.black),
            # Thicker line after start date
            ('LINEBEFORE', (2, 0), (2, -1), 0.5, colors.black),
            # Thicker line after end date
            ('LINEBEFORE', (3, 0), (3, -1), 0.5, colors.black),
            # Thicker line after Ch-1
            ('LINEAFTER', (5, 0), (5, -1), 0.5, colors.black),
            # Thicker line after Ch-2
            ('LINEAFTER', (8, 0), (8, -1), 0.5, colors.black),
            ('LINEAFTER', (11, 0), (11, -1), 0.5,
             colors.black),   # Thicker line after Ch-3
            ('LINEAFTER', (14, 0), (14, -1), 0.5,
             colors.black),   # Thicker line after Ch-4
            ('LINEAFTER', (17, 0), (17, -1), 0.5,
             colors.black),   # Thicker line after Ch-5
            ('LINEAFTER', (20, 0), (20, -1), 0.5,
             colors.black),   # Thicker line after Ch-6
            ('LINEAFTER', (23, 0), (23, -1), 0.5,
             colors.black),   # Thicker line after Ch-7
            ('LINEAFTER', (26, 0), (26, -1), 0.5,
             colors.black),   # Thicker line after Ch-8
            ('LINEAFTER', (29, 0), (29, -1), 0.5,
             colors.black),   # Thicker line after Ch-9
            ('LINEAFTER', (32, 0), (32, -1), 0.5,
             colors.black),   # Thicker line after Ch-9

            # Center alignment for merged headers
            ('ALIGN', (3, 0), (5, 0), 'CENTER'),
            ('ALIGN', (6, 0), (8, 0), 'CENTER'),
            ('ALIGN', (9, 0), (11, 0), 'CENTER'),
            ('ALIGN', (12, 0), (14, 0), 'CENTER'),
            ('ALIGN', (15, 0), (17, 0), 'CENTER'),
            ('ALIGN', (18, 0), (20, 0), 'CENTER'),
            ('ALIGN', (21, 0), (23, 0), 'CENTER'),
            ('ALIGN', (24, 0), (26, 0), 'CENTER'),
            ('ALIGN', (27, 0), (29, 0), 'CENTER'),
            ('ALIGN', (30, 0), (32, 0), 'CENTER'),

        ])

        # Define the table with updated colWidths
        # Define the table with updated colWidths
        col_widths = [30, 45, 45] + [23] * len(temperature_headers)

        # Create table
        table = Table(data, colWidths=col_widths, repeatRows=2)
        table.setStyle(table_style)

        return table

    content = [
        Spacer(1, 0.1 * inch),
        mkt_table(),

    ]

    # Build the document
    doc.build(
        content,
        onFirstPage=create_page,
        onLaterPages=create_page,
        canvasmaker=NumberedCanvas)
    return response


def about_us(request):
    emp_user = request.session.get('username', None)
    acc_dept=None
    if not emp_user:
        return redirect('login')
    try:
        data = User.objects.get(username=emp_user)
    except User.DoesNotExist:
        data = SuperAdmin.objects.get(username=emp_user)
        acc_dept=Department.objects.all()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    return render(request, 'About_us/about_us.html',
                  {'data': data, 'acc_db': acc_db})
