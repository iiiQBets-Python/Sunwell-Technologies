from datetime import datetime, time, timedelta, timezone, date
import time  
import threading
from urllib import request
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


def base(request):
    return render(request, 'Base/base.html', )

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            super_admin = SuperAdmin.objects.get(username__iexact=username)
            if check_password(password, super_admin.password):
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
                user = None
                for u in User.objects.all():
                    if u.check_login_name(username):  
                        user = u
                        break


                if user and check_password(password, user.password):

                    password_expiry_date = user.created_at + timedelta(days=user.password_duration)
                    current_time = timezone.now()
             
                    if current_time > password_expiry_date:
                        success_msg = 'Your password has expired. Please change it.'
                        return render(request, 'Base/login.html', {'success_msg': success_msg})

                    if user.pass_change == False:
                        success_msg = 'Please set a new password.'
                        return render(request, 'Base/login.html', {'success_msg': success_msg})
                    
                    request.session['username'] = user.username
                    messages.success(request, 'Login Successful!')
                    
                                    
                    # Log the login event for User
                    UserActivityLog.objects.create(
                        user=user,
                        log_date=timezone.localtime(timezone.now()).date(),
                        log_time=timezone.localtime(timezone.now()).time(),
                        event_name=f"User {user.username} logged in"
                    )
                    return redirect('dashboard')              
                else:   
                    messages.error(request, 'Invalid Username or Password!')
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
        
  
        # Check if the provided username and old password are correct
        if check_password(username_1, data.login_name) and check_password(old_pass, data.password):
            # Check if the new password matches any of the last 3 passwords
            password_history = PasswordHistory.objects.filter(user=data).order_by('-created_at')[:3]
            if any(check_password(new_pass, history.password) for history in password_history):
                return JsonResponse({'message': 'New password cannot be the same as any of the last 3 passwords.'})

            # Update the password if no match is found in the last 3 entries
            user.password = new_pass
            data.password = make_password(new_pass)
            data.pass_change = True
            data.created_at = timezone.now() + timedelta(hours=5, minutes=30)
            data.save()


            # Log the password change
            UserActivityLog.objects.create(
                user=data.username,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"User {data.username} changed password"
            )

            # Check if user has 3 entries in PasswordHistory
            password_history = PasswordHistory.objects.filter(user=data).order_by('created_at')
            if password_history.count() >= 3:
                # If there are already 3 entries, replace the oldest entry
                oldest_entry = password_history.first()
                oldest_entry.password = data.password
                oldest_entry.created_at = timezone.now()
                oldest_entry.save()
            else:
                # If fewer than 3 entries, create a new entry
                PasswordHistory.objects.create(user=data, password=data.password)
            
            # Flush the session
            success_msg_2 = 'Your password has been changed. Please login again'
            return render(request, 'Base/login.html', {'success_msg_2': success_msg_2})  
        else:
            error_msg = 'Please enter valid credentials.'
            return render(request, 'Base/login.html', {'error_msg': error_msg}) 
        

def change_pass_2(request): 
    username = request.session.get('username') 
    data = User.objects.get(username=username)   
    
    if request.method == 'POST':
        username_1 = request.POST.get('username')
        old_pass = request.POST.get('old_pass')
        new_pass = request.POST.get('new_pass')
  
        # Check if the provided username and old password are correct
        if check_password(username_1, data.login_name) and check_password(old_pass, data.password):
            # Check if the new password matches any of the last 3 passwords
            password_history = PasswordHistory.objects.filter(user=data).order_by('-created_at')[:3]
            if any(check_password(new_pass, history.password) for history in password_history):
                return JsonResponse({'message': 'New password cannot be the same as any of the last 3 passwords.'})

            # Update the password if no match is found in the last 3 entries
            data.password = make_password(new_pass)
            data.pass_change = True
            data.created_at = timezone.now() + timedelta(hours=5, minutes=30)
            data.save()

            # Log the password change
            UserActivityLog.objects.create(
                user=username,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"User {data.username} changed password"
            )

            # Check if user has 3 entries in PasswordHistory
            password_history = PasswordHistory.objects.filter(user=data).order_by('created_at')
            if password_history.count() >= 3:
                # If there are already 3 entries, replace the oldest entry
                oldest_entry = password_history.first()
                oldest_entry.password = data.password
                oldest_entry.created_at = timezone.now()
                oldest_entry.save()
            else:
                # If fewer than 3 entries, create a new entry
                PasswordHistory.objects.create(user=data, password=data.password)

            # Flush the session
            if username:
                request.session.flush()

            return JsonResponse({'message': 'Your password has been changed. Please login again'})  
        else:
            return JsonResponse({'message': 'Please enter valid credentials.'})    

def forgot_password(request):
    if request.method == 'POST':
        login_name = request.POST.get('forgot_username')
        old_password = request.POST.get('forgot_old_password')
        new_password = request.POST.get('forgot_new_password')
        confirm_password = request.POST.get('forgot_confirm_password')

        # Check if a user with the given login name exists
        for user in User.objects.all():
            if check_password(login_name, user.login_name):
                user = user
                break

        # Fetch the last 3 passwords from PasswordHistory
        password_history = PasswordHistory.objects.filter(user=user).order_by('-created_at')[:3]

        # Check if old_password matches any of the last 3 passwords
        if not any(history.check_password(old_password) for history in password_history):
            return JsonResponse({'message': 'The old password does not match any of the last 3 passwords.'}, status=403)

        # Validate new password and confirm password match
        if new_password != confirm_password:
            return JsonResponse({'message': 'New password and confirm password do not match.'}, status=400)

        # Check if new password is not among the last 3 passwords
        if any(history.check_password(new_password) for history in password_history):
            return JsonResponse({'message': 'New password cannot be the same as any of the last 3 passwords.'}, status=400)

        # Hash and set the new password
        hashed_new_password = make_password(new_password)
        user.password = hashed_new_password
        user.pass_change = True
        user.created_at = timezone.now()
        user.save()

        # Update password history
        PasswordHistory.objects.create(user=user, password=new_password)

        # Log the password reset event (optional)
        UserActivityLog.objects.create(
            user=user.username,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"User {user.username} reset password"
        )

        # Redirect to login page with a success message
        return JsonResponse({'message':"Your password has been reset successfully. Please log in with your new password."})
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


# dashboard
def dashboard(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None
    return render(request, 'Dashboard/Dashboard.html', {'organization': organization, 'data':data, 'acc_db':acc_db})



# Management-organization
def organization(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username = emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    if request.method == 'POST':
        # Saving the changes
        name = request.POST.get('name')
        email = request.POST.get('email')
        phoneNo = request.POST.get('phoneNo')
        address = request.POST.get('address')        
        logo = request.FILES.get('logo')

        Organization_new = Organization(
            name = name,
            email = email,
            phoneNo = phoneNo,
            address = address,
            logo = logo
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
    return render(request, 'Management/organization.html', {'organization': organization, 'data':data, 'acc_db':acc_db})

def edit_organization(request, organization_id):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
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

    return render(request, 'Management/edit_organization.html', {'organization': organization, 'data':data, 'acc_db':acc_db})

def comm_group(request):
    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    soft_key = generate_soft_key()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    if request.method == "POST":
        comm_name = request.POST.get('comm_name')
        comm_code = request.POST.get('comm_code')
        soft_key = request.POST.get('softKey')
        activation_key = request.POST.get('activationKey')
        device_count = int(request.POST.get('device_count', 0))  # Get validated device count from form input

        # Calculate the new total devices and save it to Organization’s nod
        current_nod = organization.get_nod()
        print("Cnod", current_nod)
        total_devices = current_nod + device_count
        organization.set_nod(total_devices)
        organization.save()
        print("td", organization.get_nod())

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

        return redirect('comm_group')

    comm_groups = CommGroup.objects.all()
    return render(request, 'Management/comm_group.html', {
        'organization': organization,
        'comm_groups': comm_groups,
        'data': data,
        'acc_db': acc_db,
        'soft_key': soft_key
    })


def validate_activation_key(request):
    if request.method == 'POST':
        emp_user = request.session.get('username', None)
        try:
            data = User.objects.get(username=emp_user)
        except:
            data = SuperAdmin.objects.get(username=emp_user)
        
        entered_activation_key = request.POST.get('activation_key')
        entered_soft_key = request.POST.get('soft_key')

        try:
            if CommGroup.objects.filter(activation_key=entered_activation_key).exists():
                return JsonResponse({'validation_icon': '✖', 'message': "Activation key already exists and cannot be reused"})

            current_pc_serial_no = get_motherboard_serial_number()

            if not current_pc_serial_no:
                raise ValueError("Unable to fetch motherboard serial number")

            decoded_soft_pc_serial_no = decode_soft_key(entered_soft_key)

            if decoded_soft_pc_serial_no != current_pc_serial_no:
                return JsonResponse({'validation_icon': '✖', 'message': "Soft Key's PC/Server Serial No does not match the current machine"})

            decoded_activation_string = decode_from_custom_base62(entered_activation_key)
            
            parts = decoded_activation_string.split('-')
            
            if len(parts) != 7 or parts[1] != "IQBST" or parts[3] != "IIIQBETS" or parts[5] != "SUNWELL":
                return JsonResponse({'validation_icon': '✖', 'message': "Invalid Activation Key format"})

            decoded_activation_pc_serial_no = parts[2]
            device_count = int(parts[4])

            if decoded_activation_pc_serial_no != current_pc_serial_no:
                return JsonResponse({'validation_icon': '✖', 'message': "Activation Key's PC/Server Serial No does not match the current machine"})

            return JsonResponse({'validation_icon': '✔', 'message': "Validation successful", 'device_count': device_count})

        except Exception as e:
            return JsonResponse({'validation_icon': '✖', 'message': f"Validation failed: {str(e)}"})

    return JsonResponse({'validation_icon': '✖', 'message': "Invalid request method"})

def edit_comm_group(request, comm_code):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None


    comm_group = get_object_or_404(CommGroup, CommGroup_code=comm_code)

    if request.method == "POST":
        comm_name = request.POST.get('edit_comm_name')
        soft_key = request.POST.get('edit_softKey')
        activation_key = request.POST.get('edit_activationKey')

        # Update the CommGroup instance
        comm_group.CommGroup_name = comm_name
        comm_group.soft_key = soft_key
        comm_group.activation_key = activation_key
        comm_group.save()

        # Log the edit event
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Updated {comm_name} Comm. Group details"
        )

        return redirect('comm_group')

    return render(request, 'Management/comm_group.html', {'organization': organization,'comm_groups':comm_group, 'data':data, 'acc_db':acc_db})


def department(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    try:
        comm_group = CommGroup.objects.get(CommGroup_code=commgroup_name)
    except:
        comm_group = None   


    if request.method == "POST":
        department_name = request.POST.get('departmentName')
        commgroup_name = request.POST.get('commGroup')
        header_note = request.POST.get('headerNote')
        footer_note = request.POST.get('footerNote')
        report_datetime_stamp = request.POST.get('report_datetime_stamp') == 'True'

        email_alert = request.POST.get('email_alert')
        email_time = request.POST.get('email_time')  or None

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

        
        comm_group = CommGroup.objects.get(CommGroup_code=commgroup_name)
        

        new_department = Department(
            department_name=department_name,
            commGroup=comm_group,
            header_note=header_note,
            footer_note=footer_note,
            report_datetime_stamp=report_datetime_stamp,
            
            email_alert = email_alert,
            email_time = email_time,
            alert_email_address_1 = email_address_1,
            alert_email_address_2 = email_address_2,
            alert_email_address_3 = email_address_3,
            alert_email_address_4 = email_address_4,
            alert_email_address_5 = email_address_5,
            alert_email_address_6 = email_address_6,
            alert_email_address_7 = email_address_7,
            alert_email_address_8 = email_address_8,
            alert_email_address_9 = email_address_9,
            alert_email_address_10 = email_address_10,

        )
        new_department.save()

        # Log the add event
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new department {department_name} details"
        )

        return redirect('department')
    
    departments = Department.objects.all()
    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups,
        'organization': organization, 'data':data, 'acc_db':acc_db
    }
    
    return render(request, 'Management/department.html', context)

def edit_department(request, department_id):
    departments = get_object_or_404(Department, id=department_id)
    if request.method == "POST":
        department_name = request.POST.get('edit_dept_name')  # Correct field name
        commgroup_name = request.POST.get('edit_commGroup')
        header_note = request.POST.get('edit_headerNote')
        footer_note = request.POST.get('edit_footerNote')
        report_datetime_stamp = request.POST.get('edit_report_datetime_stamp') == 'True'  

        email_alert = request.POST.get('edit_email_alert')
        email_time = request.POST.get('edit_email_time')  or None

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

        if not department_name:
            # Handle the missing department name error
            return render(request, 'Management/department.html', {
                'department': department,
                'groups': CommGroup.objects.all(),
                'error': 'Department name is required.'
            })

        commgroup = get_object_or_404(CommGroup, CommGroup_name=commgroup_name)
        
        # Update the department
        departments.department_name = department_name
        departments.commGroup = commgroup
        departments.header_note = header_note
        departments.footer_note = footer_note
        departments.report_datetime_stamp = report_datetime_stamp

        departments.email_alert = email_alert
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
        
        departments.save()

        # Log the edit event
        UserActivityLog.objects.create(
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Edited Department {department_name} details"
        )

        return redirect('department')

    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups,
    }

    return render(request, 'Management/department.html', context)

def users(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None
    
    try:
        role_data = User_role.objects.all()
    except:
        role_data = None


    if request.method == 'POST':
        username = request.POST.get('userName')
        login_name = request.POST.get('loginName')
        password = request.POST.get('password')
        password_duration = request.POST.get('passwordDuration')
        role = request.POST.get('role')
        comm_group = request.POST.get('commGroup')
        departmentname = request.POST.get('departmentName')
        status = request.POST.get('status')
        accessible_departments = request.POST.getlist('accessibleDepartment')

        commgroup = CommGroup.objects.get(CommGroup_code=comm_group)
        department = Department.objects.get(id=departmentname)

        newuser = User(
            username=username,
            login_name=login_name,
            password=password,
            password_duration=password_duration,
            role=role,
            commGroup=commgroup,
            department=department,
            status=status,
            created_at = timezone.now() + timedelta(hours=5, minutes=30)
        )
        newuser.save()

        if accessible_departments:
            selected_departments = Department.objects.filter(id__in=accessible_departments)
            newuser.accessible_departments.set(selected_departments)

        # Handle password history
        password_history = PasswordHistory.objects.filter(user=newuser).order_by('created_at')
        if password_history.count() >= 3:
            # If there are already 3 entries, replace the oldest entry
            oldest_entry = password_history.first()
            oldest_entry.password = password
            oldest_entry.created_at = timezone.now()
            oldest_entry.save()
        else:
            # If fewer than 3 entries, create a new entry
            PasswordHistory.objects.create(user=newuser, password=password)

        # Log the add event
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new user {username} details"
        )

        return redirect('users')

    users = User.objects.all()
    departments = Department.objects.all()
    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups,
        'users': users,
        'organization': organization, 'data':data, 'acc_db':acc_db, 'role_data':role_data
    }
    return render(request, 'Management/user.html', context)

def edit_user(request, user_id):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None
    
    try:
        role_data = User_role.objects.all()
    except:
        role_data = None


    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':

        username = request.POST.get('editUsername')
        login_name = request.POST.get('editLoginName')
        password = request.POST.get('editPassword')
        password_duration = request.POST.get('editpasswordDuration')
        role = request.POST.get('editRole')
        comm_group_code = request.POST.get('editCommGroup')
        department_id = request.POST.get('editdepartmentName')
        status = request.POST.get('editstatus')
        accessible_departments = request.POST.getlist('editaccessibleDepartment')


        comm_group = get_object_or_404(CommGroup, CommGroup_code=comm_group_code)
        department = get_object_or_404(Department, id=department_id)

 
        user.username = username
        user.password = password
        user.password_duration = password_duration
        user.role = role
        user.commGroup = comm_group
        user.department = department
        user.status = status
        user.save() 


        if accessible_departments:
            selected_departments = Department.objects.filter(id__in=accessible_departments)
            user.accessible_departments.set(selected_departments)
        else:
            user.accessible_departments.clear()

        password_history = PasswordHistory.objects.filter(user=user).order_by('created_at')
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

        return redirect('users')


    departments = Department.objects.all()
    groups = CommGroup.objects.all()


    context = {
        'user': user,
        'departments': departments,
        'groups': groups,
        'organization': organization, 'data':data, 'acc_db':acc_db, 'role_data':role_data
    }


    return render(request, 'Management/user.html', context)

def role_permission(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None
    
    try:
        role_data = User_role.objects.all()
    except:
        role_data = None
    
    if request.method == 'POST':
        role = request.POST.get('role')
        description = request.POST.get('description')
    
        if role_data:
            for i in role_data:
                if i.role == role:
                    error_msg = 'This {} has already in use.'.format(role)
                    return render(request, 'Management/role_permission.html', {'data':data, 'organization':organization, 'acc_db':acc_db, 'role_data':role_data, 'error_msg':error_msg})

        role_new = User_role(
            role = role,
            description = description,
        )  
        role_new.save() 

        user_access_new = user_access_db(
            role = role,
            org_v = True,
            c_group_v = True,
            dep_v = True,
            role_v = True,
            user_v = True,
            app_v = True,
            back_v = True,
            sys_v = True,
            res_v = True
        )
        user_access_new.save()

        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new {role} role"
        ) 

        success_msg = 'Role is added successfully.'
        return redirect('role_permission')

    return render(request, 'Management/role_permission.html', {'organization': organization, 'data':data, 'acc_db':acc_db, 'role_data':role_data})

def edit_role(request, role_id):
    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    try:
        role_data = User_role.objects.all()
    except:
        role_data = None

    role_instance = get_object_or_404(User_role, id=role_id)

    if request.method == 'POST':

        role_name = request.POST.get('role')
        description = request.POST.get('description')

        if User_role.objects.filter(role=role_name).exclude(id=role_id).exists():
            error_msg = f'The role {role_name} already exists.'
            return render(request, 'Management/edit_role.html', {
                'role_instance': role_instance, 
                'organization': organization, 
                'data': data, 
                'acc_db': acc_db, 
                'role_data': role_data, 
                'error_msg': error_msg
            })


        role_instance.role = role_name
        role_instance.description = description
        role_instance.save()


        try:
            access_instance = user_access_db.objects.get(role=role_instance.role)
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

        success_msg = 'Role updated successfully.'
        return redirect('role_permission')
    context={
                'role_instance': role_instance, 
                'organization': organization, 
                'data': data, 
                'acc_db': acc_db, 
                'role_data': role_data
            }
    return render(request, 'Management/edit_role.html', context)

def user_access(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()

    role = request.GET.get('role', None)
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    try:
        role_dt = user_access_db.objects.get(role = role)
    except:
        role_dt = None


    print(role)
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

            role_dt.save()

            UserActivityLog.objects.create(
                user=emp_user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name="Role and permissions updated"
            )

            success_msg = 'Roles and permissions are updated.'
            return render(request, 'Management/user_group.html', {'organization': organization, 'data': data, 'acc_db': acc_db, 'role_dt':role_dt, 'success_msg': success_msg})

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
            return render(request, 'Management/user_group.html', {'organization': organization, 'data': data, 'acc_db': acc_db, 'role_dt':role_dt, 'success_msg': success_msg})

    return render(request, 'Management/user_group.html', {'organization': organization, 'data':data, 'acc_db':acc_db, 'role_dt':role_dt,})


def app_settings(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username=emp_user)
    except User.DoesNotExist:
        data = SuperAdmin.objects.get(username=emp_user)

    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except user_access_db.DoesNotExist:
        acc_db = None

    if request.method == 'POST':

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
        messages.success(request, 'Application settings saved successfully!')
        return redirect('app_settings')

    # Fetch the existing settings
    app_email_settings = AppSettings.objects.first()
    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'app_settings': app_email_settings
    }

    return render(request, 'Management/app_settings.html', context)


def app_sms_settings(request):
    emp_user = request.session.get('username', None)

    try:
        data = User.objects.get(username=emp_user)
    except User.DoesNotExist:
        data = SuperAdmin.objects.get(username=emp_user)

    organization = Organization.objects.first()
    acc_db = user_access_db.objects.filter(role=data.role).first()

    if request.method == 'POST':
        sms_sys_set = request.POST.get('sms_setting_status')
        comm_port = request.POST.get('commport')
        parity = request.POST.get('parity')
        baud_rate = request.POST.get('baudrate')
        data_bits = request.POST.get('databits')
        stop_bits = request.POST.get('stopbits')
        flow_control = request.POST.get('flowcontrol')

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
                'flow_control': flow_control
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
        return redirect('app_sms_settings')

    # Fetch the existing SMS settings
    app_sms_settings = AppSettings.objects.first()
    context = {
        'organization': organization,
        'data': data,
        'acc_db': acc_db,
        'app_settings': app_sms_settings
    }

    return render(request, 'Management/app_settings.html', context)

import serial
import time
from django.shortcuts import redirect
from django.contrib import messages
from .models import AppSettings

def send_test_sms(request):
    if request.method == 'POST':
        # Get the test phone number from the POST request
        test_sms_number = request.POST.get('testsms')
        if not test_sms_number:
            messages.error(request, "Please provide a valid phone number.")
            return redirect('app_sms_settings')

        # Fetch SMS settings from the database
        sms_settings = AppSettings.objects.first()
        if not sms_settings:
            messages.error(request, "SMS settings not configured.")
            return redirect('app_sms_settings')

        try:
            # Modem Configuration
            comm_port = sms_settings.comm_port
            baud_rate = int(sms_settings.baud_rate)
            parity = serial.PARITY_NONE if sms_settings.parity == 'None' else sms_settings.parity.upper()[0]
            data_bits = serial.EIGHTBITS
            stop_bits = serial.STOPBITS_ONE if sms_settings.stop_bits == 1 else serial.STOPBITS_TWO
            message = "Test SMS from Django Project"

            # Initialize Serial Connection
            ser = serial.Serial(
                port=comm_port,
                baudrate=baud_rate,
                bytesize=data_bits,
                parity=parity,
                stopbits=stop_bits,
                timeout=2
            )

            def send_command(command, wait_for_response=True, delay=2):
                """Send a command to the modem and optionally wait for a response."""
                ser.write(command.encode() + b'\r')
                ser.flush()
                time.sleep(delay)  # Allow time for the modem to process
                if wait_for_response:
                    response = ser.read(1000).decode(errors="ignore").strip()
                    return response
                return ""

            # Send Initialization Commands
            if "OK" not in send_command("AT"):
                messages.error(request, "Modem not responding to 'AT' command. Check your connection.")
                ser.close()
                return redirect('app_sms_settings')

            if "OK" not in send_command("AT+CMGF=1"):  # Set SMS mode to text
                messages.error(request, "Failed to set SMS mode to text.")
                ser.close()
                return redirect('app_sms_settings')

            # Send SMS
            response = send_command(f'AT+CMGS="{test_sms_number}"', wait_for_response=True, delay=2)
            if ">" not in response:
                messages.error(request, "Modem did not prompt for message input.")
                ser.close()
                return redirect('app_sms_settings')

            # Send the message and terminate with Ctrl+Z
            ser.write((message + '\r').encode())
            ser.flush()
            time.sleep(1)  # Brief pause before sending Ctrl+Z
            ser.write(b"\x1A")  # Ctrl+Z
            ser.flush()

            # Wait for final response
            time.sleep(5)
            response = ser.read(1000).decode(errors="ignore").strip()

            if "+CMGS" in response and "OK" in response:
                messages.success(request, f"Test SMS sent successfully to {test_sms_number}.")
            else:
                messages.error(request, f"Failed to send SMS. Detailed response: {response}")

            ser.close()

        except Exception as e:
            messages.error(request, f"Error sending SMS: {str(e)}")
            return redirect('app_sms_settings')

        # Redirect back to settings page after successful execution
        return redirect('app_sms_settings')
    else:
        messages.error(request, "Invalid request method.")
        return redirect('app_sms_settings')

def send_test_email(request):
    if request.method == 'POST':
        recipient_email = request.POST.get('testemail')
        email_time = request.POST.get('testemailtime')
        
        # Fetch the email settings dynamically
        email_settings = get_email_settings(request)
        if not email_settings:
            return HttpResponse("Email settings are not configured.", status=500)
        
        subject = 'Sun Well'
        message = 'Welcome to Sun Well'

        # Set the dynamic email settings
        settings.EMAIL_HOST = email_settings['EMAIL_HOST']
        settings.EMAIL_HOST_USER = email_settings['EMAIL_HOST_USER']
        settings.EMAIL_HOST_PASSWORD = email_settings['EMAIL_HOST_PASSWORD']
        settings.EMAIL_PORT = email_settings['EMAIL_PORT']

        # Function to send the email
        def send_email():
            send_mail(
                subject=subject,
                message=message,
                from_email=email_settings['EMAIL_HOST_USER'],
                recipient_list=[recipient_email],
                fail_silently=False,
            )

        # Calculate delay if time is provided
        if email_time:
            # Parse the provided time
            email_datetime = datetime.strptime(email_time, "%H:%M").time()
            now = datetime.now().time()
            
            # Combine the date with the time for full datetime comparison
            today_date = date.today()
            email_datetime_full = datetime.combine(today_date, email_datetime)
            now_full = datetime.combine(today_date, now)
            
            # Calculate delay in seconds
            delay = (email_datetime_full - now_full).total_seconds()

            # If delay is negative, schedule the email for the next day
            if delay < 0:
                email_datetime_full += timedelta(days=1)
                delay = (email_datetime_full - now_full).total_seconds()

            # Schedule email with delay
            threading.Timer(delay, send_email).start()
        else:
            # Send email immediately if no time is provided
            send_email()

        return redirect('app_settings')
    else:
        return HttpResponse("Invalid request method.", status=405)
    

def perform_backup():
    backup_setting = BackupSettings.objects.last()
    if not backup_setting:
        print("No backup settings found.")
        return "failure", "No backup settings found."

    current_time = datetime.now().strftime("%d%m%Y_%H%M")
    backup_filename = f"ESTDAS_{current_time}.bak"

    local_backup_file_path = os.path.join(backup_setting.local_path, backup_filename)
    remote_backup_file_path = os.path.join(backup_setting.remote_path, backup_filename) if backup_setting.remote_path else None

    # Remove all existing .bak files in the local path
    for file_name in os.listdir(backup_setting.local_path):
        if file_name.endswith(".bak"):
            os.remove(os.path.join(backup_setting.local_path, file_name))

    # Remove all existing .bak files in the remote path if it exists
    if backup_setting.remote_path:
        for file_name in os.listdir(backup_setting.remote_path):
            if file_name.endswith(".bak"):
                os.remove(os.path.join(backup_setting.remote_path, file_name))

    db_settings = settings.DATABASES['default']
    db_name = db_settings['NAME']
    db_user = db_settings['USER']
    db_password = db_settings['PASSWORD']
    db_host = db_settings['HOST']

    local_backup_command = (
        f"sqlcmd -S {db_host} -U {db_user} -P {db_password} "
        f"-Q \"BACKUP DATABASE [{db_name}] TO DISK = N'{local_backup_file_path}'\""
    )
    
    try:
        subprocess.run(local_backup_command, check=True, shell=True)
        print("Local backup successful")

        if backup_setting.remote_path:
            remote_backup_command = (
                f"sqlcmd -S {db_host} -U {db_user} -P {db_password} "
                f"-Q \"BACKUP DATABASE [{db_name}] TO DISK = N'{remote_backup_file_path}'\""
            )
            subprocess.run(remote_backup_command, check=True, shell=True)
            print("Remote backup successful")
            
        return "success", "Backup successful"
    except subprocess.CalledProcessError as e:
        print(f"Backup failed: {str(e)}")
        return "failure", f"Backup failed: {str(e)}"

def download_backup(request):
    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    status, message = perform_backup()
    
    UserActivityLog.objects.create(
        user=emp_user,
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name=f"Downloaded database backup"
    )
    return JsonResponse({"status": status, "message": message})

def backup(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None


    if request.method == 'POST':
        local_path = request.POST.get('backup-local-path')
        remote_path = request.POST.get('backup-remote-path')
        backup_time = request.POST.get('backup-time')

        # Create or update the backup settings
        backup_setting= BackupSettings(
            local_path=local_path,
                remote_path = remote_path,
                backup_time= backup_time
        )
        backup_setting.save()

        # Log the backup settings update
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name="Added backup settings"
        )

        messages.success(request, 'Backup settings saved successfully!')
        return redirect('backup')
    
    backup_setting = BackupSettings.objects.first()
    context={
        
        'data':data,
        'acc_db':acc_db,
        'backup_setting': backup_setting
    }
      # Get the first or handle appropriately
    
    return render(request, 'Management/backup.html', context)

def edit_backup(request, id):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    backup_setting = BackupSettings.objects.first()
    if request.method == 'POST':
        
        backup_setting.local_path = request.POST.get('backup-local-path')
        backup_setting.remote_path = request.POST.get('backup-remote-path')
        backup_setting.backup_time = request.POST.get('backup-time')

        backup_setting.save()

        # Log the backup settings update
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name="Updated backup settings"
        )

        messages.success(request, 'Updated Backup settings successfully!')
        return redirect('backup')
    
    context={
        'backup_setting':backup_setting, 'data':data, 'acc_db':acc_db
    }

    # Fetch the existing backup settings (if any)
      # Get the first or handle appropriately
    return render(request, 'Management/edit_backup.html', context)


def schedule_daily_backup():
    print("Scheduler thread started")
    backup_setting = BackupSettings.objects.last()
    if backup_setting and backup_setting.backup_time:
        
        backup_time_str = backup_setting.backup_time.strftime("%H:%M")
        print(f"Scheduling daily backup at {backup_time_str}")

        # Schedule backup at the specified time
        schedule.every().day.at(backup_time_str).do(perform_backup)

        while True:
            schedule.run_pending()
            time.sleep(1)

def start_backup_scheduler():
    print("Starting backup scheduler")
    backup_thread = threading.Thread(target=schedule_daily_backup, daemon=True)
    backup_thread.start()

start_backup_scheduler()


def restore(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    return render(request, 'Management/restore.html', {'organization': organization, 'data':data, 'acc_db':acc_db})



# Settings
def equipment_configure_view(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    if request.method == 'POST':
        equip_name = request.POST.get('equipname')
        status = request.POST.get('equipStatus')
        ip_address = request.POST.get('ipaddress')
        department_id = request.POST.get('selected_department')
        interval = request.POST.get('interval')
        equipment_type = request.POST.get('equiptype')
        door_access_type = request.POST.get('dooracctype')

        print("Acess Dept", department_id)
        # Save equipment details
        equipment = Equipment(
            equip_name=equip_name,
            status=status,
            ip_address=ip_address,
            interval=interval,
            department_id=department_id,
            equipment_type=equipment_type,
            door_access_type=door_access_type
        )
        equipment.save()

        # Handle PLC users if PLC is selected
        if door_access_type == 'plc':
            for i in range(1, 16):
                user = request.POST.get(f'plc_user_{i}')
                if user:
                    plc_user = PLCUser(equipment=equipment, username=user)
                    plc_user.save()

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
                    biometric_user = BiometricUser(equipment=equipment, username=user, card_number=card)
                    biometric_user.save()

        # Log the equipment addition
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new equipment {equip_name}"
        )

        messages.success(request, 'Equipment added successfully!')
        return redirect('equipment_configure')

    equipment_list = Equipment.objects.all()
    return render(request, 'Equip_Settings/equip_config.html', {
        'equipment_list': equipment_list,
        'organization': organization,
        'data': data
    })


def equipment_setting(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    return render(request, 'Equip_Settings/equip_settings.html', {'organization': organization, 'data':data, 'acc_db':acc_db})


# DATA Analysis


def view_log(request):
    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    equipment_list = Equipment.objects.all()

    # Get filter parameters from the request
    selected_equipment = request.GET.get('equipment')
    from_date = request.GET.get('from-date')
    to_date = request.GET.get('to-date')
    from_time = request.GET.get('from-time') or '00:00'  # Default to '00:00' if empty
    to_time = request.GET.get('to-time') or '23:59'      # Default to '23:59' if empty

    filter_kwargs = Q()

    # Filter by equipment if selected
    if selected_equipment:
        filter_kwargs &= Q(equip_name__equip_name=selected_equipment)

    # Handle missing dates - default to the 1st of the current month and today's date
    current_date = now().date()
    if not from_date:
        from_date = current_date.replace(day=1).strftime('%Y-%m-%d')  # 1st of the current month
    if not to_date:
        to_date = current_date.strftime('%Y-%m-%d')  # Today's date

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
            (Q(date=from_date_parsed) & Q(time__gte=from_time_parsed)) |  # from_time on from_date
            (Q(date=to_date_parsed) & Q(time__lte=to_time_parsed)) |      # to_time on to_date
            Q(date__gt=from_date_parsed, date__lt=to_date_parsed)         # all dates in between
        )

    # Fetch the filtered temperature and humidity records
    data_logs = TemperatureHumidityRecord.objects.filter(filter_kwargs).order_by('date', 'time')
    eqp_list = Equipment.objects.filter(status='Active')
    
    # Handle PDF generation if requested
    if 'generate_pdf' in request.GET:
        # Determine the number of temperature and humidity columns
        equipment_records = TemperatureHumidityRecord.objects.filter(equip_name__equip_name=selected_equipment)
        temperature_channels = ['tmp_1', 'tmp_2', 'tmp_3', 'tmp_4', 'tmp_5', 'tmp_6', 'tmp_7', 'tmp_8', 'tmp_9', 'tmp_10']
        humidity_channels = ['rh_1', 'rh_2', 'rh_3', 'rh_4', 'rh_5', 'rh_6', 'rh_7', 'rh_8', 'rh_9', 'rh_10']

        active_temperature_channels = [channel for channel in temperature_channels if any(getattr(record, channel) is not None for record in equipment_records)]
        active_humidity_channels = [channel for channel in humidity_channels if any(getattr(record, channel) is not None for record in equipment_records)]

        # Check if both temperature and humidity columns exceed 5
        if len(active_temperature_channels) > 5 and len(active_humidity_channels) > 5:
            # Call the landscape mode PDF generator if both exceed 5
            return generate_log_pdf_landscape(
                request,
                data_logs,
                from_date_parsed.strftime('%d-%m-%Y'),
                to_date_parsed.strftime('%d-%m-%Y'),
                from_time_parsed.strftime('%H:%M'),
                to_time_parsed.strftime('%H:%M'),
                organization,
                data.department,
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
                data.department,
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
    })


def generate_log_pdf(request, records, from_date, to_date, from_time, to_time, organization, department, username, selected_equipment):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="equipment_log_report.pdf"'

    doc = SimpleDocTemplate(response, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=160, bottomMargin=60)
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
        
    def create_page(canvas, doc):

        page_num = canvas.getPageNumber()
        total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')

        # Set the title and logo
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        canvas.drawCentredString(300, 800, organization.name)
        
        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        canvas.drawCentredString(300, 780, department.header_note)

        logo_path = organization.logo.path
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
        canvas.drawString(30, 690, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(400, 690, f"Records To: {records_to_date} {records_to_time}")
        
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
        footer_right_top = department.footer_note
        footer_right_bottom = f"Page {page_num} of {total_pages}"
        
        # Draw footer at the bottom of the page
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_left_top)
        canvas.drawString(30, 35, footer_left_bottom)
        canvas.drawCentredString(300, 40, footer_center)
        canvas.drawRightString(570, 45, footer_right_top)
        canvas.drawRightString(570, 35, footer_right_bottom)  
        
    def add_alarm_tables():

        equipment = TemperatureHumidityRecord.objects.filter(equip_name__equip_name=selected_equipment).first()
        # Data for Temperature and Humidity Alarms
        alarm_data = [['Parameter', 'Low Alarm', 'Low Alert', 'High Alarm', 'High Alert']]

        if equipment and (equipment.t_low_alarm is not None or equipment.t_high_alarm is not None):
            alarm_data.append([
                'Temperature (°C)',
                f"{equipment.t_low_alarm:.1f}" if equipment.t_low_alarm is not None else 'N/A',
                f"{equipment.t_low_alert:.1f}" if equipment.t_low_alert is not None else 'N/A',
                f"{equipment.t_high_alarm:.1f}" if equipment.t_high_alarm is not None else 'N/A',
                f"{equipment.t_high_alert:.1f}" if equipment.t_high_alert is not None else 'N/A',
            ])

        # Add humidity data if it exists
        if equipment and (equipment.rh_low_alarm is not None or equipment.rh_high_alarm is not None):
            alarm_data.append([
                'Humidity (% RH)',
                f"{equipment.rh_low_alarm:.1f}" if equipment.rh_low_alarm is not None else 'N/A',
                f"{equipment.rh_low_alert:.1f}" if equipment.rh_low_alert is not None else 'N/A',
                f"{equipment.rh_high_alarm:.1f}" if equipment.rh_high_alarm is not None else 'N/A',
                f"{equipment.rh_high_alert:.1f}" if equipment.rh_high_alert is not None else 'N/A',
            ])


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

        # Define column widths
        col_widths = [130, 80, 80, 80, 80]  # Adjust column widths as needed

        # Create the alarm table
        alarm_table = Table(alarm_data, colWidths=col_widths)
        alarm_table.setStyle(alarm_table_style)


        return alarm_table

    def add_temperature_table():
        # Initialize lists for temperature and humidity data
        temperature_channels = ['tmp_1', 'tmp_2', 'tmp_3', 'tmp_4', 'tmp_5', 'tmp_6', 'tmp_7', 'tmp_8', 'tmp_9', 'tmp_10']
        humidity_channels = ['rh_1', 'rh_2', 'rh_3', 'rh_4', 'rh_5', 'rh_6', 'rh_7', 'rh_8', 'rh_9', 'rh_10']
        
        temp_data = [['Temperature (°C)', 'Minimum', 'Maximum', 'Average']]
        humidity_data = [['Humidity (% RH)', 'Minimum', 'Maximum', 'Average']]

        # Dynamically calculate min, max, and average for temperature channels
        for channel in temperature_channels:
            channel_values = [getattr(record, channel) for record in records if getattr(record, channel) is not None]
            if channel_values:
                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                temp_data.append([channel.capitalize(), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])

        # Calculate min, max, and average for each humidity channel in the filtered records
        for channel in humidity_channels:
            channel_values = [getattr(record, channel) for record in records if getattr(record, channel) is not None]
            if channel_values:
                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                humidity_data.append([channel.capitalize(), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])

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
        col_widths = [130, 80, 120]  # Adjust column widths as needed

        # Create the temperature table
        temp_table = Table(temp_data, colWidths=col_widths)
        temp_table.setStyle(table_style)
        humidity_table = None
        if len(humidity_data) > 1:
            # Create the humidity table
            humidity_table = Table(humidity_data, colWidths=col_widths)
            humidity_table.setStyle(table_style)

        return [temp_table, Spacer(1, 0.2 * inch), humidity_table] if humidity_table else [temp_table]
    
    from reportlab.lib import colors
    from reportlab.platypus import Paragraph
    from reportlab.lib.styles import ParagraphStyle

    def add_main_table():
        # Define styles for normal and bold text
        normal_style = ParagraphStyle('Normal', fontName='Helvetica', fontSize=10)
        bold_style = ParagraphStyle('Bold', fontName='Helvetica-Bold', fontSize=10)

        temperature_channels = ['tmp_1', 'tmp_2', 'tmp_3', 'tmp_4', 'tmp_5', 'tmp_6', 'tmp_7', 'tmp_8', 'tmp_9', 'tmp_10']
        humidity_channels = ['rh_1', 'rh_2', 'rh_3', 'rh_4', 'rh_5', 'rh_6', 'rh_7', 'rh_8', 'rh_9', 'rh_10']

        active_humidity_channels = [channel for channel in humidity_channels if any(getattr(record, channel) is not None for record in records)]
        active_humidity_channels = active_humidity_channels[:5] if active_humidity_channels else []
        active_temperature_channels = temperature_channels[:5] if active_humidity_channels else temperature_channels[:10]

        temperature_header = ['Ch-' + str(i+1) for i in range(len(active_temperature_channels))]
        humidity_header = ['Ch-' + str(i+1) for i in range(5)] if active_humidity_channels else []

        if active_humidity_channels:
            data = [
                [' ', 'Date', 'Time', 'Set'] + ['-----Temperature(°C)-----'] + [''] * (len(temperature_header) - 1) +
                ['Set'] + ['-----Humidity(%RH)-----'] + [''] * (len(humidity_header) - 1),
                ['Rec No', 'DD-MM-YYYY', 'HH:MM', 'Temp'] + temperature_header + ['Rh'] + humidity_header
            ]
        else:
            data = [
                [' ', 'Date', 'Time', 'Set'] + ['-----Temperature(°C)-----'] + [''] * (len(temperature_header) - 1),
                ['Rec No', 'DD-MM-YYYY', 'HH:MM', 'Temp'] + temperature_header
            ]

        equipment = records.filter(equip_name__equip_name=selected_equipment).first()
        if equipment:
            t_low_alarm = equipment.t_low_alarm 
            t_high_alarm = equipment.t_high_alarm 
            t_low_alert = equipment.t_low_alert
            t_high_alert = equipment.t_high_alert
            rh_low_alarm = equipment.rh_low_alarm 
            rh_high_alarm = equipment.rh_high_alarm
            rh_low_alert = equipment.rh_low_alert
            rh_high_alert = equipment.rh_high_alert
        else:
            t_low_alarm = t_high_alarm = rh_low_alarm = rh_high_alarm = None
            t_low_alert = t_high_alert = rh_low_alert = rh_high_alert = None

        for idx, record in enumerate(records, start=1):
            temp_values = []
            for channel in active_temperature_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    if value <= t_low_alarm or value >= t_high_alarm:
                        # Bold for values outside alarm range
                        temp_values.append(Paragraph(f"<b>{value:.1f}</b>", bold_style))
                    elif (t_low_alarm < value <= t_low_alert) or (t_high_alarm <= value < t_high_alert):
                        # Underline for values within alert range
                        temp_values.append(Paragraph(f"<u>{value:.1f}</u>", normal_style))
                    else:
                        temp_values.append(Paragraph(f"{value:.1f}", normal_style))
                else:
                    temp_values.append('')

            humidity_values = []
            for channel in active_humidity_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    if value <= rh_low_alarm or value >= rh_high_alarm:
                        # Bold for values outside alarm range
                        humidity_values.append(Paragraph(f"<b>{value:.1f}</b>", bold_style))
                    elif (rh_low_alarm < value <= rh_low_alert) or (rh_high_alarm <= value < rh_high_alert):
                        # Underline for values within alert range
                        humidity_values.append(Paragraph(f"<u>{value:.1f}</u>", normal_style))
                    else:
                        humidity_values.append(Paragraph(f"{value:.1f}", normal_style))
                else:
                    humidity_values.append('')

            row = [
                str(idx),
                record.date.strftime('%d-%m-%Y'),
                record.time.strftime('%H:%M'),
                Paragraph(f"{record.set_temp:.1f}", normal_style) if record.set_temp is not None else ''
            ] + temp_values + [
                Paragraph(f"{record.set_rh:.1f}", normal_style) if record.set_rh is not None else ''
            ] + humidity_values

            data.append(row)

        main_table_style = TableStyle([
            ('SPAN', (4, 0), (3 + len(temperature_header), 0)),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 1), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
        ])

        if active_humidity_channels:
            main_table_style.add('SPAN', (4 + len(temperature_header) + 1, 0), (3 + len(temperature_header) + len(humidity_header) + 1, 0))

        # return current_row
        colWidths = [40, 70, 44, 42] + [32] * len(temperature_header) + ([32] + [32] * len(humidity_header) if active_humidity_channels else [])
        main_table = Table(data, colWidths=colWidths, repeatRows=2)
        main_table.setStyle(main_table_style)

        return main_table


    content = [
        Spacer(1, 0.2 * inch),
        add_alarm_tables(),
        Spacer(1, 0.2 * inch),
        *add_temperature_table(),
        PageBreak(),
        add_main_table(),
    ]

    doc.build(content, onFirstPage=create_page, onLaterPages=create_page)
    return response


def generate_log_pdf_landscape(request, records, from_date, to_date, from_time, to_time, organization, department, username, selected_equipment):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="equipment_log_report.pdf"'
    
    doc = SimpleDocTemplate(response, pagesize=landscape(A4), rightMargin=30, leftMargin=30, topMargin=160, bottomMargin=60)
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

    # c = canvas.Canvas(response, pagesize=landscape(A4))

    def create_page(canvas, doc):

        page_num = canvas.getPageNumber()
        total_pages = doc.page
        current_time = localtime().strftime('%d-%m-%Y %H:%M')

        # Set the title and logo
        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        canvas.drawString(350, 570, organization.name)

        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        canvas.drawString(370, 550, department.header_note)
        
        logo_path = organization.logo.path
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

        canvas.drawString(30, 460, f"Records From: {records_from_date} {records_from_time}")
        canvas.drawString(600, 460, f"Records To: {records_to_date} {records_to_time}")
        
        # Draw separator line above the new table
        canvas.setLineWidth(0.5)
        canvas.line(13, 440, 830, 440)  # Line above the new table

        # Add a line above the footer
        canvas.setLineWidth(1)
        canvas.line(13, 60, 830, 60)  # Line just above the footer

        # Add footer with page number
        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = f"Printed By - {username} on {datetime.now().strftime('%d-%m-%Y %H:%M')}"  # Centered dynamic text
        footer_text_right_top = department.footer_note
        footer_text_right = f"Page {page_num}"
        
        # Draw footer at the bottom of the page
        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)  # Draw "Sunwell"
        canvas.drawString(30, 35, footer_text_left_bottom)  # Draw "ESTDAS v1.0" below "Sunwell"
        canvas.drawCentredString(420, 40, footer_text_center)  # Centered
        canvas.drawRightString(800, 45, footer_text_right_top)
        canvas.drawRightString(800, 35, footer_text_right)  # Right side (page number)

    def add_alarm_tables():
        equipment = TemperatureHumidityRecord.objects.filter(equip_name__equip_name=selected_equipment).first()
        # Data for Temperature and Humidity Alarms
        alarm_data = [['Parameter', 'Low Alarm', 'Low Alert', 'High Alarm', 'High Alert']]

        if equipment and (equipment.t_low_alarm is not None or equipment.t_high_alarm is not None):
            alarm_data.append([
                'Temperature (°C)',
                f"{equipment.t_low_alarm:.1f}" if equipment.t_low_alarm is not None else 'N/A',
                f"{equipment.t_low_alert:.1f}" if equipment.t_low_alert is not None else 'N/A',
                f"{equipment.t_high_alarm:.1f}" if equipment.t_high_alarm is not None else 'N/A',
                f"{equipment.t_high_alert:.1f}" if equipment.t_high_alert is not None else 'N/A',
            ])

        # Add humidity data if it exists
        if equipment and (equipment.rh_low_alarm is not None or equipment.rh_high_alarm is not None):
            alarm_data.append([
                'Humidity (% RH)',
                f"{equipment.rh_low_alarm:.1f}" if equipment.rh_low_alarm is not None else 'N/A',
                f"{equipment.rh_low_alert:.1f}" if equipment.rh_low_alert is not None else 'N/A',
                f"{equipment.rh_high_alarm:.1f}" if equipment.rh_high_alarm is not None else 'N/A',
                f"{equipment.rh_high_alert:.1f}" if equipment.rh_high_alert is not None else 'N/A',
            ])

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

        # Define column widths
        col_widths = [210, 130, 130, 130, 130]  # Adjust column widths as needed

        # Create the alarm table
        alarm_table = Table(alarm_data, colWidths=col_widths)
        alarm_table.setStyle(alarm_table_style)

        return alarm_table


    def add_temperature_table():
        
        
        # Initialize lists for temperature and humidity data
        temperature_channels = ['tmp_1', 'tmp_2', 'tmp_3', 'tmp_4', 'tmp_5', 'tmp_6', 'tmp_7', 'tmp_8', 'tmp_9', 'tmp_10']
        humidity_channels = ['rh_1', 'rh_2', 'rh_3', 'rh_4', 'rh_5', 'rh_6', 'rh_7', 'rh_8', 'rh_9', 'rh_10']
        
        temp_data = [['Temperature (°C)', 'Minimum', 'Maximum', 'Average']]
        humidity_data = [['Humidity (% RH)', 'Minimum', 'Maximum', 'Average']]

        # Dynamically calculate min, max, and average for temperature channels
        for channel in temperature_channels:
            channel_values = [getattr(record, channel) for record in records if getattr(record, channel) is not None]
            if channel_values:
                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                temp_data.append([channel.capitalize(), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])

        # Dynamically calculate min, max, and average for humidity channels if data exists
        for channel in humidity_channels:
            channel_values = [getattr(record, channel) for record in records if getattr(record, channel) is not None]
            if channel_values:
                min_val = min(channel_values)
                max_val = max(channel_values)
                avg_val = sum(channel_values) / len(channel_values)
                humidity_data.append([channel.capitalize(), f"{min_val:.1f}", f"{max_val:.1f}", f"{avg_val:.1f}"])

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
        [[temp_table, Spacer(1, 0.2 * inch), humidity_table]],  # Spacer to add space between the tables
        colWidths=[290, 100, 350]  # Adjust widths to align both tables with the full width
        )

        return combined_table

    def add_main_table():
        # Define styles for normal and bold text
        normal_style = ParagraphStyle('Normal', fontName='Helvetica', fontSize=10)
        bold_style = ParagraphStyle('Bold', fontName='Helvetica-Bold', fontSize=10)


        temperature_channels = ['tmp_1', 'tmp_2', 'tmp_3', 'tmp_4', 'tmp_5', 'tmp_6', 'tmp_7', 'tmp_8', 'tmp_9', 'tmp_10']
        humidity_channels = ['rh_1', 'rh_2', 'rh_3', 'rh_4', 'rh_5', 'rh_6', 'rh_7', 'rh_8', 'rh_9', 'rh_10']

        equipment = records.filter(equip_name__equip_name=selected_equipment).first()
        if equipment:
            t_low_alarm = equipment.t_low_alarm
            t_high_alarm = equipment.t_high_alarm
            t_low_alert = equipment.t_low_alert
            t_high_alert = equipment.t_high_alert
            rh_low_alarm = equipment.rh_low_alarm
            rh_high_alarm = equipment.rh_high_alarm
            rh_low_alert = equipment.rh_low_alert
            rh_high_alert = equipment.rh_high_alert
        else:
            t_low_alarm = t_high_alarm = rh_low_alarm = rh_high_alarm = None
            t_low_alert = t_high_alert = rh_low_alert = rh_high_alert = None

        
        # Prepare the main table headers
        data = [
            [' ', 'Date', 'Time', 'Set', '<---------Temperature(°C)--------->', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', 'Set', '<---------Humidity(%RH)--------->', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' '],
            ['Rec No', 'DD-MM-YYYY', 'HH:MM', 'Temp', 'Ch-1', 'Ch-2', 'Ch-3', 'Ch-4', 'Ch-5', 'Ch-6', 'Ch-7', 'Ch-8', 'Ch-9', 'Ch-10', 'Rh', 'Ch-1', 'Ch-2', 'Ch-3', 'Ch-4', 'Ch-5', 'Ch-6', 'Ch-7', 'Ch-8', 'Ch-9', 'Ch-10']
        ]

        # Populate the table with filtered records
        for idx, record in enumerate(records, start=1):
            temp_values = []
            for channel in temperature_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    # Bold for alarm values
                    if value <= t_low_alarm or value >= t_high_alarm:
                        temp_values.append(Paragraph(f"<b>{value:.1f}</b>", bold_style))
                    # Underline for alert values
                    elif (t_low_alarm < value <= t_low_alert) or (t_high_alarm <= value < t_high_alert):
                        temp_values.append(Paragraph(f"<u>{value:.1f}</u>", normal_style))
                    else:
                        temp_values.append(Paragraph(f"{value:.1f}", normal_style))
                else:
                    temp_values.append('')

            humidity_values = []
            for channel in humidity_channels:
                value = getattr(record, channel, None)
                if value is not None:
                    # Bold for alarm values
                    if value <= rh_low_alarm or value >= rh_high_alarm:
                        humidity_values.append(Paragraph(f"<b>{value:.1f}</b>", bold_style))
                    # Underline for alert values
                    elif (rh_low_alarm < value <= rh_low_alert) or (rh_high_alarm <= value < rh_high_alert):
                        humidity_values.append(Paragraph(f"<u>{value:.1f}</u>", normal_style))
                    else:
                        humidity_values.append(Paragraph(f"{value:.1f}", normal_style))
                else:
                    humidity_values.append('')

            # Construct the row with dynamic data
            row = [
                str(idx),
                record.date.strftime('%d-%m-%Y'),
                record.time.strftime('%H:%M'),
                Paragraph(f"{record.set_temp:.1f}", normal_style) if record.set_temp is not None else ''
            ] + temp_values + [
                Paragraph(f"{record.set_rh:.1f}", normal_style) if record.set_rh is not None else ''
            ] + humidity_values

            data.append(row)

        main_table_style = TableStyle([
            ('SPAN', (4, 0), (13, 0)),
            ('SPAN', (15, 0), (24, 0)),
            ('BACKGROUND', (0, 1), (-1, 1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, 1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 1), 12),
            ('TOPPADDING', (0, 0), (-1, 0), 12),
        ])

        colWidths = [29, 55, 36, 32] + [32] * 10 + [32] + [32] * 10
        main_table = Table(data, colWidths=colWidths, repeatRows=2)
        main_table.setStyle(main_table_style)

        return main_table

    content = [
        Spacer(1, 0.2 * inch),
        add_alarm_tables(),
        Spacer(1, 0.2 * inch),
        add_temperature_table(),
        PageBreak(),
        add_main_table(),
    ]

    doc.build(content, onFirstPage=create_page, onLaterPages=create_page)
    return response   


def alaram_log(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    return render(request, 'Data_Analysis/alaram_log.html', {'organization': organization, 'data':data, 'acc_db':acc_db})

# Live data
def livedata_summary(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    return render(request, 'Live Data/realtime_summary.html', {'organization': organization, 'data':data, 'acc_db':acc_db})


def user_activity(request):
    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username=emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()

    try:
        acc_db = user_access_db.objects.get(role=data.role)
    except:
        acc_db = None

    filter_format = request.GET.get('format')  # "Date Wise" or "User-wise"
    from_date = request.GET.get('from-date')
    to_date = request.GET.get('to-date')
    from_time = request.GET.get('from-time')
    to_time = request.GET.get('to-time')
    users = request.GET.getlist('user-list')  # For user-wise filtering
    event_name = request.GET.get('event-name')

    filter_kwargs = Q()

    if filter_format == 'Date Wise':
        if from_date and to_date:
            from_date_parsed = parse_date(from_date)
            to_date_parsed = parse_date(to_date)

            from_time_parsed = parse_time(from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(to_time) if to_time else datetime_time(23, 59, 59)

            # Combine date and time into datetime objects for accurate filtering
            from_datetime = make_aware(datetime.combine(from_date_parsed, from_time_parsed))
            to_datetime = make_aware(datetime.combine(to_date_parsed, to_time_parsed))

            # Apply the datetime filter to the combined datetime field
            filter_kwargs &= Q(log_date__gte=from_date_parsed) & Q(log_date__lte=to_date_parsed)
            filter_kwargs &= Q(log_time__gte=from_time_parsed) & Q(log_time__lte=to_time_parsed)
        else:
            return HttpResponse("From Date and To Date are mandatory for Date Wise format.", status=400)

    elif filter_format == 'User Wise':
        if users:
            user_names = User.objects.filter(id__in=users).values_list('username', flat=True)
            filter_kwargs &= Q(user__in=user_names)

            current_date = now()
            from_date_parsed = parse_date(from_date) if from_date else current_date.replace(day=1).date()
            to_date_parsed = parse_date(to_date) if to_date else current_date.date()

            from_time_parsed = parse_time(from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(to_time) if to_time else datetime_time(23, 59, 59)

            # Combine date and time into datetime objects for accurate filtering
            from_datetime = make_aware(datetime.combine(from_date_parsed, from_time_parsed))
            to_datetime = make_aware(datetime.combine(to_date_parsed, to_time_parsed))

            filter_kwargs &= Q(log_date__gte=from_date_parsed) & Q(log_date__lte=to_date_parsed)
            filter_kwargs &= Q(log_time__gte=from_time_parsed) & Q(log_time__lte=to_time_parsed)
        else:
            return HttpResponse("User List is mandatory for User-wise format.", status=400)

    if event_name:
        filter_kwargs &= Q(event_name__icontains=event_name)

    # Directly filter on `log_date` and `log_time` without combining them into a datetime
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
            data.department,
            data.username,
            filter_format
        )

    context = {
        'user_logs': user_logs,
        'user_list': user_list,
        'organization': organization,
        'data': data,
        'acc_db': acc_db
    }

    return render(request, 'auditlog/user_audit_log.html', context)


def generate_userActivity_pdf(request, user_logs, from_date, to_date, from_time, to_time, organization, department, username, filter_format):
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="user_audit_report.pdf"'

    doc = SimpleDocTemplate(response, pagesize=A4, rightMargin=30, leftMargin=30, topMargin=160, bottomMargin=60)
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

    # PDF Header/Footer
    def header_footer(canvas, doc, from_date, to_date, from_time, to_time, department, organization, username, page_num, total_pages):
        current_time = localtime()
        formatted_time = current_time.strftime('%d-%m-%Y %H:%M')

        from_date_formatted = datetime.strptime(from_date, '%Y-%m-%d').strftime('%d-%m-%Y')
        to_date_formatted = datetime.strptime(to_date, '%Y-%m-%d').strftime('%d-%m-%Y')

        canvas.setFont("Helvetica-Bold", 14)
        canvas.setFillColor(colors.blue)
        canvas.drawCentredString(300, 800, organization.name)
        canvas.setFillColor(colors.black)
        canvas.setFont("Helvetica", 12)
        canvas.drawCentredString(300, 780, department.header_note)

        logo_path = organization.logo.path
        canvas.drawImage(logo_path, 470, 780, width=80, height=30)

        canvas.setLineWidth(0.5)
        canvas.line(30, 770, 570, 770)

        canvas.setFont("Helvetica-Bold", 12)
        if filter_format == 'Date Wise':
            canvas.drawCentredString(300, 750, "User Audit Trail Report Date Wise")
        elif filter_format == 'User Wise':
            canvas.drawCentredString(300, 750, "User Audit Trail Report User Wise")

        canvas.setFont("Helvetica-Bold", 10)
        # Display filter range
        canvas.drawString(30, 730, "Filter From: {} {}".format(from_date_formatted, from_time))
        canvas.drawString(420, 730, "Filter To: {} {}".format(to_date_formatted, to_time))

        # Display records range
        canvas.drawString(30, 705, "Records From: {} {}".format(records_from_date, records_from_time))
        canvas.drawString(420, 705, "Records To: {} {}".format(records_to_date, records_to_time))

        canvas.setLineWidth(0.5)
        canvas.line(30, 60, 570, 60)

        footer_text_left_top = "Sunwell"
        footer_text_left_bottom = "ESTDAS v1.0"
        footer_text_center = "Printed By - {} on {}".format(username, formatted_time)
        footer_text_right_top = department.footer_note 
        footer_text_right_bottom = f"Page {page_num} of {total_pages}"

        canvas.setFont("Helvetica", 10)
        canvas.drawString(30, 45, footer_text_left_top)
        canvas.drawString(30, 35, footer_text_left_bottom)
        canvas.drawCentredString(300, 40, footer_text_center)
        canvas.drawRightString(570, 45, footer_text_right_top)
        canvas.drawRightString(570, 35, footer_text_right_bottom)

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
        header_footer(canvas, doc, from_date, to_date, from_time, to_time, department, organization, username, 1, total_pages)
        
    def later_pages(canvas, doc):
        header_footer(canvas, doc, from_date, to_date, from_time, to_time, department, organization, username, doc.page, total_pages)

    doc.build(
        content,
        onFirstPage=first_page,
        onLaterPages=later_pages
    )

    return response


def equipment_Audit_log(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None
    return render(request, 'auditlog/equipment_audit.html', {'organization': organization, 'data':data, 'acc_db':acc_db})


def alaram_Audit_log(request):

    emp_user = request.session.get('username', None)
    try:
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    return render(request, 'auditlog/alaram_audit.html', {'organization': organization, 'data':data, 'acc_db':acc_db})


import csv
from django.urls import reverse
from django.contrib import messages
from django.core.files.storage import default_storage
from datetime import datetime

def upload_csv(request):
    if request.method == "POST":
        equip_id = request.POST.get('equip_name')
        csv_file = request.FILES.get("csv_file")
        
        if not csv_file.name.endswith('.csv'):
            messages.error(request, 'File is not CSV type')
            return redirect(reverse('upload_csv'))

        try:
            equip_name = Equipment.objects.get(id=equip_id)
        except Equipment.DoesNotExist:
            messages.error(request, 'Selected equipment not found')
            return redirect(reverse('upload_csv'))

        file_path = default_storage.save(csv_file.name, csv_file)
        file_path = default_storage.path(file_path)
        
        with open(file_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    # Convert date from DD-MM-YYYY to YYYY-MM-DD
                    date_str = row['Date']
                    formatted_date = datetime.strptime(date_str, '%d-%m-%Y').date()

                    TemperatureHumidityRecord.objects.create(
                        equip_name=equip_name,
                        date=formatted_date,
                        time=row['Time'] if 'Time' in row else None,
                        set_temp=row['Set Temp'],
                        t_low_alarm=row['T Low Alarm'],
                        t_low_alert=row['T Low Alert'],
                        t_high_alarm=row['T High Alarm'],
                        t_high_alert=row['T High Alert'],
                        tmp_1=row['Tmp 1'] if 'Tmp 1' in row else None,
                        tmp_2=row['Tmp 2'] if 'Tmp 2' in row else None,
                        tmp_3=row['Tmp 3'] if 'Tmp 3' in row else None,
                        tmp_4=row['Tmp 4'] if 'Tmp 4' in row else None,
                        tmp_5=row['Tmp 5'] if 'Tmp 5' in row else None,
                        tmp_6=row['Tmp 6'] if 'Tmp 6' in row else None,
                        tmp_7=row['Tmp 7'] if 'Tmp 7' in row else None,
                        tmp_8=row['Tmp 8'] if 'Tmp 8' in row else None,
                        tmp_9=row['Tmp 9'] if 'Tmp 9' in row else None,
                        tmp_10=row['Tmp 10'] if 'Tmp 10' in row else None,
                        set_rh=row['Set RH'] if 'Set RH' in row else None,
                        rh_low_alarm=row['RH Low Alarm'] if 'RH Low Alarm' in row else None,
                        rh_low_alert=row['RH Low Alert'] if 'RH Low Alert' in row else None,
                        rh_high_alarm=row['RH High Alarm'] if 'RH High Alarm' in row else None,
                        rh_high_alert=row['RH High Alert'] if 'RH High Alert' in row else None,
                        rh_1=row['RH 1'] if 'RH 1' in row else None,
                        rh_2=row['RH 2'] if 'RH 2' in row else None,
                        rh_3=row['RH 3'] if 'RH 3' in row else None,
                        rh_4=row['RH 4'] if 'RH 4' in row else None,
                        rh_5=row['RH 5'] if 'RH 5' in row else None,
                        rh_6=row['RH 6'] if 'RH 6' in row else None,
                        rh_7=row['RH 7'] if 'RH 7' in row else None,
                        rh_8=row['RH 8'] if 'RH 8' in row else None,
                        rh_9=row['RH 9'] if 'RH 9' in row else None,
                        rh_10=row['RH 10'] if 'RH 10' in row else None,
                    )
                except ValueError as e:
                    messages.error(request, f"Error processing row: {row}. {str(e)}")
                    return redirect(reverse('upload_csv'))

        messages.success(request, "CSV file uploaded and records saved.")
        return redirect(reverse('upload_csv'))

    equipment = Equipment.objects.all()
    return render(request, 'upload_csv.html', {'equipment': equipment})
