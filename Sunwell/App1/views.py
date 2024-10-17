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
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Spacer
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from django.core.mail import send_mail
from django.shortcuts import render
from django.http import HttpResponse
from App1.emailsms import get_email_settings


def base(request):
    return render(request, 'Base/base.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            super_admin = SuperAdmin.objects.get(username__iexact=username.lower())
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
    username = request.session.get('username')
    
    if request.method == 'POST':
        username_1 = request.POST.get('username')
        old_pass = request.POST.get('old_pass')
        new_pass = request.POST.get('new_pass')

        user = None
        for u in User.objects.all():
            if u.check_login_name(username_1):  
                user = u
                break

        if user and check_password(old_pass, user.password):
            user.password = new_pass
            user.pass_change = True
            user.created_at = timezone.now() + timedelta(hours=5, minutes=30)
            user.save()

            UserActivityLog.objects.create(
                user=user.username,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"User {user.username} changed password"
            ) 

            success_msg_2 = 'Your password has been changed. Please login again'
            return render(request, 'Base/login.html', {'success_msg_2': success_msg_2})

        else:
            error_msg = 'Please enter valid credentials.'
            return render(request, 'Base/login.html', {'error_msg': error_msg})
        

def change_pass_2(request): 
    username = request.session.get('username') 

    data = User.objects.get(username = username)   
    
    if request.method == 'POST':
        username_1 = request.POST.get('username')
        old_pass = request.POST.get('old_pass')
        new_pass = request.POST.get('new_pass')
  
        if  check_password(username_1, data.login_name):
            if  check_password(old_pass, data.password):
                data.password = new_pass
                data.pass_change = True
                data.created_at = timezone.now() + timedelta(hours=5, minutes=30)
                data.save()

                UserActivityLog.objects.create(
                    user=username,
                    log_date=timezone.localtime(timezone.now()).date(),
                    log_time=timezone.localtime(timezone.now()).time(),
                    event_name=f"User {data.username} changed password"
                ) 

                if username:
                    request.session.flush()

                return JsonResponse({'message': 'Your password has been changed. Please login again'})  
        else:
            return JsonResponse({'message': 'Please enter valid credentials.'})  
        

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
        logo = request.FILES['logo']

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
    

    organization = Organization.objects.first()  # Fetch the first Organization object
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

    organization = get_object_or_404(Organization, id=organization_id)
    
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
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    # Generate the new soft key
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

        new_commgroup = CommGroup(
            CommGroup_name=comm_name,
            CommGroup_code=comm_code,
            soft_key=soft_key,
            activation_key=activation_key,
        )
        new_commgroup.save()

        # Log the add event
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new comm.group {comm_name} details"
        )

        return redirect('comm_group')

    comm_groups = CommGroup.objects.all()
    return render(request, 'Management/comm_group.html', {'organization': organization, 'comm_groups': comm_groups, 'data': data, 'acc_db': acc_db, 'soft_key': soft_key})

import logging
from django.http import JsonResponse
from .utils import get_motherboard_serial_number, decode_soft_key
from .utils import decode_from_custom_base62

def validate_activation_key(request):
    if request.method == 'POST':
        entered_activation_key = request.POST.get('activation_key')
        entered_soft_key = request.POST.get('soft_key')
        print("entered_activation_key",entered_activation_key)

        try:
            # Fetch the motherboard serial number from the current machine
            current_pc_serial_no = get_motherboard_serial_number()
            # print(current_pc_serial_no)

            if not current_pc_serial_no:
                raise ValueError("Unable to fetch motherboard serial number")

            # Decode the soft key and compare the serial number
            decoded_soft_pc_serial_no = decode_soft_key(entered_soft_key)
            # print("decoded_soft_pc_serial_no", decoded_soft_pc_serial_no)
            if decoded_soft_pc_serial_no != current_pc_serial_no:
                return JsonResponse({'validation_icon': '✖', 'message': "Soft Key's PC/Server Serial No does not match the current machine"})
            else:
                # Decode the activation key and compare the serial number
                decoded_activation_string = decode_from_custom_base62(entered_activation_key)
                parts = decoded_activation_string.split('-IIIQBETS-')
                print(parts)
                print('parts', parts[1][0:2])
                if len(parts) != 2:
                    return JsonResponse({'validation_icon': '✖', 'message': "Invalid Activation Key format"})

                decoded_activation_pc_serial_no = parts[0]
                print("decoded_activation_pc_serial_no", decoded_activation_pc_serial_no)

                # Check if all serial numbers match
                if decoded_activation_pc_serial_no != current_pc_serial_no:
                    return JsonResponse({'validation_icon': '✖', 'message': "Activation Key's PC/Server Serial No does not match the current machine"})

                # If all validations pass, return success
                return JsonResponse({'validation_icon': '✔', 'message': "Validation successful"})

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


    if request.method == "POST":
        department_name = request.POST.get('departmentName')
        commgroup_code = request.POST.get('commGroup')
        header_note = request.POST.get('headerNote')
        footer_note = request.POST.get('footerNote')

        commgroup = CommGroup.objects.get(CommGroup_name=commgroup_code)

        new_department = Department(
            department_name=department_name,
            commGroup=commgroup,
            header_note=header_note,
            footer_note=footer_note,
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


    department = get_object_or_404(Department, id=department_id)
    if request.method == "POST":
        department_name = request.POST.get('edit_dept_name')  
        commgroup_name = request.POST.get('edit_commGroup')
        header_note = request.POST.get('edit_headerNote')
        footer_note = request.POST.get('edit_footerNote')
        report_datetime_stamp = request.POST.get('edit_report_datetime_stamp')

        if not department_name:
            # Handle the missing department name error
            return render(request, 'Management/department.html', {
                'department': department,
                'organization': organization, 'data':data, 'acc_db':acc_db,
                'groups': CommGroup.objects.all(),
                'error': 'Department name is required.'
            })

        commgroup = get_object_or_404(CommGroup, CommGroup_name=commgroup_name)
        
        # Update the department
        department.department_name = department_name
        department.commGroup = commgroup
        department.header_note = header_note
        department.footer_note = footer_note
        department.report_datetime_stamp = report_datetime_stamp
        department.save()

        # Log the edit event
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Updated department {department_name} details"
        )

        return redirect('department')

    groups = CommGroup.objects.all()
    context = {
        'department': department,
        'groups': groups,
        'organization': organization, 'data':data, 'acc_db':acc_db
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


        if login_name:
            user.set_login_name(login_name)  

    
        if password:
            user.set_password(password)  

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
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    return render(request, 'Management/app_settings.html', {'organization': organization, 'data':data, 'acc_db':acc_db})

def send_email(request):
    if request.method == 'POST':
        recipient_email = request.POST.get('testemail')
        print(recipient_email,'recipient_email')

        # Fetch the email settings dynamically
        email_settings = get_email_settings(request)
        if not email_settings:
            return HttpResponse("Email settings are not configured.", status=500)
        
        subject='Sun Well'
        message = 'Welcome to Sun Well'


        # Set the dynamic email settings
        from django.conf import settings
        settings.EMAIL_HOST = email_settings['EMAIL_HOST']
        settings.EMAIL_HOST_USER = email_settings['EMAIL_HOST_USER']
        settings.EMAIL_HOST_PASSWORD = email_settings['EMAIL_HOST_PASSWORD']
        settings.EMAIL_PORT = email_settings['EMAIL_PORT']

        print(settings.EMAIL_HOST,'settings.EMAIL_HOST')

        # Send the email
        send_mail(
            subject=subject,  # Email subject
            message=message,  # Email message
            from_email=email_settings['EMAIL_HOST_USER'],  # Sender's email from dynamic settings
            recipient_list=[recipient_email],  # Recipient's email
            fail_silently=False,
        )

        return redirect('app_settings')

        #return HttpResponse("Email sent successfully.")

def email_form(request):
    # Handle POST request
    if request.method == 'POST':
        email_alert = request.POST.get('email_alert')
        email_time = request.POST.get('email_time')

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



        email_form = EmailForm(
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
        email_form.save()
        return redirect('department')

        
    else:
        pass

def email_settings(request):
    # Handle POST request
    if request.method == 'POST':
        smptemail = request.POST.get('smptemail')
        smtpPort = request.POST.get('smtpPort')
        smptuser = request.POST.get('smptuser')
        smptpass = request.POST.get('smptpass')
        selected_qc = request.session['selected_qc']

        try:
            # Get the Department instance using the name stored in session
            department_name = Department.objects.get(department_name=selected_qc)
        except Department.DoesNotExist:
            messages.error(request, 'Selected department does not exist.')
            return redirect('app_settings')

        # Check if an AppSettings already exists for the selected department
        if not AppSettings.objects.filter(department=department_name).exists():
            # Create and save AppSettings instance
            app_email_settings = AppSettings(
                department=department_name,  # Use the Department instance here
                email_host=smptemail,
                email_port=smtpPort,
                email_host_user=smptuser,
                email_host_password=smptpass
            )
            app_email_settings.save()
            return redirect('app_settings')
        else:
            messages.error(request, 'App Setting with the selected department already exists.')
            return redirect('app_settings')

    # If the request is not POST, handle other cases
    return redirect('app_settings')

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

@csrf_exempt  # Handle CSRF token manually (already done in JS)
def save_qc_session(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            qc_value = data.get('qc_value')
            
            request.session['selected_qc'] = qc_value  
            print(request.session['selected_qc'],'session')
            return JsonResponse({'success': True})
        except Exception as e:
            return JsonResponse({'success': False, 'error': str(e)})
    return JsonResponse({'success': False})


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
    
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None


    if request.method == 'POST':
        local_path = request.POST.get('backup-local-path')
        remote_path = request.POST.get('backup-remote-path')
        backup_time = request.POST.get('backup-time')

        # Create or update the backup settings
        backup_setting, created = BackupSettings.objects.update_or_create(
            local_path=local_path,
            defaults={
                'remote_path': remote_path,
                'backup_time': backup_time
            }
        )

        # Log the backup settings update
        UserActivityLog.objects.create(
            user=emp_user,
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name="Updated backup settings"
        )

        messages.success(request, 'Backup settings saved successfully!')
        return redirect('backup')

    # Fetch the existing backup settings (if any)
    backup_setting = BackupSettings.objects.first()  # Get the first or handle appropriately
    context = {
        'local_path': backup_setting.local_path if backup_setting else '',
        'remote_path': backup_setting.remote_path if backup_setting else '',
        'backup_time': backup_setting.backup_time if backup_setting else '00:00',
        'organization': organization, 'data':data, 'acc_db':acc_db
    }
    return render(request, 'Management/backup.html', context)


# def schedule_daily_backup():
#     print("Scheduler thread started")
#     backup_setting = BackupSettings.objects.last()
#     if backup_setting and backup_setting.backup_time:
        
#         backup_time_str = backup_setting.backup_time.strftime("%H:%M")
#         print(f"Scheduling daily backup at {backup_time_str}")

#         # Schedule backup at the specified time
#         schedule.every().day.at(backup_time_str).do(perform_backup)

#         while True:
#             schedule.run_pending()
#             time.sleep(1)

# def start_backup_scheduler():
#     print("Starting backup scheduler")
#     backup_thread = threading.Thread(target=schedule_daily_backup, daemon=True)
#     backup_thread.start()

# start_backup_scheduler()


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
        interval = request.POST.get('interval')
        equipment_type = request.POST.get('equiptype')
        door_access_type = request.POST.get('dooracctype')

        # Save equipment details
        equipment = Equipment(
            equip_name=equip_name,
            status=status,
            ip_address=ip_address,
            interval=interval,
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
        data = User.objects.get(username = emp_user)
    except:
        data = SuperAdmin.objects.get(username=emp_user)
    organization = Organization.objects.first()
    
    try:
        acc_db = user_access_db.objects.get(role = data.role)
    except:
        acc_db = None

    return render(request, 'Data_Analysis/view_logs.html', {'organization': organization, 'data':data, 'acc_db':acc_db})


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
        canvas.drawCentredString(300, 780, "Report for QC")

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
