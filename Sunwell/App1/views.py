from datetime import datetime, timezone 
import time  
import threading
from urllib import request
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
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.platypus import Table, TableStyle
from reportlab.lib import colors
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import A4
from reportlab.lib.enums import TA_LEFT
from reportlab.lib import colors
from reportlab.platypus.tables import Table, TableStyle


def base(request):
    return render(request, 'Base/base.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            super_admin = SuperAdmin.objects.get(sa_username__iexact=username.lower())
            if check_password(password, super_admin.sa_password):
                request.session['username'] = super_admin.sa_username
                messages.success(request, 'Login Successful!')
                
                # Log the login event
                UserActivityLog.objects.create(
                    user=super_admin,
                    log_date=timezone.localtime(timezone.now()).date(),
                    log_time=timezone.localtime(timezone.now()).time(),
                    event_name=f"SuperAdmin {super_admin.sa_username} logged in"
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


def user_logout(request):
    username = request.session.get('username')

    if username:
        user = User.objects.filter(username=username).first() or SuperAdmin.objects.filter(sa_username=username).first()
        if user:
            # Log the logout event
            UserActivityLog.objects.create(
                user=user,
                log_date=timezone.localtime(timezone.now()).date(),
                log_time=timezone.localtime(timezone.now()).time(),
                event_name=f"User {user.username} logged out"
            )

    request.session.flush()
    messages.success(request, 'Logout successful!')
    return redirect('login')


# dashboard
def dashboard(request):
    return render(request, 'Dashboard/Dashboard.html')



# Management-organization
def organization(request):
    organization = Organization.objects.first()  # Fetch the first Organization object
    return render(request, 'Management/organization.html', {'organization': organization})


def edit_organization(request, organization_id):
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
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name="Updated Organization details"
        )

        return redirect('organization')
    
    return render(request, 'Management/edit_organization.html', {'organization': organization})


def comm_group(request):
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
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new Comm.Group {comm_name} details"
        )

        return redirect('comm_group')

    comm_groups = CommGroup.objects.all()
    return render(request, 'Management/comm_group.html', {'comm_groups': comm_groups})


def edit_comm_group(request, comm_code):
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
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Updated Communication Group {comm_name} details"
        )

        return redirect('comm_group')

    return render(request, 'Management/comm_group.html', {'comm_group': comm_group})


def department(request):
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
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new Department {department_name} details"
        )

        return redirect('department')
    
    departments = Department.objects.all()
    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups
    }
    
    return render(request, 'Management/department.html', context)

def edit_department(request, department_id):
    department = get_object_or_404(Department, id=department_id)
    if request.method == "POST":
        department_name = request.POST.get('edit_dept_name')  # Correct field name
        commgroup_name = request.POST.get('edit_commGroup')
        header_note = request.POST.get('edit_headerNote')
        footer_note = request.POST.get('edit_footerNote')
        report_datetime_stamp = request.POST.get('edit_report_datetime_stamp') == 'True'  # Handle boolean value

        if not department_name:
            # Handle the missing department name error
            return render(request, 'Management/department.html', {
                'department': department,
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
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Edited Department {department_name} details"
        )

        return redirect('department')

    groups = CommGroup.objects.all()
    context = {
        'department': department,
        'groups': groups
    }

    return render(request, 'Management/department.html', context)


def user_group(request):
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
        )
        newuser.save()

        if accessible_departments:
            selected_departments = Department.objects.filter(id__in=accessible_departments)
            newuser.accessible_departments.set(selected_departments)

        # Log the add event
        UserActivityLog.objects.create(
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new User {username} details"
        )

        return redirect('user_group')

    users = User.objects.all()
    departments = Department.objects.all()
    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups,
        'users': users
    }
    return render(request, 'Management/user_group.html', context)

def edit_user(request, user_id):
    # Retrieve the user to be edited
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        # Fetch updated form data from the request
        username = request.POST.get('editUsername')
        login_name = request.POST.get('editLoginName')
        password = request.POST.get('editPassword')
        password_duration = request.POST.get('editpasswordDuration')
        role = request.POST.get('editRole')
        comm_group_code = request.POST.get('editCommGroup')
        department_id = request.POST.get('editdepartmentName')
        status = request.POST.get('editstatus')
        accessible_departments = request.POST.getlist('editaccessibleDepartment')

        # Fetch the related CommGroup and Department objects
        comm_group = get_object_or_404(CommGroup, CommGroup_code=comm_group_code)
        department = get_object_or_404(Department, id=department_id)

        # Update the user's details
        user.username = username

        # Hash and update login_name only if it's changed
        if login_name:
            user.set_login_name(login_name)  # Use set_login_name to hash it

        # Hash and update password only if a new password is provided
        if password:
            user.set_password(password)  # Use set_password to hash it

        user.password_duration = password_duration
        user.role = role
        user.commGroup = comm_group
        user.department = department
        user.status = status
        user.save()  # Save the updated user details

        # Update accessible departments
        if accessible_departments:
            selected_departments = Department.objects.filter(id__in=accessible_departments)
            user.accessible_departments.set(selected_departments)
        else:
            user.accessible_departments.clear()

        # Log the edit event
        logged_in_user = request.session.get('username')  # Get the logged-in username from the session
        if logged_in_user:
            try:
                # Fetch the user object for the logged-in user
                logged_user = User.objects.get(username=logged_in_user)
                
                # Create a log entry for editing the user
                UserActivityLog.objects.create(
                    user=logged_user,
                    log_date=timezone.localtime(timezone.now()).date(),
                    log_time=timezone.localtime(timezone.now()).time(),
                    event_name=f"Edited User {username} details"
                )
            except User.DoesNotExist:
                # Handle the case where the logged-in user does not exist
                pass  # You may log an error or handle it as needed

        return redirect('user_group')

    # Fetch departments and groups for the form
    departments = Department.objects.all()
    groups = CommGroup.objects.all()

    # Prepare context data for rendering the template
    context = {
        'user': user,
        'departments': departments,
        'groups': groups
    }

    # Render the user edit form
    return render(request, 'Management/user_group.html', context)


def role_permission(request):
    # Log access to role permission page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Role Permission details"
    )
    return render(request, 'Management/role_permission.html')


def user_access(request):
    # Log access to user access page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed User Access details"
    )
    return render(request, 'Management/user_access.html')


def app_settings(request):
    # Log access to app settings page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Application Settings"
    )
    return render(request, 'Management/app_settings.html')


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
    status, message = perform_backup()
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name=f"Downloaded database backup"
    )
    return JsonResponse({"status": status, "message": message})

def backup(request):
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
            user=User.objects.get(username=request.session.get('username')),
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
        'backup_time': backup_setting.backup_time if backup_setting else '00:00'
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
    # Log access to restore page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Restore settings"
    )
    return render(request, 'Management/restore.html')



# Settings
def equipment_configure_view(request):
    if request.method == 'POST':
        equip_name = request.POST.get('equipname')
        status = request.POST.get('equipStatus')
        ip_address = request.POST.get('ipaddress')
        interval = request.POST.get('interval')
        equipment_type = request.POST.get('equiptype')
        door_access_type = request.POST.get('dooracctype')

        equipment = Equipment(
            equip_name=equip_name,
            status=status,
            ip_address=ip_address,
            interval=interval,
            equipment_type=equipment_type,
            door_access_type=door_access_type
        )
        equipment.save()
        
        # Log the equipment addition
        UserActivityLog.objects.create(
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name=f"Added new equipment {equip_name}"
        )

        messages.success(request, 'Equipment added successfully!')
        return redirect('equipment_configure')

    equipment_list = Equipment.objects.all()
    return render(request, 'Equip_Settings/equip_config.html', {'equipment_list': equipment_list})


def equipment_setting(request):
    # Log access to equipment settings page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Equipment Settings"
    )
    return render(request, 'Equip_Settings/equip_settings.html')


# DATA Analysis
def view_log(request):
    # Log access to view logs page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed View Logs"
    )
    return render(request, 'Data_Analysis/view_logs.html')


def alaram_log(request):
    # Log access to alarm logs page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Alarm Logs"
    )
    return render(request, 'Data_Analysis/alaram_log.html')



# Live data
def livedata_summary(request):
    # Log access to live data summary page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Live Data Summary"
    )
    return render(request, 'Live Data/realtime_summary.html')





# audit_logs #

def user_activity(request):
    organization = Organization.objects.first()

    emp_user = request.session.get('username', None)
    data = User.objects.get(username=emp_user)

    # Fetch filters from the GET request
    filter_format = request.GET.get('format')  # "Date Wise" or "User-wise"
    from_date = request.GET.get('from-date')
    to_date = request.GET.get('to-date')
    from_time = request.GET.get('from-time')  # Time is optional
    to_time = request.GET.get('to-time')      # Time is optional
    users = request.GET.getlist('user-list')  # For user-wise filtering
    event_name = request.GET.get('event-name')
    
    # Prepare the filter parameters
    filter_kwargs = {}

    if filter_format == 'Date Wise':
        if from_date and to_date:
            from_date_parsed = parse_date(from_date)
            to_date_parsed = parse_date(to_date)

            from_time_parsed = parse_time(from_time) if from_time else datetime_time(0, 0, 0)
            to_time_parsed = parse_time(to_time) if to_time else datetime_time(23, 59, 59)

            filter_kwargs['log_date__range'] = [from_date_parsed, to_date_parsed]
            filter_kwargs['log_time__range'] = [from_time_parsed, to_time_parsed]
        else:
            return HttpResponse("From Date and To Date are mandatory for Date Wise format.", status=400)

    elif filter_format == 'User Wise':
        if users:
            filter_kwargs['user__in'] = users

            # Parse date and time only if provided
            if from_date and to_date:
                from_date_parsed = parse_date(from_date)
                to_date_parsed = parse_date(to_date)

                from_time_parsed = parse_time(from_time) if from_time else datetime_time(0, 0, 0)
                to_time_parsed = parse_time(to_time) if to_time else datetime_time(23, 59, 59)

                filter_kwargs['log_date__range'] = [from_date_parsed, to_date_parsed]
                filter_kwargs['log_time__range'] = [from_time_parsed, to_time_parsed]
        else:
            return HttpResponse("User List is mandatory for User-wise format.", status=400)

    # Filter by event name if provided
    if event_name:
        filter_kwargs['event_name__icontains'] = event_name

    # Query the database with the filters
    user_logs = UserActivityLog.objects.filter(**filter_kwargs)

    # Get all users for the User List dropdown (active users only)
    user_list = User.objects.filter(status='Active')

    # If PDF generation is requested
    if request.GET.get('generate_pdf'):
        # Provide default values if from_date or to_date is empty to avoid parsing errors in PDF generation
        if not from_date:
            from_date = timezone.now().strftime('%Y-%m-%d')
        if not to_date:
            to_date = timezone.now().strftime('%Y-%m-%d')

        return generate_pdf(request, user_logs, from_date, to_date, from_time, to_time)

    # Prepare the context
    context = {
        'user_logs': user_logs,
        'user_list': user_list,
    }

    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Generated User Activity Log PDF"
    )

    return render(request, 'auditlog/user_audit_log.html', context)


def create_page(request, c, page_num, from_date, to_date, from_time, to_time):
    organization = Organization.objects.first()

    emp_user = request.session.get('username', None)
    data = User.objects.get(username=emp_user)

    Dep = Department.objects.get(department_name=data.department)

    current_time = timezone.now()
    formatted_time = current_time.strftime('%d-%m-%Y %H:%M')

    from_date_parsed = datetime.strptime(from_date, '%Y-%m-%d')
    from_date_formatted = from_date_parsed.strftime('%d-%m-%Y')

    to_date_parsed = datetime.strptime(to_date, '%Y-%m-%d')
    to_date_formatted = to_date_parsed.strftime('%d-%m-%Y')

    # Calculate center of the page
    center_x = 595.28 / 2

    # Set the title and logo
    c.setFont("Helvetica-Bold", 14)
    c.setFillColor(colors.blue)
    c.drawCentredString(center_x, 800, organization.name)  # Centered organization name

    c.setFillColor(colors.black)
    c.setFont("Helvetica", 12)
    c.drawCentredString(center_x, 780, Dep.header_note)  # Centered department header note

    # Draw the image logo
    logo_path = organization.logo.path
    c.drawImage(logo_path, 470, 780, width=80, height=30)

    # Draw the separator line under the header
    c.setLineWidth(0.5)
    c.line(30, 770, 570, 770)

    # Add the filters and records info
    c.setFont("Helvetica-Bold", 12)
    c.drawString(200, 750, "User Audit Trail Report Date Wise")

    c.setFont("Helvetica-Bold", 10)
    if from_time and to_time:
        c.drawString(30, 730, "Filter From: {} {}".format(from_date_formatted, from_time))
        c.drawString(420, 730, "Filter To: {} {}".format(to_date_formatted, to_time))

        c.drawString(30, 705, "Records From: {} {}".format(from_date_formatted, from_time))
        c.drawString(420, 705, "Records To: {} {}".format(to_date_formatted, to_time))
    else:
        c.drawString(30, 730, "Filter From: {} 00:00".format(from_date_formatted))
        c.drawString(420, 730, "Filter To: {}  23:59".format(to_date_formatted))

        c.drawString(30, 705, "Records From: {} 00:00".format(from_date_formatted))
        c.drawString(420, 705, "Records To: {}  23:59".format(to_date_formatted))

    # Set a fixed position for the table, leaving enough space below the header
    table_y_position = 680  # Adjust this value based on how much space you want to leave

    # Draw a separator line before the footer
    c.setLineWidth(0.5)
    c.line(30, 60, 570, 60)

    # Add footer with page number
    footer_text_left_top = Dep.footer_note
    footer_text_left_bottom = "ESTDAS v1.0"

    if Dep.report_datetime_stamp:
        footer_text_center = "Printed By - {} on {}".format(data.username, formatted_time)
    else:
        footer_text_center = "Printed By - {}".format(data.username)

    footer_text_right = f"Page {page_num}"

    # Draw footer at the bottom of the page
    c.setFont("Helvetica", 10)
    c.drawString(30, 45, footer_text_left_top)
    c.drawString(30, 35, footer_text_left_bottom)
    c.drawCentredString(300, 40, footer_text_center)
    c.drawRightString(570, 40, footer_text_right)

    return table_y_position  # Return the position where the table should start



def generate_pdf(request, user_logs, from_date, to_date, from_time, to_time):
    emp_user = request.session.get('username', None)
    data = User.objects.get(username=emp_user)

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="user_audit_report.pdf"'

    c = canvas.Canvas(response, pagesize=A4)
    page_num = 1

    # Get the table starting y-position
    table_y_position = create_page(request, c, page_num, from_date, to_date, from_time, to_time)

    # Prepare the data for the table
    data = [
        ['Sl No', 'Log Date', 'Log Time', 'Login Name', 'Event']
    ]

    # Add user log data to the table
    for idx, log in enumerate(user_logs, start=1):
        data.append([
            str(idx),
            log.log_date.strftime('%d-%m-%Y'),
            log.log_time.strftime('%H:%M:%S'),
            log.user.username,
            log.event_name
        ])

    # Define table style
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

    table_row_height = 20
    max_rows_per_page = 30
    top_margin_page1 = table_y_position
    top_margin_other_pages = 670
    current_row = 1

    while current_row < len(data):
        top_margin = top_margin_page1 if page_num == 1 else top_margin_other_pages
        page_data = data[current_row:current_row + max_rows_per_page]
        page_table = Table([data[0]] + page_data, colWidths=[35, 80, 80, 100, 240])
        page_table.setStyle(table_style)
        table_position_y = top_margin - (table_row_height * (min(len(page_data), max_rows_per_page)))
        page_table.wrapOn(c, 50, top_margin)
        page_table.drawOn(c, 30, table_position_y)

        current_row += max_rows_per_page
        if current_row < len(data):
            c.showPage()
            page_num += 1
            table_y_position = create_page(request, c, page_num, from_date, to_date, from_time, to_time)

    c.save()
    return response



def equipment_Audit_log(request):
    # Log access to equipment audit logs page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Equipment Audit Logs"
    )
    return render(request, 'auditlog/equipment_audit.html')


def alaram_Audit_log(request):
    # Log access to alarm audit logs page
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Alarm Audit Logs"
    )
    return render(request, 'auditlog/alaram_audit.html')


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
                        tmp_1=row['Tmp 1'],
                        tmp_2=row['Tmp 2'],
                        tmp_3=row['Tmp 3'],
                        tmp_4=row['Tmp 4'],
                        tmp_5=row['Tmp 5'],
                        tmp_6=row['Tmp 6'],
                        tmp_7=row['Tmp 7'],
                        tmp_8=row['Tmp 8'],
                        tmp_9=row['Tmp 9'],
                        tmp_10=row['Tmp 10'],
                        set_rh=row['Set RH'],
                        rh_low_alarm=row['RH Low Alarm'],
                        rh_low_alert=row['RH Low Alert'],
                        rh_high_alarm=row['RH High Alarm'],
                        rh_high_alert=row['RH High Alert'],
                        rh_1=row['RH 1'],
                        rh_2=row['RH 2'],
                        rh_3=row['RH 3'],
                        rh_4=row['RH 4'],
                        rh_5=row['RH 5'],
                        rh_6=row['RH 6'],
                        rh_7=row['RH 7'],
                        rh_8=row['RH 8'],
                        rh_9=row['RH 9'],
                        rh_10=row['RH 10'],
                    )
                except ValueError as e:
                    messages.error(request, f"Error processing row: {row}. {str(e)}")
                    return redirect(reverse('upload_csv'))

        messages.success(request, "CSV file uploaded and records saved.")
        return redirect(reverse('upload_csv'))

    equipment = Equipment.objects.all()
    return render(request, 'upload_csv.html', {'equipment': equipment})

