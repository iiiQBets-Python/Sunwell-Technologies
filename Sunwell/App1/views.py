from datetime import datetime, time, timedelta, timezone
import threading
from django.shortcuts import render, redirect,get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import login, logout
from django.contrib import messages
from .models import *
from django.conf import settings
from django.http import JsonResponse
import os
import subprocess
import schedule, time

from django.template.loader import get_template
from xhtml2pdf import pisa

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
    # Log the view access
    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed Organization details"
    )
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
            event_name=f"Added new Communication Group {comm_name} details"
        )

        return redirect('comm_group')

    comm_groups = CommGroup.objects.all()
    return render(request, 'Management/comm_group.html', {'comm_groups': comm_groups})


def department(request):
    if request.method == "POST":
        department_name = request.POST.get('departmentName')
        commgroup_code = request.POST.get('commGroup')
        header_note = request.POST.get('headerNote')
        footer_note = request.POST.get('footerNote')

        commgroup = CommGroup.objects.get(CommGroup_code=commgroup_code)

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

        backup_setting = BackupSettings(
            local_path=local_path,
            remote_path=remote_path,
            backup_time=backup_time
        )
        backup_setting.save()

        # Log the backup settings update
        UserActivityLog.objects.create(
            user=User.objects.get(username=request.session.get('username')),
            log_date=timezone.localtime(timezone.now()).date(),
            log_time=timezone.localtime(timezone.now()).time(),
            event_name="Updated backup settings"
        )

        messages.success(request, 'Backup settings saved successfully!')
        return redirect('backup')

    return render(request, 'Management/backup.html')


def schedule_daily_backup():
    print("Scheduler thread started")
    backup_setting = BackupSettings.objects.last()
    if backup_setting and backup_setting.backup_time:
        
        backup_time_str = backup_setting.backup_time.strftime("%H:%M")
        print(f"Scheduling daily backup at {backup_time_str}")

        
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
    logs = UserActivityLog.objects.all()

    # Apply filters based on the request
    if 'user_list' in request.GET:
        user_list = request.GET.getlist('user_list')
        if user_list:
            logs = logs.filter(user__username__in=user_list)
    
    if 'from_date' in request.GET and 'to_date' in request.GET:
        from_date = request.GET.get('from_date')
        to_date = request.GET.get('to_date')
        if from_date and to_date:
            from_time = request.GET.get('from_time', '00:00')  # Default from 00:00
            to_time = request.GET.get('to_time', '23:59')  # Default to 23:59
            
            # Combine date and time
            from_datetime = datetime.combine(datetime.strptime(from_date, "%Y-%m-%d"), time.fromisoformat(from_time))
            to_datetime = datetime.combine(datetime.strptime(to_date, "%Y-%m-%d"), time.fromisoformat(to_time))
            
            logs = logs.filter(log_date__gte=from_datetime, log_date__lte=to_datetime)
    
    if 'event_name' in request.GET:
        event_name = request.GET.get('event_name')
        if event_name:
            logs = logs.filter(event_name__icontains=event_name)
    
    # Order logs by selected option
    if 'orderBy' in request.GET:
        order_by = request.GET.get('orderBy')
        if order_by == 'logDate':
            logs = logs.order_by('-log_date', '-log_time')
        elif order_by == 'unsorted':
            logs = logs.order_by('id')


    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Accessed User Activity Logs"
    )

    context = {
        'logs': logs,
    }
    return render(request, 'auditlog/user_audit_log.html', context)


def generate_user_activity_pdf(request):
    logs = UserActivityLog.objects.all()

    if 'user_list' in request.GET:
        user_list = request.GET.getlist('user_list')
        if user_list:
            logs = logs.filter(user__username__in=user_list)
    
    if 'from_date' in request.GET and 'to_date' in request.GET:
        from_date = request.GET.get('from_date')
        to_date = request.GET.get('to_date')
        if from_date and to_date:
            logs = logs.filter(log_date__range=[from_date, to_date])

    if 'from_time' in request.GET and 'to_time' in request.GET:
        from_time = request.GET.get('from_time')
        to_time = request.GET.get('to_time')
        if from_time and to_time:
            logs = logs.filter(log_time__range=[from_time, to_time])

    if 'event_name' in request.GET:
        event_name = request.GET.get('event_name')
        if event_name:
            logs = logs.filter(event_name__icontains=event_name)
    
    # Order logs by selected option
    if 'orderBy' in request.GET:
        order_by = request.GET.get('orderBy')
        if order_by == 'logDate':
            logs = logs.order_by('-log_date', '-log_time')
        elif order_by == 'unsorted':
            logs = logs.order_by('id')

    # Render the PDF with filtered logs
    template = get_template('auditlog/user_activity_pdf.html')
    html = template.render({'logs': logs})

    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = 'inline; filename="user_activity_report.pdf"'  # Changed to 'inline'
    
    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse('We had some errors <pre>' + html + '</pre>')
    

    UserActivityLog.objects.create(
        user=User.objects.get(username=request.session.get('username')),
        log_date=timezone.localtime(timezone.now()).date(),
        log_time=timezone.localtime(timezone.now()).time(),
        event_name="Generated User Activity PDF"
    )

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
