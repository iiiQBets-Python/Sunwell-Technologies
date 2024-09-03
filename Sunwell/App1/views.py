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
                return redirect('dashboard')
            else:
                messages.error(request, 'Invalid Username or Password!')
        except SuperAdmin.DoesNotExist:
            try:                
                user = None
                for u in User.objects.all():
                    if u.check_login_name(username):  # Compare the unhashed login_name
                        user = u
                        break

                if user and check_password(password, user.password):
                    request.session['username'] = user.username
                    messages.success(request, 'Login Successful!')
                    return redirect('dashboard')              
                else:   
                               
                    messages.error(request, 'Invalid Username or Password!')
            except User.DoesNotExist:
                messages.error(request, 'User does not exist!')

        return render(request, 'Base/login.html')
    else:
        return render(request, 'Base/login.html')

def user_logout(request):
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
        organization.name = request.POST.get('name')
        organization.email = request.POST.get('email')
        organization.phoneNo = request.POST.get('phoneNo')
        organization.address = request.POST.get('address')
        
        if request.FILES.get('logo'):
            organization.logo = request.FILES['logo']
        
        organization.save()
        return redirect('organization')
    
    return render(request, 'Management/edit_organization.html', {'organization': organization})

def comm_group(request):
    if request.method == "POST":
        comm_name = request.POST.get('comm_name')
        comm_code = request.POST.get('comm_code')
        soft_key = request.POST.get('softKey')
        activation_key = request.POST.get('activationKey')

        new_commgroup = CommGroup(
            CommGroup_name = comm_name,
            CommGroup_code = comm_code,
            soft_key = soft_key,
            activation_key = activation_key,
        )
        new_commgroup.save()

        return redirect('comm_group')

    # Fetching all communication groups for display in the table
    comm_groups = CommGroup.objects.all()
    return render(request, 'Management/comm_group.html', {'comm_groups': comm_groups})

def department(request):
    if request.method == "POST":
        department_name = request.POST.get('departmentName')
        commgroup_code = request.POST.get('commGroup')
        header_note = request.POST.get('headerNote')
        footer_note = request.POST.get('footerNote')

        # Fetch the CommGroup instance
        commgroup = CommGroup.objects.get(CommGroup_code=commgroup_code)

        new_department = Department(
            department_name=department_name,
            commGroup=commgroup,
            header_note=header_note,
            footer_note=footer_note,
        )
        new_department.save()

        return redirect('department')
    
    departments = Department.objects.all()
    groups = CommGroup.objects.all()
    context = {
        'departments': departments,
        'groups': groups
    }
    
    return render(request, 'Management/department.html',context )

def user_group(request):
    emp_user = request.session.get('username', None)

    data = User.objects.get(username = emp_user)
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

        # Fetch related objects
        commgroup = CommGroup.objects.get(CommGroup_code=comm_group)
        department = Department.objects.get(id=departmentname)
        
        # Create the User object first
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

        # Add accessible departments to the ManyToMany field if there are any
        if accessible_departments:
            selected_departments = Department.objects.filter(id__in=accessible_departments)
            newuser.accessible_departments.set(selected_departments)

        return redirect('user_group')

    # Fetch users, departments, and communication groups for the template
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
    return render(request, 'Management/role_permission.html')

def user_access(request):
    return render(request, 'Management/user_access.html')

def app_settings(request):
    return render (request, 'Management/app_settings.html')

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
    return render (request, 'Management/restore.html')


# Settings
def equipment_configure_view(request):
    if request.method == 'POST':
        equip_name = request.POST.get('equipname')
        status = request.POST.get('equipStatus')
        ip_address = request.POST.get('ipaddress')  # Check the ID to ensure it matches
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
        messages.success(request, 'Equipment added successfully!')
        return redirect('equipment_configure')

    equipment_list = Equipment.objects.all()
    return render(request, 'Equip_Settings/equip_config.html', {'equipment_list': equipment_list})


def equipment_setting(request):
    return render(request, 'Equip_Settings/equip_settings.html')

# DATA Analysis
def view_log(request):
    return render(request, 'Data_Analysis/view_logs.html')

def alaram_log(request):
    return render(request, 'Data_Analysis/alaram_log.html')


# Live data
def livedata_summary(request):
    return render (request, 'Live Data/realtime_summary.html')

# audit_logs #
def useractivity(request):
    return render(request, 'auditlog/audit.html')

def Equipment_Audit(request):
    return render(request, 'auditlog/equipment_audit.html')

def user_Audit(request):
    return render(request, 'auditlog/user_audit.html')