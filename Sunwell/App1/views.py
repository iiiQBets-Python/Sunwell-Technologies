from django.shortcuts import render, redirect,get_object_or_404
from django.contrib.auth import login, logout
from django.contrib import messages
from .models import *

def base(request):
    return render(request, 'Base/base.html')

def user_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        try:
            super_admin = SuperAdmin.objects.get(sa_username=username)
            if check_password(password, super_admin.sa_password):
                request.session['username'] = super_admin.sa_username
                messages.success(request, 'Login Successful!')
                return redirect('SA_dashboard')
            else:
                messages.error(request, 'Invalid Username or Password!')
        except SuperAdmin.DoesNotExist:
            try:
                user = Custom_User.objects.get(username=username)
                if check_password(password, user.password):
                    request.session['username'] = user.username
                    messages.success(request, 'Login Successful!')
                    return redirect('dashboard')
                
                else:
                    messages.error(request, 'Invalid Username or Password!')
            except Custom_User.DoesNotExist:
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
            status=status
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

def livedata_summary(request):
    return render (request, 'Live Data/realtime_summary.html')

def backup(request):
    return render (request, 'Management/backup.html')

def restore(request):
    return render (request, 'Management/restore.html')


# Settings
def equipmentconfigure(request):
    return render(request, 'Settings/equipment_config.html')

def equipmentsetting_Graphcolor(request):
    return render(request, 'Settings/Graphcolor.html')

# DATA Analysis
def view_log(request):
    return render(request, 'Data_Analysis/view_logs.html')

def alaram_log(request):
    return render(request, 'Data_Analysis/alaram_log.html')


# audit_logs #
def useractivity(request):
    return render(request, 'auditlog/audit.html')

def Equipment_Audit(request):
    return render(request, 'auditlog/equipment_audit.html')

def user_Audit(request):
    return render(request, 'auditlog/user_audit.html')