from django.urls import path
from .views import *

urlpatterns = [

    # Base URL's
    path('base/', base, name='base'),
    path('', user_login, name='login'),
    path('logout/', user_logout, name='logout'),


    #Dashboard URL's
    path('dashboard/', dashboard, name='dashboard'),


    #Management URL's
    path('organization/', organization, name='organization'),
    path('organization/edit/<int:organization_id>/',edit_organization, name='edit_organization'),
    path('comm_group/',comm_group, name='comm_group'),
    path('validate-activation-key/', validate_activation_key, name='validate_activation_key'),
    path('department/', department, name='department'),
    path('users/', users, name='users'),
    path('role_permission/', role_permission, name='role_permission'),
    path('user_access/', user_access, name='user_access'),
    path('app_setings/', app_settings, name='app_settings'),

    path('app_setings/send_email', send_email, name="send_email"),
    path('department/email_form', email_form, name="email_form"),
    path('app_setings/email_settings', email_settings, name="email_settings"),
    path('save-qc-session/', save_qc_session, name='save_qc_session'),
    
    path('backup/', backup, name='backup'),
    path('download-backup/', download_backup, name='download_backup'),
    path('restore/', restore, name='restore'),

    path('edit_comm_group/<str:comm_code>/', edit_comm_group, name='edit_comm_group'),
    path('edit_department/<str:department_id>/', edit_department, name='edit_department'),
    path('edit_user/<str:user_id>/', edit_user, name='edit_user'),
    path('edit_role/<str:role>/', edit_role, name='edit_role'),

    
    
    # Settings
    path('equipment_configure/', equipment_configure_view, name='equipment_configure'),
    path('equipment_setting',equipment_setting,name='equipment_setting'),

    #Live data
    path('livedata_summary/', livedata_summary, name='livedata_summary'),

    #DATA Analysis
    path('view_log/',view_log,name='view_log'),
    path('alaram_log/',alaram_log,name='alaram_log'),

    # audit_logs #
    path('user_activity_log/', user_activity, name="user_activity"),
    path('Equipment_Audit/', equipment_Audit_log, name="Equipment_Audit_log"),
    path('alaram_Audit_log/', alaram_Audit_log, name="alaram_Audit_log"),

    path('upload_csv/', upload_csv, name='upload_csv'),

    path('change_pass', change_pass, name="change_pass"),
    path('change_pass_2', change_pass_2, name='change_pass_2'),
]
