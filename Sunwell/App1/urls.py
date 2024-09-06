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
    #Management URL's
    path('organization/', organization, name='organization'),
    path('organization/edit/<int:organization_id>/',edit_organization, name='edit_organization'),
    path('comm_group/',comm_group, name='comm_group'),
    path('department/', department, name='department'),
    path('user_group/', user_group, name='user_group'),
    path('role_permission/', role_permission, name='role_permission'),
    path('user_access/', user_access, name='user_access'),
    path('app_setings/', app_settings, name='app_settings'),
    path('livedata_summary/', livedata_summary, name='livedata_summary'),
    path('backup/', backup, name='backup'),
    path('download-backup/', download_backup, name='download_backup'),
    path('restore/', restore, name='restore'),
    
    
    # Settings
     path('equipment_configure/', equipment_configure_view, name='equipment_configure'),
    path('equipment_setting',equipment_setting,name='equipment_setting'),

    #DATA Analysis
    path('view_log/',view_log,name='view_log'),
    path('alaram_log/',alaram_log,name='alaram_log'),

    # audit_logs #
    path('user_activity_log/', user_activity, name="user_activity"),
    path('generate_user_activity_pdf/', generate_user_activity_pdf, name='generate_user_activity_pdf'),
    path('Equipment_Audit/', equipment_Audit_log, name="Equipment_Audit_log"),
    path('alaram_Audit_log/', alaram_Audit_log, name="alaram_Audit_log"),
]