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
    path('restore/', restore, name='restore'),
    
    
    # Settings
    path('equipmentconfigure/',equipmentconfigure,name='equipmentconfigure'),
    path('equipmentsetting_Graphcolor',equipmentsetting_Graphcolor,name='equipmentsetting_Graphcolor'),

    #DATA Analysis
    path('view_log/',view_log,name='view_log'),
    path('alaram_log/',alaram_log,name='alaram_log'),

    # audit_logs #
    path('useractivity/', useractivity, name="useractivity"),
    path('Equipment_Audit/', Equipment_Audit, name="Equipment_Audit"),
    path('user_Audit/', user_Audit, name="user_Audit"),
]