from .models import SuperAdmin, User

def get_super_admin(request):
    login_name = request.session.get('login_name')
    if login_name:
        try:
            SA = SuperAdmin.objects.get(sa_username=login_name)
            return {'Super_Admin': SA}
        except SuperAdmin.DoesNotExist:
            pass
    return {'Super_Admin': None}


def get_custom_user(request):
    login_name = request.session.get('login_name')
    if login_name:
        try:
            user = User.objects.get(login_name=login_name)
            return {'User': user}
        except User.DoesNotExist:
            pass
    return {'User': None}
