from .models import SuperAdmin, Custom_User

def get_super_admin(request):
    username = request.session.get('username')
    if username:
        try:
            SA = SuperAdmin.objects.get(sa_username=username)
            return {'Super_Admin': SA}
        except SuperAdmin.DoesNotExist:
            pass
    return {'Super_Admin': None}


def get_custom_user(request):
    username = request.session.get('username')
    if username:
        try:
            user = Custom_User.objects.get(username=username)
            return {'Custom_User': user}
        except Custom_User.DoesNotExist:
            pass
    return {'Custom_User': None}
