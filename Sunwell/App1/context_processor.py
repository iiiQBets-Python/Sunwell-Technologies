from .models import SuperAdmin, User

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
            user = User.objects.get(username=username)
            return {'User': user}
        except User.DoesNotExist:
            pass
    return {'User': None}
