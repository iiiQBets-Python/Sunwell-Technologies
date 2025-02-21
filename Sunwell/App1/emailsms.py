from App1.models import AppSettings, Department


def get_email_settings(request):
    try:
        # Get the selected QC name from the session

        # Now, filter AppSettings using the Department instance and get the
        # first match
        app_settings = AppSettings.objects.first()

        if app_settings:
            return {
                'EMAIL_HOST': app_settings.email_host,
                'EMAIL_HOST_USER': app_settings.email_host_user,
                'EMAIL_HOST_PASSWORD': app_settings.email_host_password,
                'EMAIL_PORT': app_settings.email_port,
            }
        else:
            # Handle case where no AppSettings are found for the selected
            # department
            return None
    except Department.DoesNotExist:
        # Handle the case where no department is found
        return None
    except AppSettings.DoesNotExist:
        return None
