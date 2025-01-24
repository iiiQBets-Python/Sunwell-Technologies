from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from django.core.mail import send_mail
from django.core.mail.backends.smtp import EmailBackend
from .models import Department, AppSettings, Email_logs
from datetime import datetime
from django.utils.timezone import now
import pytz
from threading import Lock

scheduler = BackgroundScheduler()
# Global set to track sent emails for the day
sent_emails_today = set()


def send_scheduled_emails():
    """
    Check all departments and send emails if their scheduled time matches the current time in IST,
    and if the email system is enabled for the department.
    """
    global sent_emails_today

    # Get current time in IST, truncated to hours and minutes
    ist_timezone = pytz.timezone("Asia/Kolkata")
    current_time = datetime.now(ist_timezone).time().replace(second=0, microsecond=0)
    today_date = datetime.now(ist_timezone).date()  # Today's date

    # Reset the global set at the start of a new day
    if not sent_emails_today or all(dept_date.split("_")[1] != str(today_date) for dept_date in sent_emails_today):
        sent_emails_today.clear()

    # Fetch email settings
    app_settings = AppSettings.objects.first()
    if not app_settings or app_settings.email_sys_set != 'Enable':
        return

    # Set up the email backend
    email_backend = EmailBackend(
        host=app_settings.email_host,
        port=app_settings.email_port,
        username=app_settings.email_host_user,
        password=app_settings.email_host_password,
        use_tls=True,
        fail_silently=False,
    )

    # Query departments with matching email_time and email system enabled
    departments = Department.objects.filter(email_time=current_time, email_sys="Enable")

    for department in departments:
        # Create a unique identifier for the department for the day
        dept_identifier = f"{department.id}_{today_date}"

        # Check if the department has already sent an email today
        if dept_identifier in sent_emails_today:
            continue  # Skip this department if an email has already been sent

        recipient_list = [
            email for email in [
                department.alert_email_address_1,
                department.alert_email_address_2,
                department.alert_email_address_3,
                department.alert_email_address_4,
                department.alert_email_address_5,
            ] if email
        ]

        subject = f"ESTDAS - Test mail for {department.department_name}"
        message = (
            f"This is a test email from ESTDAS application for "
            f"{department.department_name or ''}\n\n"
            f"{app_settings.email_signature or ''}"
        )

        if recipient_list:
            for recipient in recipient_list:
                try:
                    send_mail(
                        subject=subject,
                        message=message,
                        from_email=app_settings.email_host_user,
                        recipient_list=[recipient],
                        connection=email_backend,
                        fail_silently=False,
                    )

                    # Add the department to the set to mark it as having sent an email
                    sent_emails_today.add(dept_identifier)

                    # Log success
                    Email_logs.objects.create(
                        time=current_time,
                        date=today_date,
                        sys_mail=True,
                        to_email=recipient,
                        email_sub=subject,
                        email_body=message,
                        status="Sent",
                    )
                except Exception:
                    # Log failure
                    Email_logs.objects.create(
                        time=current_time,
                        date=today_date,
                        sys_mail=True,
                        to_email=recipient,
                        email_sub=subject,
                        email_body=message,
                        status="Failed",
                    )
        else:
            pass

def daily_email_scheduler():
    """
    Set up a periodic job to check email schedules every minute, precisely at 0 seconds.
    """
    if not scheduler.running:
        scheduler.remove_all_jobs()
        scheduler.add_job(
            send_scheduled_emails,
            CronTrigger(second=0),  # Runs exactly at 0 seconds of every minute
            id="scheduled_email_check",
            replace_existing=True,
        )
        scheduler.start()
