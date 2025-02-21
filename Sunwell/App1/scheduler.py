from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from django.core.mail import send_mail
from django.core.mail.backends.smtp import EmailBackend
from django.utils.timezone import now
import pytz
import serial
import time
from .models import Department, AppSettings, Email_logs, Sms_logs
from .sms_queue_handler import add_to_sms_queue
from django.http import JsonResponse

scheduler = BackgroundScheduler()


def send_scheduled_notifications():
    """
    This function will handle both scheduled Emails and SMS in a single scheduler job.
    """

    # Get current time in IST
    ist_timezone = pytz.timezone("Asia/Kolkata")
    current_time = datetime.now(
        ist_timezone).time().replace(second=0, microsecond=0)

    # Fetch App Settings
    app_settings = AppSettings.objects.first()
    if not app_settings:
        return JsonResponse(
            {"status": "error", "message": "No App Setting found"}, status=400)

    # Process Emails if enabled
    if app_settings.email_sys_set:
        send_scheduled_emails(current_time, app_settings)

    # Process SMS if enabled
    if app_settings.sms_sys_set:
        send_scheduled_sms(current_time, app_settings)


def send_scheduled_emails(current_time, app_settings):

    ist_timezone = pytz.timezone("Asia/Kolkata")

    # Fetch departments scheduled for emails
    departments = Department.objects.filter(
        email_time=current_time, email_sys="Enable")

    if not departments.exists():
        pass
        return JsonResponse(
            {"status": "error", "message": "No Departments found at specified time"}, status=400)

    # Initialize Email Backend
    try:
        email_backend = EmailBackend(
            host=app_settings.email_host,
            port=app_settings.email_port,
            username=app_settings.email_host_user,
            password=app_settings.email_host_password,
            fail_silently=False,
        )
    except Exception as e:
        return JsonResponse(
            {"status": "error", "message": "No Email Setting found"}, status=400)

    for department in departments:
        recipient_list = [
            email for email in [
                department.alert_email_address_1,
                department.alert_email_address_2,
                department.alert_email_address_3,
                department.alert_email_address_4,
                department.alert_email_address_5,
                department.alert_email_address_6,
                department.alert_email_address_7,
                department.alert_email_address_8,
                department.alert_email_address_9,
                department.alert_email_address_10,
            ] if email
        ]

        if recipient_list:
            subject = f"ESTDAS - Test mail for {department.department_name}"
            message = f"This is a test email from ESTDAS application for {
                department.department_name or ''} department \n\n{
                app_settings.email_signature or ''}"

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

                    # Log success
                    Email_logs.objects.create(
                        time=current_time,
                        date=datetime.now(ist_timezone).date(),
                        sys_mail=True,
                        to_email=recipient,
                        email_sub=subject,
                        email_body=message,
                        status="Sent",
                    )

                except Exception as e:

                    # Log failure
                    Email_logs.objects.create(
                        time=current_time,
                        date=datetime.now(ist_timezone).date(),
                        sys_mail=True,
                        to_email=recipient,
                        email_sub=subject,
                        email_body=message,
                        status="Failed",
                    )


def send_scheduled_sms(current_time, app_settings):

    ist_timezone = pytz.timezone("Asia/Kolkata")

    # Fetch departments scheduled for SMS
    departments = Department.objects.filter(
        sms_time=current_time, sms_sys="Enable")

    if not departments.exists():
        pass
        return JsonResponse(
            {"status": "error", "message": "No Departments found at specified time"}, status=400)

    for department in departments:
        number = {
            user_name: phone_number
            for user_name, phone_number in [
                (department.user1, department.user1_num),
                (department.user2, department.user2_num),
                (department.user3, department.user3_num),
                (department.user4, department.user4_num),
                (department.user5, department.user5_num),
                (department.user6, department.user6_num),
                (department.user7, department.user7_num),
                (department.user8, department.user8_num),
                (department.user9, department.user9_num),
                (department.user10, department.user10_num),
            ]
            if user_name  # Ensure that empty names are not included in the dictionary
        }
        message = f"This is a test SMS from ESTDAS application for {
            department.department_name or ''} department."
        status = add_to_sms_queue(
            number,
            message,
            equipment=None,
            alarm_id=None,
            sys_sms=True)


def start_notification_scheduler():
    global scheduler

    scheduler.add_job(
        send_scheduled_notifications,
        CronTrigger(second=0),
        id="scheduled_notifications_check",
        replace_existing=True,
    )

    scheduler.start()
