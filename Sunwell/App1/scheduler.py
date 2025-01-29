from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from django.core.mail import send_mail
from django.core.mail.backends.smtp import EmailBackend
from .models import Department, AppSettings, Email_logs, Sms_logs
from datetime import datetime
from django.utils.timezone import now
import pytz
import serial

scheduler = BackgroundScheduler()

def send_scheduled_emails():
    """
    Check all departments and send emails if their scheduled time matches the current time in IST,
    and if the email system is enabled for the department.
    """
    # Get current time in IST, truncated to hours and minutes
    ist_timezone = pytz.timezone("Asia/Kolkata")
    current_time = datetime.now(ist_timezone).time().replace(second=0, microsecond=0)

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

        subject = f"ESTDAS - Test mail for {department.department_name}"
        message = (
            f"This is a test email from ESTDAS application for "
            f"{department.department_name or ''}\n\n"
            f"{app_settings.email_signature or ''}"
        )

        if recipient_list:
            for recipient in recipient_list:
                try:
                    print(f"[DEBUG] send_scheduled_emails triggered at {datetime.now()}")
                    print(f"[DEBUG] Registered Jobs: {[job.id for job in scheduler.get_jobs()]}")
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
                except Exception:
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
        else:
            pass
            # Log the absence of recipients for this department
            # Email_logs.objects.create(
            #     time=current_time,
            #     date=datetime.now(ist_timezone).date(),
            #     sys_mail=True,
            #     to_email="No Recipients",
            #     email_sub=subject,
            #     email_body=message,
            #     status="No Recipients",
            # )


def daily_email_scheduler():
    if not scheduler.get_job("scheduled_email_check"):  # Check if the job already exists
        scheduler.add_job(
            send_scheduled_emails,
            CronTrigger(second=0),
            id="scheduled_email_check",
            replace_existing=True,
        )
        scheduler.start()



from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from datetime import datetime
from django.utils.timezone import now
import pytz
from .models import Department, AppSettings, Sms_logs

import time

scheduler = BackgroundScheduler()

def send_scheduled_sms():
    """
    Check all departments and send SMS if their scheduled time matches the current time in IST,
    and if the SMS system is enabled for the department.
    """
    # Get current time in IST, truncated to hours and minutes
    ist_timezone = pytz.timezone("Asia/Kolkata")
    current_time = datetime.now(ist_timezone).time().replace(second=0, microsecond=0)

    # Fetch SMS settings
    app_settings = AppSettings.objects.first()
    if not app_settings:
        return

    if app_settings.sms_sys_set != 'Enable':
        return

    # Query departments with matching sms_time and SMS system enabled
    departments = Department.objects.filter(sms_time=current_time, sms_sys="Enable")


    for department in departments:
        recipient_details = [
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

        for user_name, user_number in recipient_details:
            if user_number:
                message = (
                    f"This is a test SMS from ESTDAS application for {user_name or ''}."
                )
                try:
                    print(f"[DEBUG] Attempting to send SMS to {user_number} ({user_name})")
                    ser = serial.Serial(
                        port=app_settings.comm_port,
                        baudrate=int(app_settings.baud_rate),
                        bytesize=serial.EIGHTBITS,
                        parity=serial.PARITY_NONE if app_settings.parity == 'None' else app_settings.parity.upper()[0],
                        stopbits=serial.STOPBITS_ONE if app_settings.stop_bits == 1 else serial.STOPBITS_TWO,
                        timeout=2
                    )

                    def send_command(command, wait_for_response=True, delay=2):
                        """Send a command to the GSM modem and optionally wait for a response."""
                        ser.write(command.encode() + b'\r')
                        ser.flush()
                        time.sleep(delay)
                        if wait_for_response:
                            response = ser.read(1000).decode(errors="ignore").strip()
                            print(f"[DEBUG] Response: {response}")
                            return response
                        return ""

                    # Test modem connectivity
                    if "OK" not in send_command("AT"):
                        raise Exception("Modem not responding to 'AT' command.")

                    # Set SMS mode to text
                    if "OK" not in send_command("AT+CMGF=1"):
                        raise Exception("Failed to set SMS mode to text.")

                    # Initiate SMS sending
                    response = send_command(f'AT+CMGS="{user_number}"', wait_for_response=True, delay=2)
                    if ">" not in response:
                        raise Exception("Modem did not prompt for message input.")

                    # Send the message and terminate with Ctrl+Z
                    ser.write((message + '\r').encode())
                    ser.flush()
                    time.sleep(1)  # Brief pause before sending Ctrl+Z
                    ser.write(b"\x1A")  # Ctrl+Z to send the SMS
                    ser.flush()

                    # Wait for final response
                    time.sleep(5)
                    response = ser.read(1000).decode(errors="ignore").strip()

                    if "+CMGS" in response and "OK" in response:
                        status = "Sent"
                    else:
                        status = "Failed"

                except Exception as e:
                    status = "Failed"
                    response = str(e)

                finally:
                    if ser and ser.is_open:
                        ser.close()

                    # Log SMS details to the database
                    Sms_logs.objects.create(
                        time=current_time,
                        date=datetime.now(ist_timezone).date(),
                        sys_sms=True,
                        to_num=user_number,
                        user_name=user_name,
                        msg_body=message,
                        status=status
                    )

def daily_sms_scheduler():
    """
    Set up a periodic job to check SMS schedules every minute, precisely at 0 seconds.
    """
    if not scheduler.running:
        scheduler.remove_all_jobs()
        scheduler.add_job(
            send_scheduled_sms,
            CronTrigger(second=0),  # Runs exactly at 0 seconds of every minute
            id="scheduled_sms_check",
            replace_existing=True,
        )
        scheduler.start()
