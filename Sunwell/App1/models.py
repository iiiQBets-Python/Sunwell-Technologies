
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone


class SuperAdmin(models.Model):
    sa_full_name = models.CharField(max_length=25)
    sa_email = models.EmailField()
    sa_username = models.CharField(max_length=25, unique=True, primary_key=True)
    sa_password = models.CharField(max_length=255)  # Ensure length to accommodate hashed password

    def __str__(self):
        return self.sa_username

    def save(self, *args, **kwargs):
        if not self.pk or not self._is_password_hashed():
            self.sa_password = make_password(self.sa_password)
        super().save(*args, **kwargs)

    def _is_password_hashed(self):
        current_password = self._get_current_password()
        if current_password:
            return check_password(self.sa_password, current_password)
        return False

    def _get_current_password(self):
        if self.pk:
            try:
                return SuperAdmin.objects.get(pk=self.pk).sa_password
            except SuperAdmin.DoesNotExist:
                return None
        return None



class Organization(models.Model):
    name = models.CharField(max_length=255)
    email = models.EmailField()
    phoneNo = models.CharField(max_length=15)
    address = models.TextField()
    logo = models.ImageField( blank=True, null=True)

    def __str__(self):
        return self.name


class CommGroup(models.Model):
    CommGroup_name = models.CharField(max_length=50, unique=True)
    CommGroup_code = models.CharField(max_length=10, primary_key=True)
    soft_key = models.CharField(max_length=50)
    activation_key = models.CharField(max_length=50)

    def __str__(self):
        return self.CommGroup_name

    

class Department(models.Model):
    department_name = models.CharField( max_length=50, null=False)
    commGroup = models.ForeignKey(CommGroup, on_delete=models.CASCADE)
    header_note = models.CharField(max_length=100)
    footer_note = models.CharField(max_length=100)
    report_datetime_stamp = models.BooleanField(default=False)

    def __str__(self):
        return self.department_name
        

class User(models.Model):    
    username = models.CharField(max_length=30, unique=True)
    login_name = models.CharField(max_length=255, unique=True)
    password = models.CharField(max_length=255)
    password_duration = models.PositiveIntegerField(default=30)
    role = models.CharField(max_length=50)
    commGroup = models.ForeignKey(CommGroup, on_delete=models.SET_NULL, null=True)
    department = models.ForeignKey(Department, on_delete=models.SET_NULL, null=True)
    status = models.CharField(max_length=10, choices=[('Active', 'Active'), ('Inactive', 'Inactive')], default='Active')
    accessible_departments = models.ManyToManyField(Department, related_name='accessible_departments', blank=True)
    
    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def set_login_name(self, raw_login_name):
        self.login_name = make_password(raw_login_name)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def check_login_name(self, raw_login_name):
        return check_password(raw_login_name, self.login_name)

    def save(self, *args, **kwargs):
        if not self.pk:  # If new instance, hash password and login name before saving
            self.set_password(self.password)
            self.set_login_name(self.login_name)
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username

    
class BackupSettings(models.Model):
    local_path = models.CharField(max_length=255)
    remote_path = models.CharField(max_length=255, blank=True, null=True)
    backup_time = models.TimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Backup Settings (Local Path: {self.local_path})"

    

class Equipment(models.Model):
    EQUIPMENT_STATUS_CHOICES = [
        ('active', 'Active'),
        ('inactive', 'Inactive')
    ]
    
    EQUIPMENT_ACCESS_CHOICES = [
        ('none', 'None'),
        ('plc', 'PLC'),
        ('biometric', 'Biometric')
    ]
    
    equip_name = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=EQUIPMENT_STATUS_CHOICES)
    ip_address = models.GenericIPAddressField()
    interval = models.IntegerField()
    equipment_type = models.CharField(max_length=255)
    door_access_type = models.CharField(max_length=15, choices=EQUIPMENT_ACCESS_CHOICES)

    def __str__(self):
        return self.equip_name
    

class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    log_date = models.DateField(default=timezone.now)
    log_time = models.TimeField(default=timezone.now)
    event_name = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.user.username} - {self.event_name} - {self.log_date} {self.log_time}"
    

class TemperatureHumidityRecord(models.Model):
    equip_name = models.ForeignKey(Equipment, on_delete=models.SET_NULL, null=True)
    date = models.DateField()
    time = models.TimeField(blank=True, null=True)
    set_temp = models.FloatField()
    t_low_alarm = models.FloatField()
    t_low_alert = models.FloatField()
    t_high_alarm = models.FloatField()
    t_high_alert = models.FloatField()
    tmp_1 = models.FloatField()
    tmp_2 = models.FloatField()
    tmp_3 = models.FloatField()
    tmp_4 = models.FloatField()
    tmp_5 = models.FloatField()
    tmp_6 = models.FloatField()
    tmp_7 = models.FloatField()
    tmp_8 = models.FloatField()
    tmp_9 = models.FloatField()
    tmp_10 = models.FloatField()
    set_rh = models.FloatField()
    rh_low_alarm = models.FloatField()
    rh_low_alert = models.FloatField()
    rh_high_alarm = models.FloatField()
    rh_high_alert = models.FloatField()
    rh_1 = models.FloatField()
    rh_2 = models.FloatField()
    rh_3 = models.FloatField()
    rh_4 = models.FloatField()
    rh_5 = models.FloatField()
    rh_6 = models.FloatField()
    rh_7 = models.FloatField()
    rh_8 = models.FloatField()
    rh_9 = models.FloatField()
    rh_10 = models.FloatField()

    def _str_(self):
        return f"Date: {self.date}, Time: {self.time}"