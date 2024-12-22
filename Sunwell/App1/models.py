
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
import base64


class SuperAdmin(models.Model):        
    username = models.CharField(max_length=30, unique=True)    
    email_id = models.EmailField()
    password = models.CharField(max_length=255) 
    role = models.CharField(max_length=50)
    def _str_(self):
        return self.username

    def save(self, *args, **kwargs):
        if not self.pk or not self._is_password_hashed():
            self.password = make_password(self.password)
        super().save(*args, **kwargs)

    def _is_password_hashed(self):
        current_password = self._get_current_password()
        if current_password:
            return check_password(self.password, current_password)
        return False

    def _get_current_password(self):
        if self.pk:
            try:
                return SuperAdmin.objects.get(pk=self.pk).password
            except SuperAdmin.DoesNotExist:
                return None
        return None


class Organization(models.Model):
    name = models.CharField(max_length=255, default='Sunwell Technologies')
    email = models.EmailField(default='sunwelltechno@gmail.com')
    phoneNo = models.CharField(max_length=15, null=True)
    address = models.TextField(null=True)
    logo = models.ImageField(blank=True, null=True)
    nod = models.CharField(max_length=255, null=True, default='MA==')  # Encoded value stored as a string

    def set_nod(self, number_of_devices):
        """Encode and set the number of devices."""
        encoded_nod = base64.b64encode(str(number_of_devices).encode('utf-8')).decode('utf-8')
        self.nod = encoded_nod

    def get_nod(self):
        """Decode and return the number of devices."""
        if self.nod is None:
            return 0  # Default value if nod is not set
        decoded_nod = base64.b64decode(self.nod.encode('utf-8')).decode('utf-8')
        return int(decoded_nod)

    def _str_(self):
        return self.name 


class CommGroup(models.Model):
    CommGroup_name = models.CharField(max_length=50, unique=True)
    CommGroup_code = models.CharField(max_length=10, primary_key=True)
    soft_key = models.CharField(max_length=255)
    activation_key = models.CharField(max_length=255, unique=True)

    def __str__(self):
        return self.CommGroup_name

    

class Department(models.Model):
    department_name = models.CharField( max_length=50, null=False)
    commGroup = models.ForeignKey(CommGroup, on_delete=models.CASCADE)
    header_note = models.CharField(max_length=100, null=True)
    footer_note = models.CharField(max_length=100, null=True)
    report_datetime_stamp = models.BooleanField(default=True, null=True)
    email_alert = models.CharField(default=0, max_length=50, blank=True, null=True)
    email_time = models.TimeField(blank=True, null=True)
    alert_email_address_1 = models.EmailField(blank=True, null=True)
    alert_email_address_2 = models.EmailField(blank=True, null=True)
    alert_email_address_3 = models.EmailField(blank=True, null=True)
    alert_email_address_4 = models.EmailField(blank=True, null=True)
    alert_email_address_5 = models.EmailField(blank=True, null=True)
    alert_email_address_6 = models.EmailField(blank=True, null=True)
    alert_email_address_7 = models.EmailField(blank=True, null=True)
    alert_email_address_8 = models.EmailField(blank=True, null=True)
    alert_email_address_9 = models.EmailField(blank=True, null=True)
    alert_email_address_10 = models.EmailField(blank=True, null=True)

    #sms alerts
    sms_alert=models.BooleanField(default=False, null=True)
    sms_time = models.TimeField(blank=True, null=True)
    user1=models.CharField(max_length=25, null=True, blank=True)
    user1_num=models.IntegerField(null=True)
    user2=models.CharField(max_length=25, null=True, blank=True)
    user2_num=models.IntegerField(null=True)
    user3=models.CharField(max_length=25, null=True, blank=True)
    user3_num=models.IntegerField(null=True)
    user4=models.CharField(max_length=25, null=True, blank=True)
    user4_num=models.IntegerField(null=True)
    user5=models.CharField(max_length=25, null=True, blank=True)
    user5_num=models.IntegerField(null=True)
    user6=models.CharField(max_length=25, null=True, blank=True)
    user6_num=models.IntegerField(null=True)
    user7=models.CharField(max_length=25, null=True, blank=True)
    user7_num=models.IntegerField(null=True)
    user8=models.CharField(max_length=25, null=True, blank=True)
    user8_num=models.IntegerField(null=True)
    user9=models.CharField(max_length=25, null=True, blank=True)
    user9_num=models.IntegerField(null=True)
    user10=models.CharField(max_length=25, null=True, blank=True)
    user10_num=models.IntegerField(null=True)



    def __str__(self):
        return self.department_name

           
class User_role(models.Model):
    role = models.CharField(max_length=50, primary_key=True)
    description  = models.TextField()

    def __str__(self):
        return self.role

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
    pass_change = models.BooleanField(default=False)
    created_at = models.DateTimeField(null=True)
    
    def set_password(self, raw_password):
        self.password = make_password(raw_password)

    def set_login_name(self, raw_login_name):
        self.login_name = make_password(raw_login_name)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)

    def check_login_name(self, raw_login_name):
        return check_password(raw_login_name, self.login_name)

    def save(self, *args, **kwargs):
        if not self.password.startswith('pbkdf2_'):  # Django uses pbkdf2 by default
            self.set_password(self.password)
        if not self.login_name.startswith('pbkdf2_'):  # Hash the login_name similarly
            self.set_login_name(self.login_name)        
        super().save(*args, **kwargs)

    def __str__(self):
        return self.username


class user_access_db(models.Model):
    
    role = models.CharField(max_length=50)

    org_v = models.BooleanField(default=False)
    org_a = models.BooleanField(default=False)
    org_e = models.BooleanField(default=False)
    org_d = models.BooleanField(default=False)
    org_p = models.BooleanField(default=False)

    c_group_v = models.BooleanField(default=False)
    c_group_a = models.BooleanField(default=False)
    c_group_e = models.BooleanField(default=False)
    c_group_d = models.BooleanField(default=False)
    c_group_p = models.BooleanField(default=False)

    dep_v = models.BooleanField(default=False)
    dep_a = models.BooleanField(default=False)
    dep_e = models.BooleanField(default=False)
    dep_d = models.BooleanField(default=False)
    dep_p = models.BooleanField(default=False)

    role_v = models.BooleanField(default=False)
    role_a = models.BooleanField(default=False)
    role_e = models.BooleanField(default=False)
    role_d = models.BooleanField(default=False)
    role_p = models.BooleanField(default=False)

    user_v = models.BooleanField(default=False)
    user_a = models.BooleanField(default=False)
    user_e = models.BooleanField(default=False)
    user_d = models.BooleanField(default=False)
    user_p = models.BooleanField(default=False)

    app_v = models.BooleanField(default=False)
    app_a = models.BooleanField(default=False)
    app_e = models.BooleanField(default=False)
    app_d = models.BooleanField(default=False)
    app_p = models.BooleanField(default=False)

    back_v = models.BooleanField(default=False)
    back_a = models.BooleanField(default=False)
    back_e = models.BooleanField(default=False)
    back_d = models.BooleanField(default=False)
    back_p = models.BooleanField(default=False)

    sys_v = models.BooleanField(default=False)
    sys_a = models.BooleanField(default=False)
    sys_e = models.BooleanField(default=False)
    sys_d = models.BooleanField(default=False)
    sys_p = models.BooleanField(default=False)

    res_v = models.BooleanField(default=False)
    res_a = models.BooleanField(default=False)
    res_e = models.BooleanField(default=False)
    res_d = models.BooleanField(default=False)
    res_p = models.BooleanField(default=False)

    def __str__(self):
        return self.role
    
class AppSettings(models.Model):

    #App settings fields

    # Email settings fields
    email_sys_set = models.CharField(max_length=100, default='Enable')
    email_host = models.CharField(max_length=100, null=True)
    email_host_user = models.EmailField(null=True)
    email_host_password = models.CharField(max_length=100, null=True)
    email_port = models.IntegerField(null=True)
    email_signature = models.TextField(blank=True, null=True)

    # SMS settings fields
    sms_sys_set = models.CharField(max_length=10, default='Enable')
    comm_port = models.CharField(max_length=10, blank=True, null=True)
    parity = models.CharField(max_length=10, blank=True, null=True)
    baud_rate = models.CharField(max_length=10, blank=True, null=True)
    data_bits = models.IntegerField(blank=True, null=True)
    stop_bits = models.IntegerField(blank=True, null=True)
    flow_control = models.CharField(max_length=10, blank=True, null=True)

    #App Settings Fields
    passwordchange=models.IntegerField(null=True)
    lockcount=models.IntegerField(null=True)
    autologouttime=models.TimeField(null=True)

   #Whatsapp Settings Fields
    whatsapp_comm_port = models.CharField(max_length=10, blank=True, null=True)
    whatsapp_parity = models.CharField(max_length=10, blank=True, null=True)
    whatsapp_baud_rate = models.CharField(max_length=10, blank=True, null=True)
    whatsapp_data_bits = models.IntegerField(blank=True, null=True)
    whatsapp_stop_bits = models.IntegerField(blank=True, null=True)
    whatsapp_flow_control = models.CharField(max_length=10, blank=True, null=True)




    #Whatsapp fields


    def _str_(self):
        return f"{self.department}"
    
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

    department=models.ForeignKey(Department, null=True, on_delete=models.SET_NULL)
    equip_name = models.CharField(max_length=255)
    status = models.CharField(max_length=10, choices=EQUIPMENT_STATUS_CHOICES)
    ip_address = models.GenericIPAddressField()
    interval = models.IntegerField()
    equipment_type = models.CharField(max_length=255)
    door_access_type = models.CharField(max_length=15, choices=EQUIPMENT_ACCESS_CHOICES)
    
    # Biometric fields
    biometric_banner_text = models.CharField(max_length=255, blank=True, null=True)
    biometric_ip_address = models.GenericIPAddressField(blank=True, null=True)

    def __str__(self):
        return self.equip_name


class PLCUser(models.Model):
    equipment = models.ForeignKey(Equipment, on_delete=models.CASCADE, related_name="plc_users")
    username = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.username} ({self.equipment.equip_name})"


class BiometricUser(models.Model):
    equipment = models.ForeignKey(Equipment, on_delete=models.CASCADE, related_name="biometric_users")
    username = models.CharField(max_length=255)
    card_number = models.CharField(max_length=255)

    def __str__(self):
        return f"{self.username} ({self.card_number}) - {self.equipment.equip_name}"


class UserActivityLog(models.Model):
    user = models.CharField(max_length=30)
    log_date = models.DateField(default=timezone.now)
    log_time = models.TimeField(default=timezone.now)
    event_name = models.CharField(max_length=255)

    def _str_(self):
        return self.user


class TemperatureHumidityRecord(models.Model):
    equip_name = models.ForeignKey(Equipment, on_delete=models.SET_NULL, null=True)
    date = models.DateField()
    time = models.TimeField(blank=True, null=True)
    set_temp = models.FloatField(blank=True, null=True)
    t_low_alarm = models.FloatField(blank=True, null=True)
    t_low_alert = models.FloatField(blank=True, null=True)
    t_high_alarm = models.FloatField(blank=True, null=True)
    t_high_alert = models.FloatField(blank=True, null=True) 
    tmp_1 = models.FloatField(blank=True, null=True)
    tmp_2 = models.FloatField(blank=True, null=True)
    tmp_3 = models.FloatField(blank=True, null=True)
    tmp_4 = models.FloatField(blank=True, null=True)
    tmp_5 = models.FloatField(blank=True, null=True)
    tmp_6 = models.FloatField(blank=True, null=True)
    tmp_7 = models.FloatField(blank=True, null=True)
    tmp_8 = models.FloatField(blank=True, null=True)
    tmp_9 = models.FloatField(blank=True, null=True)
    tmp_10 = models.FloatField(blank=True, null=True)
    set_rh = models.FloatField(blank=True, null=True)
    rh_low_alarm = models.FloatField(blank=True, null=True)
    rh_low_alert = models.FloatField(blank=True, null=True)
    rh_high_alarm = models.FloatField(blank=True, null=True)
    rh_high_alert = models.FloatField(blank=True, null=True)
    rh_1 = models.FloatField(blank=True, null=True)
    rh_2 = models.FloatField(blank=True, null=True)
    rh_3 = models.FloatField(blank=True, null=True)
    rh_4 = models.FloatField(blank=True, null=True)
    rh_5 = models.FloatField(blank=True, null=True)
    rh_6 = models.FloatField(blank=True, null=True)
    rh_7 = models.FloatField(blank=True, null=True)
    rh_8 = models.FloatField(blank=True, null=True)
    rh_9 = models.FloatField(blank=True, null=True)
    rh_10 = models.FloatField(blank=True, null=True)

    def __str__(self):
        return f"Date: {self.date}, Time: {self.time}"


class PasswordHistory(models.Model):
    user = models.ForeignKey(User, null=True, on_delete=models.CASCADE)
    password = models.CharField(max_length=128, null=True)  
    created_at = models.DateTimeField(auto_now_add=True, null=True) 

    def save(self, *args, **kwargs):
        if not self.password.startswith('pbkdf2_'):
            self.password = make_password(self.password)
       
        user_passwords = PasswordHistory.objects.filter(user=self.user).order_by('created_at')

        
        if user_passwords.count() >= 3:
            user_passwords.first().delete()  

        super().save(*args, **kwargs)

    def check_password(self, raw_password):
        return check_password(raw_password, self.password)
    
    def __str__(self):
        return self.user.username
    

    
class Alarm_codes(models.Model):
    alarm_log=models.CharField(max_length=100, null=True)
    code=models.IntegerField(unique=True)
    remarks=models.TextField(null=True)

class alarm_logs(models.Model):
    equipment=models.ForeignKey(Equipment, on_delete=models.CASCADE, null=True)
    alarm_code=models.ForeignKey(Alarm_codes, on_delete=models.CASCADE, to_field='code')
    time=models.TimeField()
    date=models.DateField()
    comments=models.CharField(max_length=255, null=True)
    acknowledge=models.BooleanField(null=True, default=False)
    ack_date=models.DateField(null=True)
    ack_user=models.CharField(max_length=50, null=True)


    