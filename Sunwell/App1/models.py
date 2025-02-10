
from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
import base64
from django.core.validators import MaxValueValidator, MinValueValidator
from django.utils.timezone import now

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
    department_name = models.CharField(unique=True, max_length=50, null=False)
    commGroup = models.ForeignKey(CommGroup, on_delete=models.CASCADE)
    header_note = models.CharField(max_length=100, null=True)
    footer_note = models.CharField(max_length=100, null=True)
    report_datetime_stamp = models.BooleanField(default=True, null=True)
    email_sys = models.CharField(max_length=10, default='Enable', null=True)
    email_delay = models.CharField(default=0, max_length=50, blank=True, null=True)
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
    sms_sys = models.CharField(max_length=10, default='Enable', null=True)
    sms_delay = models.CharField(default=0, max_length=50, blank=True, null=True)
    sms_time = models.TimeField(blank=True, null=True)
    user1=models.CharField(max_length=25, null=True, blank=True)
    user1_num=models.BigIntegerField(null=True, blank=True)
    user2=models.CharField(max_length=25, null=True, blank=True)
    user2_num=models.BigIntegerField(null=True, blank=True)
    user3=models.CharField(max_length=25, null=True, blank=True)
    user3_num=models.BigIntegerField(null=True, blank=True)
    user4=models.CharField(max_length=25, null=True, blank=True)
    user4_num=models.BigIntegerField(null=True, blank=True)
    user5=models.CharField(max_length=25, null=True, blank=True)
    user5_num=models.BigIntegerField(null=True, blank=True)
    user6=models.CharField(max_length=25, null=True, blank=True)
    user6_num=models.BigIntegerField(null=True, blank=True)
    user7=models.CharField(max_length=25, null=True, blank=True)
    user7_num=models.BigIntegerField(null=True, blank=True)
    user8=models.CharField(max_length=25, null=True, blank=True)
    user8_num=models.BigIntegerField(null=True, blank=True)
    user9=models.CharField(max_length=25, null=True, blank=True)
    user9_num=models.BigIntegerField(null=True, blank=True)
    user10=models.CharField(max_length=25, null=True, blank=True)
    user10_num=models.BigIntegerField(null=True, blank=True)



    def __str__(self):
        return self.department_name

           
class User_role(models.Model):
    role = models.CharField(max_length=50, unique=True)
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
    last_password_change = models.DateTimeField(default=now)
    account_lock=models.BooleanField(default=False)
    failed_attempts = models.IntegerField(default=0)
    
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

    e_conf_v = models.BooleanField(default=False)
    e_conf_a = models.BooleanField(default=False)
    e_conf_e = models.BooleanField(default=False)
    e_conf_d = models.BooleanField(default=False)

    e_set_v = models.BooleanField(default=False)
    e_set_a = models.BooleanField(default=False)
    e_set_e = models.BooleanField(default=False)
    e_set_d = models.BooleanField(default=False)

    v_log_v = models.BooleanField(default=False)
    v_log_p = models.BooleanField(default=False)

    a_log_v = models.BooleanField(default=False)
    a_log_p = models.BooleanField(default=False)

    mkt_v = models.BooleanField(default=False)
    mkt_p = models.BooleanField(default=False)


    sum_v = models.BooleanField(default=False)
    dis_v = models.BooleanField(default=False)
    io_v = models.BooleanField(default=False)
    comp_v = models.BooleanField(default=False)

    u_act_v = models.BooleanField(default=False)
    u_act_p = models.BooleanField(default=False)

    u_equ_v = models.BooleanField(default=False)
    u_equ_p = models.BooleanField(default=False)

    a_act_v = models.BooleanField(default=False)
    a_act_p = models.BooleanField(default=False)

    e_aud_v = models.BooleanField(default=False)
    e_aud_p = models.BooleanField(default=False)

    s_act_v = models.BooleanField(default=False)
    s_act_p = models.BooleanField(default=False)

    def _str_(self):
        return self.role

 
class AppSettings(models.Model):

    #App settings fields

    # Email settings fields
    email_sys_set = models.BooleanField(default=False)
    email_host = models.CharField(max_length=100, null=True)
    email_host_user = models.EmailField(null=True)
    email_host_password = models.CharField(max_length=100, null=True)
    email_port = models.IntegerField(null=True)
    email_signature = models.TextField(blank=True, null=True)

    # SMS settings fields
    sms_sys_set = models.BooleanField(default=False)
    comm_port = models.CharField(max_length=10, blank=True, null=True)
    parity = models.CharField(max_length=10, blank=True, null=True)
    baud_rate = models.CharField(max_length=10, blank=True, null=True)
    data_bits = models.IntegerField(blank=True, null=True)
    stop_bits = models.IntegerField(blank=True, null=True)
    flow_control = models.CharField(max_length=10, blank=True, null=True)

    #App Settings Fields
    passwordchange=models.IntegerField(null=True)
    lockcount=models.IntegerField(null=True)
    autologouttime=models.IntegerField(null=True)

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
    equip_name = models.CharField(max_length=255, unique=True)
    status = models.CharField(max_length=10, choices=EQUIPMENT_STATUS_CHOICES)
    ip_address = models.GenericIPAddressField(unique=True)
    interval = models.IntegerField()
    equipment_type = models.CharField(max_length=255)
    door_access_type = models.CharField(max_length=15, choices=EQUIPMENT_ACCESS_CHOICES)
    
    # Biometric fields
    biometric_banner_text = models.CharField(max_length=255, blank=True, null=True)
    biometric_ip_address = models.GenericIPAddressField(blank=True, null=True)

    # Temperature Set values
    set_value = models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    low_alarm = models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    high_alarm = models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    high_alert= models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    low_alert= models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    cooling=models.BooleanField(null=True, default=True)
    total_temp_sensors=models.IntegerField(blank=True, null=True)
    # Humidity Set Values
    set_value_hum = models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    low_alarm_hum = models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    high_alarm_hum = models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    high_alert_hum= models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    low_alert_hum= models.DecimalField(max_digits=3, decimal_places=1, blank=True, null=True)
    cooling_hum=models.BooleanField(null=True, default=True)
    total_humidity_sensors=models.IntegerField(blank=True, null=True)

    online = models.BooleanField(null=True, default=False)


    def __str__(self):
        return self.equip_name


class PLCUser(models.Model):
    equipment = models.ForeignKey(Equipment, on_delete=models.CASCADE, related_name="plc_users")
    code = models.IntegerField(null=True, unique=True)
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
        return f"Eqp: {self.equip_name}, Date: {self.date}, Time: {self.time}"


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

class Alarm_logs(models.Model):
    equipment=models.ForeignKey(Equipment, on_delete=models.CASCADE, null=True)
    alarm_code=models.ForeignKey(Alarm_codes, on_delete=models.CASCADE, to_field='code')
    time=models.TimeField()
    date=models.DateField()
    comments=models.CharField(max_length=255, null=True)
    acknowledge=models.BooleanField(null=True, default=False)
    ack_date=models.DateField(null=True)
    ack_time=models.TimeField(null=True)
    ack_user=models.CharField(max_length=50, null=True)




class Email_logs(models.Model):
    equipment=models.ForeignKey(Equipment, on_delete=models.CASCADE, null=True, blank=True)
    time=models.TimeField()
    date=models.DateField()
    sys_mail = models.BooleanField(default=False)
    to_email = models.EmailField()
    email_sub = models.CharField(max_length=100, null=True)
    email_body = models.TextField(null=True)
    status = models.CharField(max_length=10, null=True)

    def __int__(self):
        return self.equipment

class Sms_logs(models.Model):
    equipment=models.ForeignKey(Equipment, on_delete=models.CASCADE, null=True, blank=True)
    time=models.TimeField()
    date=models.DateField()
    sys_sms = models.BooleanField(default=False)
    to_num = models.BigIntegerField(null=True, blank=True)
    user_name = models.CharField(max_length=100, null=True)
    msg_body = models.TextField(null=True)
    status = models.CharField(max_length=10, null=True)

    def __int__(self):
        return self.equipment



class Equipmentwrite(models.Model):
    equipment=models.ForeignKey(Equipment, on_delete=models.CASCADE, null=True, blank=True)
    time=models.TimeField()
    date=models.DateField()
    label=models.CharField(max_length=50,null=True)
    value=models.DecimalField(decimal_places=2, max_digits=5)
    status=models.CharField(max_length=10)
    login_name=models.CharField(max_length=50, null=True)
    old_value=models.DecimalField(decimal_places=2, max_digits=5, null=True)
    comment=models.CharField(max_length=200, null=True)

    def __int__(self):
        return self.equipment

# class dooraccesslog(models.Model):


class EquipParameter(models.Model):
    equipment=models.ForeignKey(Equipment, on_delete=models.CASCADE, null=True, blank=True)
    t1color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t2color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t3color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t4color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t5color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t6color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t7color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t8color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t9color = models.CharField(max_length=20, null=True, blank=True, default='black')
    t10color = models.CharField(max_length=20, null=True, blank=True, default='black')

    rh1color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh2color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh3color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh4color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh5color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh6color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh7color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh8color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh9color = models.CharField(max_length=20, null=True, blank=True, default='black')
    rh10color = models.CharField(max_length=20, null=True, blank=True, default='black')

    def __int__(self):
        return self.equipment
    

class emailalert(models.Model):
    equipment_name = models.ForeignKey(Equipment, on_delete=models.CASCADE)

  
    code_1001 = models.BooleanField(default=False, help_text="Temp 1 Low Alarm")
    code_1002 = models.BooleanField(default=False, help_text="Temp 2 Low Alarm")
    code_1003 = models.BooleanField(default=False, help_text="Temp 3 Low Alarm")
    code_1004 = models.BooleanField(default=False, help_text="Temp 4 Low Alarm")
    code_1005 = models.BooleanField(default=False, help_text="Temp 5 Low Alarm")
    code_1006 = models.BooleanField(default=False, help_text="Temp 6 Low Alarm")
    code_1007 = models.BooleanField(default=False, help_text="Temp 7 Low Alarm")
    code_1008 = models.BooleanField(default=False, help_text="Temp 8 Low Alarm")
    code_1009 = models.BooleanField(default=False, help_text="Temp 9 Low Alarm")
    code_1010 = models.BooleanField(default=False, help_text="Temp 10 Low Alarm")

    # Temperature Alarms (High)
    code_1011 = models.BooleanField(default=False, help_text="Temp 1 High Alarm")
    code_1012 = models.BooleanField(default=False, help_text="Temp 2 High Alarm")
    code_1013 = models.BooleanField(default=False, help_text="Temp 3 High Alarm")
    code_1014 = models.BooleanField(default=False, help_text="Temp 4 High Alarm")
    code_1015 = models.BooleanField(default=False, help_text="Temp 5 High Alarm")
    code_1016 = models.BooleanField(default=False, help_text="Temp 6 High Alarm")
    code_1017 = models.BooleanField(default=False, help_text="Temp 7 High Alarm")
    code_1018 = models.BooleanField(default=False, help_text="Temp 8 High Alarm")
    code_1019 = models.BooleanField(default=False, help_text="Temp 9 High Alarm")
    code_1020 = models.BooleanField(default=False, help_text="Temp 10 High Alarm")

    # Temperature Within Limits
    code_1021 = models.BooleanField(default=False, help_text="Temp 1 Within Limit")
    code_1022 = models.BooleanField(default=False, help_text="Temp 2 Within Limit")
    code_1023 = models.BooleanField(default=False, help_text="Temp 3 Within Limit")
    code_1024 = models.BooleanField(default=False, help_text="Temp 4 Within Limit")
    code_1025 = models.BooleanField(default=False, help_text="Temp 5 Within Limit")
    code_1026 = models.BooleanField(default=False, help_text="Temp 6 Within Limit")
    code_1027 = models.BooleanField(default=False, help_text="Temp 7 Within Limit")
    code_1028 = models.BooleanField(default=False, help_text="Temp 8 Within Limit")
    code_1029 = models.BooleanField(default=False, help_text="Temp 9 Within Limit")
    code_1030 = models.BooleanField(default=False, help_text="Temp 10 Within Limit")

    # Circuit Failures and Power Issues
    code_1031 = models.BooleanField(default=False, help_text="CS 1 Circuit Fail")
    code_1032 = models.BooleanField(default=False, help_text="CS 2 Circuit Fail")
    code_1033 = models.BooleanField(default=False, help_text="Dry Heater Circuit Fail")
    code_1034 = models.BooleanField(default=False, help_text="Mains Power Fail")
    code_1035 = models.BooleanField(default=False, help_text="Mains Power Resume")

    # Miscellaneous Alerts
    code_1036 = models.BooleanField(default=False, help_text="LT Thermostat Trip")
    code_1037 = models.BooleanField(default=False, help_text="HT Thermostat Trip")
    code_1038 = models.BooleanField(default=False, help_text="Door Open")
    code_1039 = models.BooleanField(default=False, help_text="Door Closed")
    code_1040 = models.BooleanField(default=False, help_text="Water Level Low")
    code_1041 = models.BooleanField(default=False, help_text="Water Level OK")

    # Relative Humidity (Low Alarms)
    code_1042 = models.BooleanField(default=False, help_text="RH 1 Low Alarm")
    code_1043 = models.BooleanField(default=False, help_text="RH 2 Low Alarm")
    code_1044 = models.BooleanField(default=False, help_text="RH 3 Low Alarm")
    code_1045 = models.BooleanField(default=False, help_text="RH 4 Low Alarm")
    code_1046 = models.BooleanField(default=False, help_text="RH 5 Low Alarm")
    code_1047 = models.BooleanField(default=False, help_text="RH 6 Low Alarm")
    code_1048 = models.BooleanField(default=False, help_text="RH 7 Low Alarm")
    code_1049 = models.BooleanField(default=False, help_text="RH 8 Low Alarm")
    code_1050 = models.BooleanField(default=False, help_text="RH 9 Low Alarm")
    code_1051 = models.BooleanField(default=False, help_text="RH 10 Low Alarm")

    # Relative Humidity (High Alarms)
    code_1053 = models.BooleanField(default=False, help_text="RH 1 High Alarm")
    code_1054 = models.BooleanField(default=False, help_text="RH 2 High Alarm")
    code_1055 = models.BooleanField(default=False, help_text="RH 3 High Alarm")
    code_1056 = models.BooleanField(default=False, help_text="RH 4 High Alarm")
    code_1057 = models.BooleanField(default=False, help_text="RH 5 High Alarm")
    code_1058 = models.BooleanField(default=False, help_text="RH 6 High Alarm")
    code_1059 = models.BooleanField(default=False, help_text="RH 7 High Alarm")
    code_1060 = models.BooleanField(default=False, help_text="RH 8 High Alarm")
    code_1061 = models.BooleanField(default=False, help_text="RH 9 High Alarm")
    code_1062 = models.BooleanField(default=False, help_text="RH 10 High Alarm")

    # Relative Humidity (Within Limits)
    code_1063 = models.BooleanField(default=False, help_text="RH 1 Within Limit")
    code_1064 = models.BooleanField(default=False, help_text="RH 2 Within Limit")
    code_1065 = models.BooleanField(default=False, help_text="RH 3 Within Limit")
    code_1066 = models.BooleanField(default=False, help_text="RH 4 Within Limit")
    code_1067 = models.BooleanField(default=False, help_text="RH 5 Within Limit")
    code_1068 = models.BooleanField(default=False, help_text="RH 6 Within Limit")
    code_1069 = models.BooleanField(default=False, help_text="RH 7 Within Limit")
    code_1070 = models.BooleanField(default=False, help_text="RH 8 Within Limit")
    code_1071 = models.BooleanField(default=False, help_text="RH 9 Within Limit")
    code_1072 = models.BooleanField(default=False, help_text="RH 10 Within Limit")


    code_2001 = models.BooleanField(default=False, help_text="Door Access By User 1")
    code_2002 = models.BooleanField(default=False, help_text="Door Access By User 2")
    code_2003 = models.BooleanField(default=False, help_text="Door Access By User 3")
    code_2004 = models.BooleanField(default=False, help_text="Door Access By User 4")
    code_2005 = models.BooleanField(default=False, help_text="Door Access By User 5")
    code_2006 = models.BooleanField(default=False, help_text="Door Access By User 6")
    code_2007 = models.BooleanField(default=False, help_text="Door Access By User 7")
    code_2008 = models.BooleanField(default=False, help_text="Door Access By User 8")
    code_2009 = models.BooleanField(default=False, help_text="Door Access By User 9")
    code_2010 = models.BooleanField(default=False, help_text="Door Access By User 10")
    code_2011 = models.BooleanField(default=False, help_text="Door Access By User 11")
    code_2012 = models.BooleanField(default=False, help_text="Door Access By User 12")
    code_2013 = models.BooleanField(default=False, help_text="Door Access By User 13")
    code_2014 = models.BooleanField(default=False, help_text="Door Access By User 14")
    code_2015 = models.BooleanField(default=False, help_text="Door Access By User 15")

    


class smsalert(models.Model):
    equipment_name = models.ForeignKey(Equipment, on_delete=models.CASCADE)

  
    code_1001 = models.BooleanField(default=False, help_text="Temp 1 Low Alarm")
    code_1002 = models.BooleanField(default=False, help_text="Temp 2 Low Alarm")
    code_1003 = models.BooleanField(default=False, help_text="Temp 3 Low Alarm")
    code_1004 = models.BooleanField(default=False, help_text="Temp 4 Low Alarm")
    code_1005 = models.BooleanField(default=False, help_text="Temp 5 Low Alarm")
    code_1006 = models.BooleanField(default=False, help_text="Temp 6 Low Alarm")
    code_1007 = models.BooleanField(default=False, help_text="Temp 7 Low Alarm")
    code_1008 = models.BooleanField(default=False, help_text="Temp 8 Low Alarm")
    code_1009 = models.BooleanField(default=False, help_text="Temp 9 Low Alarm")
    code_1010 = models.BooleanField(default=False, help_text="Temp 10 Low Alarm")

    # Temperature Alarms (High)
    code_1011 = models.BooleanField(default=False, help_text="Temp 1 High Alarm")
    code_1012 = models.BooleanField(default=False, help_text="Temp 2 High Alarm")
    code_1013 = models.BooleanField(default=False, help_text="Temp 3 High Alarm")
    code_1014 = models.BooleanField(default=False, help_text="Temp 4 High Alarm")
    code_1015 = models.BooleanField(default=False, help_text="Temp 5 High Alarm")
    code_1016 = models.BooleanField(default=False, help_text="Temp 6 High Alarm")
    code_1017 = models.BooleanField(default=False, help_text="Temp 7 High Alarm")
    code_1018 = models.BooleanField(default=False, help_text="Temp 8 High Alarm")
    code_1019 = models.BooleanField(default=False, help_text="Temp 9 High Alarm")
    code_1020 = models.BooleanField(default=False, help_text="Temp 10 High Alarm")

    # Temperature Within Limits
    code_1021 = models.BooleanField(default=False, help_text="Temp 1 Within Limit")
    code_1022 = models.BooleanField(default=False, help_text="Temp 2 Within Limit")
    code_1023 = models.BooleanField(default=False, help_text="Temp 3 Within Limit")
    code_1024 = models.BooleanField(default=False, help_text="Temp 4 Within Limit")
    code_1025 = models.BooleanField(default=False, help_text="Temp 5 Within Limit")
    code_1026 = models.BooleanField(default=False, help_text="Temp 6 Within Limit")
    code_1027 = models.BooleanField(default=False, help_text="Temp 7 Within Limit")
    code_1028 = models.BooleanField(default=False, help_text="Temp 8 Within Limit")
    code_1029 = models.BooleanField(default=False, help_text="Temp 9 Within Limit")
    code_1030 = models.BooleanField(default=False, help_text="Temp 10 Within Limit")

    # Circuit Failures and Power Issues
    code_1031 = models.BooleanField(default=False, help_text="CS 1 Circuit Fail")
    code_1032 = models.BooleanField(default=False, help_text="CS 2 Circuit Fail")
    code_1033 = models.BooleanField(default=False, help_text="Dry Heater Circuit Fail")
    code_1034 = models.BooleanField(default=False, help_text="Mains Power Fail")
    code_1035 = models.BooleanField(default=False, help_text="Mains Power Resume")

    # Miscellaneous Alerts
    code_1036 = models.BooleanField(default=False, help_text="LT Thermostat Trip")
    code_1037 = models.BooleanField(default=False, help_text="HT Thermostat Trip")
    code_1038 = models.BooleanField(default=False, help_text="Door Open")
    code_1039 = models.BooleanField(default=False, help_text="Door Closed")
    code_1040 = models.BooleanField(default=False, help_text="Water Level Low")
    code_1041 = models.BooleanField(default=False, help_text="Water Level OK")

    # Relative Humidity (Low Alarms)
    code_1042 = models.BooleanField(default=False, help_text="RH 1 Low Alarm")
    code_1043 = models.BooleanField(default=False, help_text="RH 2 Low Alarm")
    code_1044 = models.BooleanField(default=False, help_text="RH 3 Low Alarm")
    code_1045 = models.BooleanField(default=False, help_text="RH 4 Low Alarm")
    code_1046 = models.BooleanField(default=False, help_text="RH 5 Low Alarm")
    code_1047 = models.BooleanField(default=False, help_text="RH 6 Low Alarm")
    code_1048 = models.BooleanField(default=False, help_text="RH 7 Low Alarm")
    code_1049 = models.BooleanField(default=False, help_text="RH 8 Low Alarm")
    code_1050 = models.BooleanField(default=False, help_text="RH 9 Low Alarm")
    code_1051 = models.BooleanField(default=False, help_text="RH 10 Low Alarm")

    # Relative Humidity (High Alarms)
    code_1053 = models.BooleanField(default=False, help_text="RH 1 High Alarm")
    code_1054 = models.BooleanField(default=False, help_text="RH 2 High Alarm")
    code_1055 = models.BooleanField(default=False, help_text="RH 3 High Alarm")
    code_1056 = models.BooleanField(default=False, help_text="RH 4 High Alarm")
    code_1057 = models.BooleanField(default=False, help_text="RH 5 High Alarm")
    code_1058 = models.BooleanField(default=False, help_text="RH 6 High Alarm")
    code_1059 = models.BooleanField(default=False, help_text="RH 7 High Alarm")
    code_1060 = models.BooleanField(default=False, help_text="RH 8 High Alarm")
    code_1061 = models.BooleanField(default=False, help_text="RH 9 High Alarm")
    code_1062 = models.BooleanField(default=False, help_text="RH 10 High Alarm")

    # Relative Humidity (Within Limits)
    code_1063 = models.BooleanField(default=False, help_text="RH 1 Within Limit")
    code_1064 = models.BooleanField(default=False, help_text="RH 2 Within Limit")
    code_1065 = models.BooleanField(default=False, help_text="RH 3 Within Limit")
    code_1066 = models.BooleanField(default=False, help_text="RH 4 Within Limit")
    code_1067 = models.BooleanField(default=False, help_text="RH 5 Within Limit")
    code_1068 = models.BooleanField(default=False, help_text="RH 6 Within Limit")
    code_1069 = models.BooleanField(default=False, help_text="RH 7 Within Limit")
    code_1070 = models.BooleanField(default=False, help_text="RH 8 Within Limit")
    code_1071 = models.BooleanField(default=False, help_text="RH 9 Within Limit")
    code_1072 = models.BooleanField(default=False, help_text="RH 10 Within Limit")


    code_2001 = models.BooleanField(default=False, help_text="Door Access By User 1")
    code_2002 = models.BooleanField(default=False, help_text="Door Access By User 2")
    code_2003 = models.BooleanField(default=False, help_text="Door Access By User 3")
    code_2004 = models.BooleanField(default=False, help_text="Door Access By User 4")
    code_2005 = models.BooleanField(default=False, help_text="Door Access By User 5")
    code_2006 = models.BooleanField(default=False, help_text="Door Access By User 6")
    code_2007 = models.BooleanField(default=False, help_text="Door Access By User 7")
    code_2008 = models.BooleanField(default=False, help_text="Door Access By User 8")
    code_2009 = models.BooleanField(default=False, help_text="Door Access By User 9")
    code_2010 = models.BooleanField(default=False, help_text="Door Access By User 10")
    code_2011 = models.BooleanField(default=False, help_text="Door Access By User 11")
    code_2012 = models.BooleanField(default=False, help_text="Door Access By User 12")
    code_2013 = models.BooleanField(default=False, help_text="Door Access By User 13")
    code_2014 = models.BooleanField(default=False, help_text="Door Access By User 14")
    code_2015 = models.BooleanField(default=False, help_text="Door Access By User 15")
