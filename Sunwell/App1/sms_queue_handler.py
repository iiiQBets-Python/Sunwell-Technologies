import threading
import queue
import serial
import time
from .models import AppSettings, Sms_logs, Equipment
from datetime import datetime

sms_queue = queue.Queue()
sms_lock = threading.Lock()



def sms_worker():
    """Processes SMS messages in a FIFO order."""
    while True:
        try:
            sms_details = sms_queue.get()  
            if sms_details is None: 
                break

            send_sms_from_queue(sms_details) 
            sms_queue.task_done()  
        except Exception as e:
            print(f"Error in SMS worker: {e}")
            continue 


sms_thread = threading.Thread(target=sms_worker, daemon=True)
sms_thread.start()


def add_to_sms_queue(number, message, equipment, alarm_id, sys_sms):

    sms_queue.put({
        'number': number,
        'message': message,
        'sys_sms': sys_sms,
        'equipment': equipment,
        'alarm_id': alarm_id,
    })


def send_sms_from_queue(sms_details):
    numbers = sms_details["number"]
    message = sms_details["message"]
    equipment = sms_details["equipment"]
    sys_sms = sms_details["sys_sms"]
    Eqp = Equipment.objects.get(id=equipment) if equipment is not None else None

    settings = AppSettings.objects.first()

    for name, num in numbers.items():
        with sms_lock:
            try:
                # Attempt to open the serial port for communication with the modem
                with serial.Serial(
                    port=settings.comm_port,
                    baudrate=settings.baud_rate,
                    bytesize=serial.EIGHTBITS,
                    parity=serial.PARITY_NONE,
                    stopbits=serial.STOPBITS_ONE,
                    timeout=2
                ) as ser:
                    # Initialize modem and send message
                    ser.write(b'AT\r')
                    time.sleep(1)
                    response = ser.read_all().decode(errors="ignore").strip()

                    if "OK" not in response:
                        raise Exception("Initial AT command failed")
                    
                    ser.write(b'AT+CMGF=1\r')
                    time.sleep(1)
                    response = ser.read_all().decode(errors="ignore").strip()

                    if "OK" not in response:
                        raise Exception("Could not set text mode")

                    ser.write(f'AT+CMGS="{num}"\r'.encode())
                    time.sleep(3)
                    response = ser.read_all().decode(errors="ignore").strip()

                    if ">" not in response:
                        raise Exception("Modem did not return prompt character")

                    # Send the message and terminate with Ctrl+Z
                    ser.write((message + '\x1A').encode())  # Ctrl+Z
                    ser.flush()
                    time.sleep(8)
                    response = ser.read_all().decode(errors="ignore").strip()

                    status = "Sent" if "+CMGS" in response else "Failed"

                    # Log SMS sending status
                    Sms_logs.objects.create(
                        time=datetime.now().time(),
                        date=datetime.now().date(),
                        sys_sms=sys_sms,
                        to_num=num,
                        user_name=name,
                        msg_body=message,
                        status=status,
                        equipment=Eqp,
                    )

                    print(f"SMS to {name} ({num}): {status}")

            except FileNotFoundError as e:
                # Handle specific case when the serial port is not found
                print(f"Error sending SMS to {name} ({num}): could not open port '{settings.comm_port}': {str(e)}")
                Sms_logs.objects.create(
                    time=datetime.now().time(),
                    date=datetime.now().date(),
                    sys_sms=sys_sms,
                    to_num=num,
                    user_name=name,
                    msg_body=message,
                    status="Failed",
                    equipment=Eqp,
                )
                continue 

            except Exception as e:
                # Handle other general exceptions
                print(f"Error sending SMS to {name} ({num}): {str(e)}")
                Sms_logs.objects.create(
                    time=datetime.now().time(),
                    date=datetime.now().date(),
                    sys_sms=sys_sms,
                    to_num=num,
                    user_name=name,
                    msg_body=message,
                    status="Failed",
                    equipment=Eqp,
                )
                continue 


