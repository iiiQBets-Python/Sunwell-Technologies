import threading
import queue
import serial
import time
from .models import AppSettings, Sms_logs, Equipment
from datetime import datetime

sms_queue = queue.Queue()
sms_lock = threading.Lock()  

# Background worker for processing SMS
def sms_worker():
    """Processes SMS messages in a FIFO order."""
    while True:
        sms_details = sms_queue.get()  # Get the next SMS from the queue
        if sms_details is None:  # Exit signal
            break

        send_sms_from_queue(sms_details)  # Process and send the SMS
        sms_queue.task_done()  # Mark the task as complete

# Start the worker thread
sms_thread = threading.Thread(target=sms_worker, daemon=True)
sms_thread.start()

def add_to_sms_queue(number, message, equipment, alarm_id, sys_sms):

    print("EQP ", equipment)
    sms_queue.put({
        'number': number,
        'message': message,
        'sys_sms': sys_sms,
        'equipment': equipment,
        'alarm_id': alarm_id,
    })
  
def send_sms_from_queue(sms_details):
    print("SMS Details", sms_details)
    number=sms_details["number"]
    message=sms_details["message"]
    equipment=sms_details["equipment"]
    alarm_id=sms_details["alarm_id"]
    sys_sms=sms_details["sys_sms"]
    Eqp=""
    if equipment is not None:
        Eqp=Equipment.objects.get(id=equipment)
    else:
        Eqp=None
    try:
        with sms_lock:  
            settings = AppSettings.objects.first()
            print(f"Initializing modem on port {settings.comm_port} with baud rate {settings.baud_rate}")
            start_time = time.time()
            with serial.Serial(
                port=settings.comm_port,
                baudrate=settings.baud_rate,
                bytesize=serial.EIGHTBITS,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                timeout=2  
            ) as ser:
                print(f"Serial port {settings.comm_port} opened: {ser.is_open}")
                ser.write(b'AT\r')  
                ser.flush()
                time.sleep(1)  
                response = ser.read_all().decode(errors="ignore").strip()
                print(f"AT command response: {response}")

                if "OK" not in response:
                    print(f"Modem not responding to 'AT' command. Response: {response}")
                    return

                # Set SMS mode to text
                ser.write(b'AT+CMGF=1\r')  # Set text mode
                ser.flush()
                time.sleep(1)
                response = ser.read_all().decode(errors="ignore").strip()
                print(f"AT+CMGF response: {response}")

                if "OK" not in response:
                    print(f"Failed to set SMS mode. Response: {response}")
                    return

                for name, num in number.items():
                    print("type of number:", type(num))
                    # int(num)
                    ser.write(f'AT+CMGS="{num}"\r'.encode())
                    ser.flush()
                    time.sleep(2)
                    response = ser.read_all().decode(errors="ignore").strip()
                    print(f"AT+CMGS response: {response}")

                    if ">" not in response:
                        print(f"Modem did not prompt for SMS message input. Response: {response}")
                        return

                    # Send the message and terminate with Ctrl+Z
                    ser.write((message + '\x1A').encode())  # Ctrl+Z
                    ser.flush()

                    # Wait for the final response
                    time.sleep(5)
                    response = ser.read_all().decode(errors="ignore").strip()
                    print(f"Final response after sending SMS: {response}")

                    status = "Sent" if "+CMGS" in response else "Failed"
                    print(f"SMS status: {status}")
                    Sms_logs.objects.create(
                        time=datetime.now().time(),
                        date=datetime.now().date(),
                        sys_sms=sys_sms,
                        to_num=num,
                        msg_body=message,
                        status=status,
                        equipment=Eqp,
                    )
            ser.close()

    except Exception as e:
        print(f"Error while sending SMS: {e}")
        # ser.close()
        Sms_logs.objects.create(
            time=datetime.now().time(),
            date=datetime.now().date(),
            sys_sms=sys_sms,
            to_num=sms_details['number'],
            msg_body=message,
            status="Failed",
            equipment=Eqp,
        )
    end_time = time.time()  
    print(f"Total time taken to send all messages: {end_time - start_time} seconds")
    

