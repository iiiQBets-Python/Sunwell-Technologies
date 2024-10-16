import subprocess
import string, random

CHARSET = string.ascii_uppercase + string.digits

# Function to convert integer to custom Base62 format
def int_to_base62(n):
    if n == 0:
        return CHARSET[0]
    base62 = []
    base = len(CHARSET)
    while n:
        n, remainder = divmod(n, base)
        base62.append(CHARSET[remainder])
    return ''.join(reversed(base62))

# Function to encode input string to Base62
def encode_to_custom_base62(input_string):
    input_bytes = input_string.encode('utf-8')
    input_int = int.from_bytes(input_bytes, 'big')
    return int_to_base62(input_int)

def base62_to_int(base62_str):
    base = len(CHARSET)
    num = 0
    for char in base62_str:
        num = num * base + CHARSET.index(char)
    return num


# Function to decode Base62 string
def decode_from_custom_base62(base62_str):
    input_int = base62_to_int(base62_str)
    input_bytes = input_int.to_bytes((input_int.bit_length() + 7) // 8, 'big')
    return input_bytes.decode('utf-8')

# Function to fetch motherboard serial number
def get_motherboard_serial_number():
    try:
        result = subprocess.run(['wmic', 'baseboard', 'get', 'serialnumber'], 
                                capture_output=True, text=True, check=True)
        output_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(output_lines) > 1:
            return output_lines[1]  # Return the serial number
        else:
            return None
    except subprocess.CalledProcessError as e:
        print(f"Error running command: {e}")
        return None
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return None


def generate_soft_key():
    try:
        pc_server_serial_no = get_motherboard_serial_number()
        if not pc_server_serial_no:
            return None
        random_num = random.randint(1000, 9999)
        input_string = f"{random_num}-IIIQST-{pc_server_serial_no}"
        return encode_to_custom_base62(input_string)
    except Exception as e:
        print(f"An error occurred while generating the soft key: {e}")
        return None

# Function to decode soft key and retrieve the PC/Server serial number
def decode_soft_key(soft_key):
    decoded_string = decode_from_custom_base62(soft_key)
    parts = decoded_string.split('-IIIQST-')
    
    if len(parts) != 2:
        raise ValueError("Invalid Soft Key Format")
    
    random_num = parts[0]  # random number in the key (can be ignored)
    pc_server_serial_no = parts[1]  # The PC/Server Serial No
    
    return pc_server_serial_no