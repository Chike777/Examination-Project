import sys
import time
from PyQt6.QtWidgets import QApplication, QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QTextEdit
from PyQt6.QtCore import QDateTime, QTimer
from mbedtls import pk, hmac, hashlib, cipher
import serial

# Constants
RSA_SIZE = 256
EXPONENT = 65537
SECRET_KEY = b"Fj2-;wu3Ur=ARl2!Tqi6IuKM3nG]8z1+"

SERIAL_BAUDRATE = 115200
CHECK_MSG = b"OKAY"
ERROR = True

# Global Variables
HMAC_KEY = None
hmac_hash = None
ser = None
client_rsa = None
server_rsa = None
SESSION_ID = None
aes = None

def initialize():
    global HMAC_KEY, hmac_hash, ser, client_rsa
    
    # Initialize HMAC key
    HMAC_KEY = hashlib.sha256()
    HMAC_KEY.update(SECRET_KEY)
    HMAC_KEY = HMAC_KEY.digest()
    hmac_hash = hmac.new(HMAC_KEY, digestmod="SHA256")
    
    # Initialize serial communication
    ser = serial.Serial(SERIAL_PORT, SERIAL_BAUDRATE)
    
    # Generate client RSA key pair
    client_rsa = pk.RSA()
    client_rsa.generate(RSA_SIZE * 8, EXPONENT)

def error_log():
    global ERROR
    ERROR = False

def client_close():
    global ser
    if ser and ser.is_open:
        ser.write(b"close")
        ser.close()
        ser = None

def client_send(buf: bytes):
    hmac_hash.update(buf)
    buf += hmac_hash.digest()
    if len(buf) != ser.write(buf):
        print("Connection Error")
        client_close()

def client_receive(size: int) -> bytes:
    buffer = ser.read(size + hmac_hash.digest_size)
    hmac_hash.update(buffer[0:size])
    buff = buffer[size:size + hmac_hash.digest_size]
    dig = hmac_hash.digest()
    if buff != dig:
        try:            
            error_log()
        except:
            client_close()

    return buffer[0:size]

def handshake():
    global client_rsa, server_rsa

    client_send(client_rsa.export_public_key())
    buffer = client_receive(2 * RSA_SIZE)

    SERVER_PUBLIC_KEY = client_rsa.decrypt(buffer[0:RSA_SIZE])
    SERVER_PUBLIC_KEY += client_rsa.decrypt(buffer[RSA_SIZE:2 * RSA_SIZE])
    server_rsa = pk.RSA().from_DER(SERVER_PUBLIC_KEY)
    del client_rsa
    client_rsa = pk.RSA()
    client_rsa.generate(RSA_SIZE * 8, EXPONENT)

    buffer = client_rsa.export_public_key() + client_rsa.sign(SECRET_KEY, "SHA256")
    buffer = server_rsa.encrypt(buffer[0:184]) + server_rsa.encrypt(buffer[184:368]) + server_rsa.encrypt(buffer[368:550])
    client_send(buffer)

    buffer = client_receive(RSA_SIZE)
    if CHECK_MSG != client_rsa.decrypt(buffer):
        raise Exception("Handshake failed")

def authenticate_and_setup():
    global SESSION_ID, aes

    buffer = client_rsa.sign(SECRET_KEY, "SHA256")
    buffer = server_rsa.encrypt(buffer[0:RSA_SIZE//2]) + server_rsa.encrypt(buffer[RSA_SIZE//2:RSA_SIZE])
    client_send(buffer)

    buffer = client_receive(RSA_SIZE)
    buffer = client_rsa.decrypt(buffer)
    SESSION_ID = buffer[0:8]

    aes = cipher.AES.new(buffer[24:56], cipher.MODE_CBC, buffer[8:24])
    
def send_request(val) -> bytes:
    global SESSION_ID
    if SESSION_ID is None:
        print("Session ID is not set. Please establish a session first.")
        return False
    request = bytes([val])
    buffer = request + SESSION_ID
    
    plen = cipher.AES.block_size - (len(buffer) % cipher.AES.block_size)
    
    buffer = aes.encrypt(buffer + bytes([len(buffer)] * plen))
    client_send(buffer)

    buffer = client_receive(cipher.AES.block_size)
    buffer = aes.decrypt(buffer)
    if buffer[0] == 0x10:
        return buffer[1:6]
    else:
        print("Command not found!")
        return False

def establish_session():
    try:
        initialize()
        handshake()
        authenticate_and_setup()
        return True
    except Exception as e:
        client_close()
        return False

def close_session():
    global SESSION_ID, ser
    try:
        client_close()
        SESSION_ID = None
        return True
    except Exception as e:
        print(e)
        return False

class Window(QDialog):
    def __init__(self):
        super().__init__()
        self.session_id = 0

        self.setFixedSize(800, 500)
        self.setWindowTitle("Client Application")

        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)

        try:
            self.serial = serial.Serial(port="/dev/ttyUSB0", baudrate=115200, timeout=1)
            if self.serial.is_open:
                self.log_text_edit.append("Serial port opened successfully")
            else:
                self.log_text_edit.append("Failed to open serial port")
        except serial.SerialException as e:
            self.log_text_edit.append(f"Error opening serial port: {e}")
            self.serial = None 

        # Create buttons
        self.session_button = QPushButton("Establish Session")
        
        self.toggle_relay_button = QPushButton("Toggle Relay")
        self.get_temperature_button = QPushButton("Get the Temperature")
        self.clear_log_button_widget = QPushButton("Clear the log")  
        self.toggle_relay_button.setEnabled(False)
        self.get_temperature_button.setEnabled(False)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.session_button)
        button_layout.addWidget(self.toggle_relay_button)
        button_layout.addWidget(self.get_temperature_button)
        button_layout.addWidget(self.clear_log_button_widget)

        main_layout = QVBoxLayout()
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.log_text_edit)
        self.setLayout(main_layout)

        self.session_button.clicked.connect(self.start_session_button)
        self.toggle_relay_button.clicked.connect(self.toggle_relay)
        self.get_temperature_button.clicked.connect(self.get_temperature)
        self.clear_log_button_widget.clicked.connect(self.clear_log)  

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.handle_serial_data)
        self.timer.start(100)

    def start_session_button(self):
        global SERIAL_PORT, ERROR
        SERIAL_PORT = "/dev/ttyUSB0"
        if self.session_button.text() == "Establish Session":
            success = establish_session()
            if success:
                self.session_id = int(QDateTime.currentSecsSinceEpoch())
                self.session_button.setText("Close Session")
                self.toggle_relay_button.setEnabled(True)
                self.get_temperature_button.setEnabled(True)
                self.log_text_edit.append("Establishing Session...")
            else:
                self.log_text_edit.append("Failed to establish session.")
        else:
            success = close_session()
            if success:
                self.session_id = 0
                self.session_button.setText("Establish Session")
                self.toggle_relay_button.setEnabled(False)
                self.get_temperature_button.setEnabled(False)
                self.log_text_edit.append("Session closed.")
            else:
                self.log_text_edit.append("Failed to close session.")

    def toggle_relay(self):
        success = send_request(2).decode("utf-8")
        if success =="11111":
            self.log_text_edit.append("Toggle LED: ON")
        elif success =="10101":
            self.log_text_edit.append("Toggle LED: OFF")
        else:
            self.log_text_edit.append("Error: Unable to toggle LED!")

    def get_temperature(self):
        success = send_request(1).decode("utf-8")
        if success:
            self.log_text_edit.append("Temperature: " + success + "°C")
        else:
            self.log_text_edit.append("Error: Unable to get temperature")       

    def clear_log(self): 
        self.log_text_edit.clear()

    def handle_serial_data(self):
        if self.serial and self.serial.in_waiting > 0:
            line = self.serial.readline().decode().strip()
            if line.startswith("SESSION_ESTABLISHED"):
                parts = line.split(':')
                if len(parts) == 2:
                    try:
                        self.session_id = int(parts[1])
                        self.log_text_edit.append(f"Session established with ID: {self.session_id}")
                        self.session_button.setText("Close Session")
                        self.toggle_relay_button.setEnabled(True)
                        self.get_temperature_button.setEnabled(True)
                    except ValueError:
                        self.log_text_edit.append("Failed to parse session ID.")
                else:
                    self.log_text_edit.append("Unexpected format.")
            elif line == "SESSION_CLOSED":
                self.session_id = 0
                self.session_button.setText("Establish Session")
                self.toggle_relay_button.setEnabled(False)
                self.get_temperature_button.setEnabled(False)
                self.log_text_edit.append("Session closed.")
            elif line.startswith("TEMPERATURE:"):
                self.log_text_edit.append(f"Received Temperature: {line} | Session ID: {self.session_id}")
            elif line.startswith("RELAY_TOGGLED"):
                self.log_text_edit.append(f"Relay toggled. | Session ID: {self.session_id}")
            elif line.startswith("NO_SESSION"):
                self.log_text_edit.append(f"No session active. | Session ID: {self.session_id}")
            elif line.startswith("UNKNOWN_COMMAND"):
                self.log_text_edit.append(f"Unknown command received. | Session ID: {self.session_id}")
            elif line:
                self.log_text_edit.append(f"Unrecognized response: {line} | Session ID: {self.session_id}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Window()
    window.show()
    sys.exit(app.exec())