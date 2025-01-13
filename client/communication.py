import serial
import serial.tools.list_ports


def init(port):
    global sercom
    sercom = serial.Serial(port, 115200)
    return sercom.is_open


def send(data: bytes):
    status = False
    global sercom
    if sercom.is_open:
        sercom.reset_output_buffer()
        status = (len(data) == sercom.write(data))
    return status
        

def receive(size: int) -> bytes:
    data = b''
    global sercom
    if sercom.is_open:
        sercom.reset_input_buffer()
        data = sercom.read(size)
    return data

def close():
    global sercom
    sercom.close()
