import communication
from mbedtls import pk, hmac, hashlib, cipher

class Session:
    RSA_SIZE = 256
    EXPONENT = 65537
    SECRET_KEY = b"Fj2-;wu3Ur=ARl2!Tqi6IuKM3nG]8z1+"
    SESSION_TEMPERATURE = 0x02
    SESSION_TOGGLE_LED = 0x03
    SESSION_OKAY = 0x01
    SESSION_CLOSE = 0xFF

    def __init__(self, port):
        self.SESSION_ID = b''
        if not communication.init(port):
            print("Failed to open the port")
            exit(1)

        # Initialize HMAC key
        self.hmac_key = hashlib.sha256()
        self.hmac_key.update(self.SECRET_KEY)
        self.hmac_key = self.hmac_key.digest()
        self.hmac_instance = hmac.new(self.hmac_key, digestmod="SHA256")

        self.__clientRSA = pk.RSA()
        self.__clientRSA.generate(self.RSA_SIZE * 8, self.EXPONENT)

        public_key_der = self.__clientRSA.export_public_key()
        self.send_datas(public_key_der)

        buffer = self.receive(2 * self.RSA_SIZE)
        server_key_pub = self.__clientRSA.decrypt(buffer[0:self.RSA_SIZE])
        server_key_pub += self.__clientRSA.decrypt(buffer[self.RSA_SIZE:2 * self.RSA_SIZE])
        self.__serverRSA = pk.RSA().from_DER(server_key_pub)

        del self.__clientRSA
        self.__clientRSA = pk.RSA()
        self.__clientRSA.generate(self.RSA_SIZE * 8, self.EXPONENT)

        buffer = self.__clientRSA.export_public_key() + self.__clientRSA.sign(self.SECRET_KEY, "SHA256")
        buffer = self.__serverRSA.encrypt(buffer[0: 184]) + self.__serverRSA.encrypt(buffer[184:368]) + self.__serverRSA.encrypt(buffer[368:550])

        self.send_datas(buffer)
        buffer = self.receive(self.RSA_SIZE)

        if b"OKAY" != self.__clientRSA.decrypt(buffer):
            print("Failed to exchange the public keys")
            exit(1)

    def send_datas(self, buf: bytes):
        self.hmac_instance.update(buf)
        hmac_digest = self.hmac_instance.digest()
        buf += hmac_digest
        communication.send(buf)

    def receive(self, size: int) -> bytes:
        buffer = communication.receive(size + self.hmac_instance.digest_size)
        self.hmac_instance.update(buffer[0:size])
        if buffer[size:size + self.hmac_instance.digest_size] == self.hmac_instance.digest():
            return buffer[0:size]
        else:
            return b''

    def establish(self) -> bool:
        self.SESSION_ID = bytes(8 * [0])
        buffer = self.__clientRSA.sign(self.SECRET_KEY, "SHA256")
        buffer = self.__serverRSA.encrypt(buffer[0:self.RSA_SIZE // 2]) + self.__serverRSA.encrypt(buffer[self.RSA_SIZE // 2:self.RSA_SIZE])
        self.send_datas(buffer)

        buffer = self.receive(self.RSA_SIZE)
        buffer = self.__clientRSA.decrypt(buffer)
        self.SESSION_ID = buffer[0:8]
        self.aes = cipher.AES.new(buffer[24:56], cipher.MODE_CBC, buffer[8:24])

        return True

    def get_temperature(self):
        received = self.request(int(self.SESSION_TEMPERATURE))
        return received

    def request(self, message) -> bytes:
        request = bytes([message])
        buffer = request + self.SESSION_ID
        plen = cipher.AES.block_size - (len(buffer) % cipher.AES.block_size)
        buffer = self.aes.encrypt(buffer + bytes([len(buffer)] * plen))
        self.send_datas(buffer)
        buffer = self.receive(cipher.AES.block_size)
        buffer = self.aes.decrypt(buffer)
        if buffer[0] == self.SESSION_OKAY:
            return buffer[1:6]
        else:
            return None

    def toggle_led(self):
        received = self.request(int(self.SESSION_TOGGLE_LED))
        return received

    def __bool__(self) -> bool:
        return (0 != int.from_bytes(self.SESSION_ID, 'little'))
    
    def terminate(self):
        self.SESSION_ID = bytes(8 * [0])
        # Close the session on the server also
