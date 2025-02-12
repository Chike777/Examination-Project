import sys
import argparse
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit, QHBoxLayout
)
from PyQt6.QtCore import Qt
import serial

class SecureClientGUI(QMainWindow):
    def __init__(self, port=None, baudrate=None):
        super().__init__()

        self.setWindowTitle("Secure Client")
        self.setGeometry(100, 100, 600, 400)

        self.serial_connection = None
        self.port = port
        self.baudrate = baudrate

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        self.serial_settings_layout = QHBoxLayout()
        layout.addLayout(self.serial_settings_layout)

        self.port_label = QLabel("Port:")
        self.serial_settings_layout.addWidget(self.port_label)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("COM port (/dev/ttyUSB0)")
        if port:  # Pre-fill port if provided
            self.port_input.setText(port)
        self.serial_settings_layout.addWidget(self.port_input)

        self.baudrate_label = QLabel("Baudrate:")
        self.serial_settings_layout.addWidget(self.baudrate_label)

        self.baudrate_input = QLineEdit()
        self.baudrate_input.setPlaceholderText("115200")
        if baudrate:  
            self.baudrate_input.setText(baudrate)
        self.serial_settings_layout.addWidget(self.baudrate_input)

        self.session_button = QPushButton("Establish Session")
        self.session_button.clicked.connect(self.toggle_session)
        layout.addWidget(self.session_button)

        self.temperature_button = QPushButton("Get Temperature")
        self.temperature_button.clicked.connect(self.get_temperature)
        self.temperature_button.setEnabled(False)
        layout.addWidget(self.temperature_button)

        self.relay_button = QPushButton("Toggle Relay")
        self.relay_button.clicked.connect(self.toggle_relay)
        self.relay_button.setEnabled(False)
        layout.addWidget(self.relay_button)

        self.log_label = QLabel("Logs:")
        layout.addWidget(self.log_label)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.clear_log_button = QPushButton("Clear Logs")
        self.clear_log_button.clicked.connect(self.clear_logs)
        layout.addWidget(self.clear_log_button)

        self.session_active = False

    def toggle_session(self):
        """Establish or close a session."""
        if not self.session_active:
            self.log("Establishing session...")
            self.session_active = True
            self.session_button.setText("Close Session")
            self.temperature_button.setEnabled(True)
            self.relay_button.setEnabled(True)

            # Initialize serial connection
            self.initialize_serial_connection()

            self.log("Session established.")
        else:
            self.log("Closing session...")
            self.session_active = False
            self.session_button.setText("Establish Session")
            self.temperature_button.setEnabled(False)
            self.relay_button.setEnabled(False)

            # Close serial connection
            self.close_serial_connection()

            self.log("Session closed.")

    def initialize_serial_connection(self):
        """Initialize the serial connection."""
        try:
            self.serial_connection = serial.Serial(self.port, self.baudrate, timeout=1)
            if self.serial_connection.is_open:
                self.log(f"Connected to {self.port} at {self.baudrate} baud.")
        except Exception as e:
            self.log(f"Error initializing serial connection: {e}")

    def close_serial_connection(self):
        """Close the serial connection."""
        if self.serial_connection and self.serial_connection.is_open:
            self.serial_connection.close()
            self.log(f"Connection closed.")

    def get_temperature(self):
        """Request temperature from the ESP32 server."""
        if self.session_active and self.serial_connection:
            try:
                # Send temperature request command
                self.serial_connection.write(b"GET_TEMP\n")
                response = self.serial_connection.readline().decode("utf-8").strip()
                self.log(f"Temperature: {response} °C")
            except Exception as e:
                self.log(f"Error reading temperature: {e}")
        else:
            self.log("Session not active or serial connection not established.")

    def toggle_relay(self):
        """Toggle the relay on the ESP32 server."""
        if self.session_active and self.serial_connection:
            try:
                # Send relay toggle command
                self.serial_connection.write(b"TOGGLE_RELAY\n")
                response = self.serial_connection.readline().decode("utf-8").strip()
                self.log(f"Relay state: {response}")
            except Exception as e:
                self.log(f"Error toggling relay: {e}")
        else:
            self.log("Session not active or serial connection not established.")

    def log(self, message):
        """Log a message to the log area."""
        self.log_area.append(f" {message}")

    def clear_logs(self):
        """Clear the log area."""
        self.log_area.clear()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="Secure Client GUI Application")
    parser.add_argument("--port", type=str, help="The COM port (e.g., COM3 or /dev/ttyUSB0)")
    parser.add_argument("--baudrate", type=str, help="The baud rate (e.g., 115200)")

    args = parser.parse_args()


    app = QApplication(sys.argv)
    gui = SecureClientGUI(port=args.port, baudrate=args.baudrate)
    gui.show()
    sys.exit(app.exec())