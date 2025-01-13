import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout,
    QPushButton, QLabel, QTextEdit, QLineEdit, QHBoxLayout
)
from PyQt6.QtCore import Qt

class SecureClientGUI(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Secure Client")
        self.setGeometry(100, 100, 600, 400)

        # Central Widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout()
        central_widget.setLayout(layout)

        # Serial Settings
        self.serial_settings_layout = QHBoxLayout()
        layout.addLayout(self.serial_settings_layout)

        self.port_label = QLabel("Port:")
        self.serial_settings_layout.addWidget(self.port_label)

        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("COM port (e.g., COM3 or /dev/ttyUSB0)")
        self.serial_settings_layout.addWidget(self.port_input)

        self.baudrate_label = QLabel("Baudrate:")
        self.serial_settings_layout.addWidget(self.baudrate_label)

        self.baudrate_input = QLineEdit()
        self.baudrate_input.setPlaceholderText("115200")
        self.serial_settings_layout.addWidget(self.baudrate_input)

        # Session Management
        self.session_button = QPushButton("Establish Session")
        self.session_button.clicked.connect(self.toggle_session)
        layout.addWidget(self.session_button)

        # Control Buttons
        self.temperature_button = QPushButton("Get Temperature")
        self.temperature_button.clicked.connect(self.get_temperature)
        self.temperature_button.setEnabled(False)
        layout.addWidget(self.temperature_button)

        self.relay_button = QPushButton("Toggle Relay")
        self.relay_button.clicked.connect(self.toggle_relay)
        self.relay_button.setEnabled(False)
        layout.addWidget(self.relay_button)

        # Logging
        self.log_label = QLabel("Logs:")
        layout.addWidget(self.log_label)

        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.clear_log_button = QPushButton("Clear Logs")
        self.clear_log_button.clicked.connect(self.clear_logs)
        layout.addWidget(self.clear_log_button)

        # Session State
        self.session_active = False

    def toggle_session(self):
        """Establish or close a session."""
        if not self.session_active:
            self.log("Establishing session...")
            self.session_active = True
            self.session_button.setText("Close Session")
            self.temperature_button.setEnabled(True)
            self.relay_button.setEnabled(True)
            self.log("Session established.")
        else:
            self.log("Closing session...")
            self.session_active = False
            self.session_button.setText("Establish Session")
            self.temperature_button.setEnabled(False)
            self.relay_button.setEnabled(False)
            self.log("Session closed.")

    def get_temperature(self):
        """Simulate retrieving temperature from the server."""
        if self.session_active:
            self.log("Retrieving temperature...")
            # Simulate a temperature value
            temperature = "25.3°C"
            self.log(f"Temperature: {temperature}")
        else:
            self.log("Session not active. Cannot retrieve temperature.")

    def toggle_relay(self):
        """Simulate toggling the relay on the server."""
        if self.session_active:
            self.log("Toggling relay...")
            # Simulate relay toggling
            relay_state = "ON" if "OFF" in self.log_area.toPlainText() else "OFF"
            self.log(f"Relay toggled to: {relay_state}")
        else:
            self.log("Session not active. Cannot toggle relay.")

    def log(self, message):
        """Log a message to the log area."""
        self.log_area.append(f"[{Qt.QTime.currentTime().toString()}] {message}")

    def clear_logs(self):
        """Clear the log area."""
        self.log_area.clear()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = SecureClientGUI()
    gui.show()
    sys.exit(app.exec())
