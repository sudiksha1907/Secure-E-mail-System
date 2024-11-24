from PyQt5.QtWidgets import (QApplication, QMainWindow, QDialog, QVBoxLayout,
                             QHBoxLayout, QPushButton, QLabel, QLineEdit,
                             QTextEdit, QFileDialog, QMessageBox, QDialogButtonBox,
                             QWidget)
from PyQt5.QtCore import Qt
import sys
import time
from datetime import datetime
from cryptography.fernet import Fernet
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import base64
import os
import json
import hashlib
import imaplib
from email import message_from_string


class UserAuth:
    def __init__(self, users_file='users.json'):
        self.users_file = users_file
        self.users = self.load_users()

    def load_users(self):
        try:
            with open(self.users_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def save_users(self):
        with open(self.users_file, 'w') as f:
            json.dump(self.users, f)

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def register_user(self, username, password):
        if username in self.users:
            return False, "Username already exists"
        self.users[username] = self.hash_password(password)
        self.save_users()
        return True, "User registered successfully"

    def authenticate_user(self, username, password):
        if username not in self.users:
            return False, "User not found"
        if self.users[username] == self.hash_password(password):
            return True, "Authentication successful"
        return False, "Incorrect password"

def decrypt_message(encrypted_message, decryption_key):
    decrypted_message = bytearray()
    for i in range(len(encrypted_message)):
        decrypted_message.append(encrypted_message[i] ^ decryption_key[i % len(decryption_key)])
    return bytes(decrypted_message)

class InitialDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Welcome")
        self.setMinimumSize(500, 300)
        layout = QVBoxLayout()

        title = QLabel("Secure Email System")
        title.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        subtitle = QLabel("Choose an option to continue")
        subtitle.setStyleSheet("font-size: 16px; margin: 10px;")
        subtitle.setAlignment(Qt.AlignCenter)
        layout.addWidget(subtitle)

        login_btn = QPushButton("Login")
        register_btn = QPushButton("Register")

        login_btn.setMinimumHeight(50)
        register_btn.setMinimumHeight(50)
        login_btn.setStyleSheet("font-size: 16px;")
        register_btn.setStyleSheet("font-size: 16px;")

        layout.addWidget(login_btn)
        layout.addWidget(register_btn)

        login_btn.clicked.connect(self.login_clicked)
        register_btn.clicked.connect(self.register_clicked)

        self.setLayout(layout)
        self.choice = None

    def login_clicked(self):
        self.choice = "login"
        self.accept()

    def register_clicked(self):
        self.choice = "register"
        self.accept()


class LoginDialog(QDialog):
    def __init__(self, auth):
        super().__init__()
        self.auth = auth
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Login")
        self.setMinimumSize(500, 300)
        layout = QVBoxLayout()

        title = QLabel("Login to Secure Email System")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Username")
        self.username.setMinimumHeight(40)
        self.username.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(self.username)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setMinimumHeight(40)
        self.password.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(self.password)

        button_layout = QHBoxLayout()
        login_btn = QPushButton("Login")
        login_btn.setMinimumHeight(40)
        login_btn.setStyleSheet("font-size: 14px;")
        login_btn.clicked.connect(self.accept)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setMinimumHeight(40)
        cancel_btn.setStyleSheet("font-size: 14px;")
        cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(login_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        self.setLayout(layout)


class RegisterDialog(QDialog):
    def __init__(self, auth):
        super().__init__()
        self.auth = auth
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Register New Account")
        self.setMinimumSize(500, 300)
        layout = QVBoxLayout()

        title = QLabel("Create New Account")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.username = QLineEdit()
        self.username.setPlaceholderText("Choose Username")
        self.username.setMinimumHeight(40)
        self.username.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(self.username)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Choose Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setMinimumHeight(40)
        self.password.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(self.password)

        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("Confirm Password")
        self.confirm_password.setEchoMode(QLineEdit.Password)
        self.confirm_password.setMinimumHeight(40)
        self.confirm_password.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(self.confirm_password)

        button_layout = QHBoxLayout()
        register_btn = QPushButton("Register")
        register_btn.setMinimumHeight(40)
        register_btn.setStyleSheet("font-size: 14px;")
        register_btn.clicked.connect(self.register)

        cancel_btn = QPushButton("Cancel")
        cancel_btn.setMinimumHeight(40)
        cancel_btn.setStyleSheet("font-size: 14px;")
        cancel_btn.clicked.connect(self.reject)

        button_layout.addWidget(register_btn)
        button_layout.addWidget(cancel_btn)
        layout.addLayout(button_layout)

        self.setLayout(layout)

    def register(self):
        if self.password.text() != self.confirm_password.text():
            QMessageBox.warning(self, "Error", "Passwords do not match!")
            return

        success, message = self.auth.register_user(
            self.username.text(),
            self.password.text()
        )
        if success:
            QMessageBox.information(self, "Success", message)
            self.accept()
        else:
            QMessageBox.warning(self, "Registration Failed", message)


class SendEmailDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.attachments = []

    def setup_ui(self):
        self.setWindowTitle("Send Encrypted Email")
        self.setMinimumSize(600, 500)
        layout = QVBoxLayout()

        title = QLabel("Send Encrypted Email")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.sender = QLineEdit()
        self.sender.setPlaceholderText("Sender Email")
        self.sender.setMinimumHeight(40)
        layout.addWidget(self.sender)

        self.sender_password = QLineEdit()
        self.sender_password.setPlaceholderText("Email Password")
        self.sender_password.setEchoMode(QLineEdit.Password)
        self.sender_password.setMinimumHeight(40)
        layout.addWidget(self.sender_password)

        self.recipient = QLineEdit()
        self.recipient.setPlaceholderText("Recipient Email")
        self.recipient.setMinimumHeight(40)
        layout.addWidget(self.recipient)

        self.message = QTextEdit()
        self.message.setPlaceholderText("Message")
        self.message.setMinimumHeight(200)
        layout.addWidget(self.message)

        attach_btn = QPushButton("Add Attachment")
        attach_btn.setMinimumHeight(40)
        attach_btn.clicked.connect(self.add_attachment)
        layout.addWidget(attach_btn)

        self.read_receipt = QPushButton("Request Read Receipt")
        self.read_receipt.setCheckable(True)
        self.read_receipt.setMinimumHeight(40)
        layout.addWidget(self.read_receipt)

        buttons = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def add_attachment(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        self.attachments.extend(files)
        if self.attachments:
            QMessageBox.information(self, "Success", f"Added {len(files)} file(s)")

    def accept(self):
        try:
            sender_email = self.sender.text()
            sender_password = self.sender_password.text()
            recipient_email = self.recipient.text()
            message_text = self.message.toPlainText()

            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender_email
            msg['To'] = recipient_email
            msg['Subject'] = "Encrypted Message"

            # Generate encryption key
            key = Fernet.generate_key()
            f = Fernet(key)

            # Encrypt message
            encrypted_message = f.encrypt(message_text.encode())
            msg.attach(MIMEText(encrypted_message.decode(), 'plain'))

            # Encrypt and add attachments
            for file_path in self.attachments:
                with open(file_path, 'rb') as attachment:
                    file_data = attachment.read()
                    # Encrypt the file data
                    encrypted_file_data = f.encrypt(file_data)

                    part = MIMEBase('application', 'octet-stream')
                    part.set_payload(encrypted_file_data)
                    encoders.encode_base64(part)

                    # Add encrypted filename
                    encrypted_filename = f.encrypt(os.path.basename(file_path).encode()).decode()
                    part.add_header(
                        'Content-Disposition',
                        f'attachment; filename= encrypted_{os.path.basename(file_path)}'
                    )
                    # Store original filename as a header
                    part.add_header('Original-Filename', encrypted_filename)
                    msg.attach(part)

            # Connect to SMTP server and send email
            with smtplib.SMTP_SSL('smtp.gmail.com', 465) as server:
                server.login(sender_email, sender_password)
                server.send_message(msg)

            # Save encryption key
            key_file = f'key_{recipient_email}_{hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}.key'
            with open(key_file, 'wb') as f:
                f.write(key)

            QMessageBox.information(self, "Success",
                                    f"Email sent successfully with encrypted attachments!\nKey saved as: {key_file}")
            super().accept()

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Failed to send email: {str(e)}")


class ReadEmailDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setup_ui()
        self.fernet = None

    def setup_ui(self):
        # Previous UI setup remains the same
        pass

    def decrypt_and_show(self):
        try:
            # Get the encryption key
            key = self.key.text().encode()
            f = Fernet(key)

            # Get file path from the file_path QLineEdit
            file_path = self.file_path.text()

            # Read the encrypted file
            with open(file_path, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            # Decrypt the data
            decrypted_data = f.decrypt(encrypted_data)

            # Create the decrypted file path (same location as original)
            base_path = os.path.splitext(file_path)[0]
            decrypted_path = f"{base_path}_decrypted{os.path.splitext(file_path)[1]}"

            # Save the decrypted file
            with open(decrypted_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            QMessageBox.information(self, "Success", f"File decrypted successfully!\nSaved at: {decrypted_path}")

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Decryption failed: {str(e)}")


    def setup_ui(self):
        self.setWindowTitle("Read Encrypted Email")
        self.setMinimumSize(600, 500)
        layout = QVBoxLayout()

        title = QLabel("Read Encrypted Email")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.email = QLineEdit()
        self.email.setPlaceholderText("Email Address")
        self.email.setMinimumHeight(40)
        layout.addWidget(self.email)

        self.password = QLineEdit()
        self.password.setPlaceholderText("Email Password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setMinimumHeight(40)
        layout.addWidget(self.password)

        self.key = QLineEdit()
        self.key.setPlaceholderText("Decryption Key")
        self.key.setMinimumHeight(40)
        layout.addWidget(self.key)

        self.decrypted_message = QTextEdit()
        self.decrypted_message.setPlaceholderText("Decrypted message will appear here")
        self.decrypted_message.setMinimumHeight(200)
        self.decrypted_message.setReadOnly(True)
        layout.addWidget(self.decrypted_message)

        decrypt_btn = QPushButton("Decrypt Message")
        decrypt_btn.setMinimumHeight(40)
        decrypt_btn.clicked.connect(self.decrypt_and_show)
        layout.addWidget(decrypt_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)

    def decrypt_and_show(self):
        try:
            email_address = self.email.text()
            password = self.password.text()
            key = self.key.text().encode()

            # Initialize Fernet with the provided key
            f = Fernet(key)

            # Connect to Gmail
            mail = imaplib.IMAP4_SSL('imap.gmail.com')
            mail.login(email_address, password)
            mail.select('inbox')

            # Search for encrypted messages
            result, data = mail.search(None, '(SUBJECT "Encrypted Message")')
            if not data[0]:
                raise Exception("No encrypted messages found")

            # Get the latest email
            latest_email_id = data[0].split()[-1]
            result, data = mail.fetch(latest_email_id, '(RFC822)')
            email_body = data[0][1]
            email_message = message_from_string(email_body.decode())

            # Extract and decrypt the message
            for part in email_message.walk():
                if part.get_content_type() == "text/plain":
                    encrypted_message = part.get_payload()
                    # Remove any whitespace and newlines
                    encrypted_message = encrypted_message.strip()
                    # Decrypt the message
                    decrypted_message = f.decrypt(encrypted_message.encode())
                    self.decrypted_message.setText(decrypted_message.decode())
                    QMessageBox.information(self, "Success", "Message decrypted successfully!")
                    break

            mail.close()
            mail.logout()

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Decryption failed: {str(e)}")

class OpenFileDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Open Encrypted File")
        self.setMinimumSize(600, 400)
        layout = QVBoxLayout()

        title = QLabel("Open & Decrypt File")
        title.setStyleSheet("font-size: 18px; font-weight: bold; margin: 10px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("Encrypted File Path")
        self.file_path.setReadOnly(True)
        self.file_path.setMinimumHeight(40)
        self.file_path.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(self.file_path)

        select_file_btn = QPushButton("Select Encrypted File")
        select_file_btn.setMinimumHeight(40)
        select_file_btn.setStyleSheet("font-size: 14px;")
        select_file_btn.clicked.connect(self.select_file)
        layout.addWidget(select_file_btn)

        self.key_path = QLineEdit()
        self.key_path.setPlaceholderText("Key File Path")
        self.key_path.setReadOnly(True)
        self.key_path.setMinimumHeight(40)
        self.key_path.setStyleSheet("font-size: 14px; padding: 5px;")
        layout.addWidget(self.key_path)

        select_key_btn = QPushButton("Select Key File")
        select_key_btn.setMinimumHeight(40)
        select_key_btn.setStyleSheet("font-size: 14px;")
        select_key_btn.clicked.connect(self.select_key)
        layout.addWidget(select_key_btn)

        decrypt_btn = QPushButton("Decrypt File")
        decrypt_btn.setMinimumHeight(40)
        decrypt_btn.setStyleSheet("font-size: 14px;")
        decrypt_btn.clicked.connect(self.decrypt_file)
        layout.addWidget(decrypt_btn)

        self.setLayout(layout)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Encrypted File")
        if file_path:
            self.file_path.setText(file_path)

    def select_key(self):
        key_path, _ = QFileDialog.getOpenFileName(self, "Select Key File", filter="Key Files (*.key)")
        if key_path:
            self.key_path.setText(key_path)

    def decrypt_file(self):
        try:
            # Read the key file
            with open(self.key_path.text(), 'rb') as key_file:
                key = key_file.read()

            # Initialize Fernet with the key
            f = Fernet(key)

            # Read the encrypted file
            with open(self.file_path.text(), 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            # Decrypt the data
            decrypted_data = f.decrypt(encrypted_data)

            # Create decrypted filename
            original_path = self.file_path.text()
            base_name = os.path.splitext(original_path)[0]
            extension = os.path.splitext(original_path)[1]
            decrypted_path = f"{base_name}_decrypted{extension}"

            # Save the decrypted file
            with open(decrypted_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            QMessageBox.information(self, "Success", f"File decrypted successfully!\nSaved as: {decrypted_path}")
            self.accept()

        except Exception as e:
            QMessageBox.warning(self, "Error", f"Decryption failed: {str(e)}")




class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.auth = UserAuth()
        self.setup_ui()

    def setup_ui(self):
        self.setWindowTitle("Secure Email System")
        self.setGeometry(100, 100, 800, 600)

        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        title = QLabel("Secure Email System")
        title.setStyleSheet("font-size: 24px; font-weight: bold; margin: 20px;")
        title.setAlignment(Qt.AlignCenter)
        layout.addWidget(title)

        send_btn = QPushButton("Send Encrypted Email")
        read_btn = QPushButton("Read Encrypted Email")
        file_btn = QPushButton("Open Encrypted File")
        logout_btn = QPushButton("Logout")

        for btn in [send_btn, read_btn, file_btn, logout_btn]:
            btn.setMinimumHeight(50)
            btn.setStyleSheet("font-size: 16px;")
            layout.addWidget(btn)

        send_btn.clicked.connect(self.show_send_dialog)
        read_btn.clicked.connect(self.show_read_dialog)
        file_btn.clicked.connect(self.show_file_dialog)
        logout_btn.clicked.connect(self.logout)

    def show_send_dialog(self):
        dialog = SendEmailDialog()
        if dialog.exec_() == QDialog.Accepted:
            QMessageBox.information(self, "Success", "Email sent successfully!")

    def show_read_dialog(self):
        dialog = ReadEmailDialog()
        if dialog.exec_() == QDialog.Accepted:
            QMessageBox.information(self, "Success", "Email read successfully!")
    def show_file_dialog(self):
        dialog = OpenFileDialog()
        dialog.exec_()  # Remove the if condition since we handle success in OpenFileDialog

    def logout(self):
        self.close()
        self.show_login()

    def show_login(self):
        dialog = LoginDialog(self.auth)
        if dialog.exec_() == QDialog.Accepted:
            username = dialog.username.text()
            password = dialog.password.text()
            success, message = self.auth.authenticate_user(username, password)
            if success:
                self.show()
            else:
                QMessageBox.warning(self, "Login Failed", message)
                self.show_login()


def main():
    app = QApplication(sys.argv)
    auth = UserAuth()

    initial_dialog = InitialDialog()
    if initial_dialog.exec_() == QDialog.Accepted:
        if initial_dialog.choice == "register":
            register_dialog = RegisterDialog(auth)
            if register_dialog.exec_() == QDialog.Accepted:
                login_dialog = LoginDialog(auth)
                if login_dialog.exec_() == QDialog.Accepted:
                    window = MainWindow()
                    window.show()
        else:
            login_dialog = LoginDialog(auth)
            if login_dialog.exec_() == QDialog.Accepted:
                window = MainWindow()
                window.show()

    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
