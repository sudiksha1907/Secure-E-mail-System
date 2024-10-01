from cryptography.fernet import Fernet
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email import message_from_string
import imaplib
import email
import base64
import os
import hashlib
import json
from email.utils import make_msgid
import time

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

# Generate a random key for Fernet encryption
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

# XOR Encryption Key (Should be the same length as the message)
xor_key = b'key12345'

def encrypt_message(message):
    encrypted_message = bytearray()
    for i in range(len(message)):
        encrypted_message.append(message[i] ^ xor_key[i % len(xor_key)])
    return bytes(encrypted_message)

def decrypt_message(encrypted_message, decryption_key):
    decrypted_message = bytearray()
    for i in range(len(encrypted_message)):
        decrypted_message.append(encrypted_message[i] ^ decryption_key[i % len(decryption_key)])
    return bytes(decrypted_message)

def encrypt_file(file_path):
    with open(file_path, 'rb') as file:
        file_data = file.read()
    encrypted_data = fernet.encrypt(file_data)
    return encrypted_data

def decrypt_file(encrypted_data):
    return fernet.decrypt(encrypted_data)

def send_email_with_encrypted_message(sender_email, sender_password, recipient_email, message, attachments, request_read_receipt=False):
    encrypted_message = encrypt_message(message.encode())

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = 'Encrypted Message'
    
    if request_read_receipt:
        msg['Disposition-Notification-To'] = sender_email
        msg['X-Confirm-Reading-To'] = sender_email
        msg['Return-Receipt-To'] = sender_email
        msg['Message-ID'] = make_msgid()

    msg.attach(MIMEText(base64.b64encode(encrypted_message).decode(), 'plain'))

    for attachment in attachments:
        encrypted_data = encrypt_file(attachment)
        part = MIMEBase('application', 'octet-stream')
        part.set_payload(encrypted_data)
        encoders.encode_base64(part)
        part.add_header('Content-Disposition', f"attachment; filename= {os.path.basename(attachment)}.encrypted")
        msg.attach(part)

    key_part = MIMEText(base64.b64encode(fernet_key).decode(), 'plain')
    key_part.add_header('Content-Disposition', 'attachment; filename="encryption_key.txt"')
    msg.attach(key_part)

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, sender_password)
        smtp.send_message(msg)

    print("Email sent successfully!")
    if request_read_receipt:
        print("Read receipt requested.")

def send_read_receipt(recipient_email, original_message_id, sender_email, sender_password):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = 'Read Receipt'
    msg['In-Reply-To'] = original_message_id
    msg['References'] = original_message_id

    body = f"Your message with ID {original_message_id} was read on {time.ctime()}"
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login(sender_email, sender_password)
        smtp.send_message(msg)

    print("Read receipt sent.")

def read_and_decrypt_email(email_address, password):
    decryption_key = input("Enter decryption key: ")

    mail = imaplib.IMAP4_SSL('imap.gmail.com')
    mail.login(email_address, password)
    mail.select('inbox')

    result, data = mail.search(None, '(SUBJECT "Encrypted Message")')
    latest_email_id = data[0].split()[-1]

    result, data = mail.fetch(latest_email_id, '(RFC822)')
    raw_email = data[0][1]

    msg = message_from_string(raw_email.decode('utf-8'))

    # Check if read receipt was requested
    read_receipt_requested = ('Disposition-Notification-To' in msg or 
                              'X-Confirm-Reading-To' in msg or 
                              'Return-Receipt-To' in msg)

    fernet_key = None

    for part in msg.walk():
        if part.get_content_type() == 'text/plain':
            if part.get_filename() == 'encryption_key.txt':
                fernet_key = base64.b64decode(part.get_payload())
            else:
                encrypted_message = base64.b64decode(part.get_payload())
                decrypted_message = decrypt_message(encrypted_message, decryption_key.encode())
                print("Decrypted Message:", decrypted_message.decode())
        elif part.get_content_disposition() is not None:
            filename = part.get_filename()
            if filename and filename.endswith('.encrypted'):
                print(f"Encrypted attachment found: {filename}")
                if fernet_key:
                    fernet = Fernet(fernet_key)
                    decrypted_data = decrypt_file(part.get_payload(decode=True))
                    original_filename = filename[:-10]
                    with open(original_filename, 'wb') as file:
                        file.write(decrypted_data)
                    print(f"Decrypted and saved as: {original_filename}")
                else:
                    print("Encryption key not found. Unable to decrypt attachment.")

    if read_receipt_requested:
        sender_email = msg['From']
        original_message_id = msg['Message-ID']
        send_read_receipt(sender_email, original_message_id, email_address, password)

    mail.store(latest_email_id, '+FLAGS', '\\Seen')
    mail.close()
    mail.logout()

def open_encrypted_file():
    file_path = input("Enter the path of the encrypted file: ")
    if not os.path.exists(file_path):
        print("File not found. Please check the path and try again.")
        return

    key_path = input("Enter the path of the encryption key file: ")
    if not os.path.exists(key_path):
        print("Key file not found. Please check the path and try again.")
        return

    try:
        with open(key_path, 'rb') as key_file:
            fernet_key = base64.b64decode(key_file.read())

        fernet = Fernet(fernet_key)

        with open(file_path, 'rb') as encrypted_file:
            encrypted_data = encrypted_file.read()

        decrypted_data = fernet.decrypt(encrypted_data)

        decrypted_file_path = file_path[:-10] if file_path.endswith('.encrypted') else file_path + '.decrypted'
        with open(decrypted_file_path, 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        print(f"File decrypted successfully. Saved as: {decrypted_file_path}")
    except Exception as e:
        print(f"An error occurred while decrypting the file: {str(e)}")

def register():
    username = input("Enter new username: ")
    password = input("Enter new password: ")
    success, message = auth.register_user(username, password)
    print(message)

def login():
    username = input("Enter username: ")
    password = input("Enter password: ")
    success, message = auth.authenticate_user(username, password)
    print(message)
    return success

def authenticated_main():
    while True:
        print("\n1. Send encrypted email")
        print("2. Read and decrypt email")
        print("3. Open encrypted file")
        print("4. Logout")
        choice = input("Enter your choice (1-4): ")

        if choice == '1':
            sender_email = input("Enter sender email: ")
            sender_password = input("Enter sender password: ")
            recipient_email = input("Enter recipient email: ")
            message = input("Enter message: ")
            request_read_receipt = input("Request read receipt? (y/n): ").lower() == 'y'

            attachments = []
            while True:
                attach = input("Do you want to add an attachment? (y/n): ").lower()
                if attach == 'y':
                    file_path = input("Enter the file path of the attachment: ")
                    if os.path.exists(file_path):
                        attachments.append(file_path)
                    else:
                        print("File not found. Please try again.")
                else:
                    break

            send_email_with_encrypted_message(sender_email, sender_password, recipient_email, message, attachments, request_read_receipt)
        elif choice == '2':
            email_address = input("Enter email address: ")
            password = input("Enter password: ")
            read_and_decrypt_email(email_address, password)
        elif choice == '3':
            open_encrypted_file()
        elif choice == '4':
            print("Logging out...")
            break
        else:
            print("Invalid choice. Please try again.")

def main():
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            register()
        elif choice == '2':
            if login():
                authenticated_main()
            else:
                print("Authentication failed. Please try again.")
        elif choice == '3':
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    auth = UserAuth()
    main()
