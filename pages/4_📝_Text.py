import streamlit as st
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import smtplib
from email.message import EmailMessage
import ssl
import toml
import yaml
from yaml.loader import SafeLoader
import os
import streamlit_authenticator as stauth

def pad_message(message):
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(message.encode())
    padded_data += padder.finalize()
    return padded_data

def encrypt_message(message, key_phrase):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(key_phrase.encode())
    iv = os.urandom(16)
    padded_message = pad_message(message)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return iv, encrypted_message, salt

def decrypt_message(iv, encrypted_message, key_phrase, salt):
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(key_phrase.encode())
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_message = unpadder.update(decrypted_padded_message)
        decrypted_message += unpadder.finalize()
        return decrypted_message.decode('utf-8')
    except ValueError as e:
        st.error(f"Decryption failed: {str(e)}")

def send_email(receiver_email, subject, body, text_attachment_path, image_attachment_path):
    credentials = toml.load('./pages/credentials.toml')
    sender_email = credentials['email']['sender_email']
    sender_password = credentials['email']['sender_password']

    msg = EmailMessage()
    msg["From"] = sender_email
    msg["To"] = receiver_email
    msg["Subject"] = subject
    msg.set_content(body)

    with open(text_attachment_path, "rb") as text_attachment:
        msg.add_attachment(
            text_attachment.read(),
            maintype="application",
            subtype="octet-stream",
            filename=os.path.basename(text_attachment_path),
        )

    if image_attachment_path:  
        with open(image_attachment_path, "rb") as image_attachment:
            msg.add_attachment(
                image_attachment.read(),
                maintype="application",
                subtype="octet-stream",
                filename=os.path.basename(image_attachment_path),
            )

    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.send_message(msg)
        return True
    except Exception as e:
        st.error(f"Failed to send email: {e}")
        return False

def main():
    
    st.title("Text Encryption and Decryption 💬")

    tab_selection = st.sidebar.radio("Select operation:", ["Encryption", "Decryption"])

    if tab_selection == "Encryption":
        st.header("Encryption 🔒")

        message = st.text_area("Enter your message 💬:")
        key_phrase = st.text_input("Enter your key phrase 🗝️:")
        email_subject = st.text_input("Enter email subject:")
        recipient_email = st.text_input("Enter recipient email:")

        if st.button("Encrypt and Send Email"):
            if message and key_phrase and email_subject and recipient_email:
                iv, encrypted_message, salt = encrypt_message(message, key_phrase)

                data = f"Key: {key_phrase}\nIV: {iv.hex()}\nEncrypted Message: {encrypted_message.hex()}\nSalt: {salt.hex()}"
                text_file_path = "encryption_details.txt"
                with open(text_file_path, 'w') as file:
                    file.write(data)

                st.success("Encryption successful! Sending email...")
                email_sent = send_email(
                    recipient_email,
                    email_subject,
                    "Please find the encrypted details attached.",
                    text_file_path,
                    None  
                )
                if email_sent:
                    st.success(f"Email sent to {recipient_email}!")
            else:
                st.error("Fill all the fields")

    elif tab_selection == "Decryption":
        st.header("Decryption 🔓")

        iv_input = st.text_input("Enter IV (Initialization Vector) 🔐:")
        encrypted_message_input = st.text_area("Enter Encrypted Message 🛅:")
        key_phrase = st.text_input("Enter your key phrase 🗝️:", key="k")
        salt_input = st.text_input("Enter Salt used for key derivation 🧂:")

        if st.button("Decrypt 🔓"):
            try:
                if iv_input and encrypted_message_input and key_phrase and salt_input:
                    iv = bytes.fromhex(iv_input)
                    encrypted_message = bytes.fromhex(encrypted_message_input)
                    salt = bytes.fromhex(salt_input)

                    decrypted_message = decrypt_message(iv, encrypted_message, key_phrase, salt)

                    st.subheader("Decryption Result:")
                    st.write(f"Decrypted Message: {decrypted_message}")
                else:
                    st.error("Fill all the fields")

            except ValueError as e:
                st.error(f"Decryption failed: Enter what you got while encrypting")

st.set_page_config(page_title="SecurEncrypt", page_icon="🗺️")
st.logo("map.png")
# config_file = './pages/config.yaml'  
# with open(config_file, 'r') as file:
#     config = yaml.load(file, Loader=SafeLoader)

# authenticator = stauth.Authenticate(
#     config['credentials'],
#     config['cookie']['name'],
#     config['cookie']['key'],
#     config['cookie']['expiry_days'],
# )
# authenticator.login()
# if st.session_state["authentication_status"]:
#     authenticator.logout()
#     st.write(f'Welcome *{st.session_state["name"]}*')
main()
# elif st.session_state["authentication_status"] is False:
#     st.error('Username/password is incorrect')
# elif st.session_state["authentication_status"] is None:
#     st.warning('Please Login To Use ')
