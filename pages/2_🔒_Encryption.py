import streamlit as st
import cv2
import numpy as np
import time
import Helper as h
import yaml
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth


def main():
    st.logo("map.png")
    st.header("Encrypt Image 🔒")

    uploaded_file = st.file_uploader("Choose an image file 🖼️", type=["jpg", "jpeg", "png"])

    if uploaded_file is not None:
        file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
        image = cv2.imdecode(file_bytes, 1)
        if image is not None:
            if st.toggle("Show"):
                st.image(image, channels="BGR", caption="Original Image")

            key_input = st.text_input("Enter a 16-byte encryption key for encryption 🗝️")

            if key_input and len(key_input) != 16:
                st.error("Encryption key must be 16 characters long.")
            else:
                key = key_input.encode()
                if st.button("Encrypt Image 🔒"):
                    encrypted_image_bytes, iv, image_hash = h.compress_and_encrypt_image(image, key)
                    st.success("Image encrypted successfully! 🚀")

                    st.session_state['iv'] = iv
                    st.session_state['image_hash'] = image_hash
                    
                    temp_txt_path = h.save_key_iv_to_file(key_input, iv)

                    encrypted_image_file = h.save_encrypted_image_to_file(encrypted_image_bytes)

                    zip_file_path = h.create_zip_file(temp_txt_path, encrypted_image_file)

                    st.session_state['text_attachment_path'] = temp_txt_path
                    st.session_state['image_attachment_path'] = encrypted_image_file
                    st.session_state['zip_file_path'] = zip_file_path

                    st.download_button(label="Download Encrypted Files (ZIP)", data=open(zip_file_path, "rb"), file_name="encrypted_files.zip")
        else:
            st.error("Failed to decode the uploaded image.")

    receiver_email = st.text_input("Enter the recipient's email address 📧")
    email_subject = st.text_input("Enter the subject for the email 📋")

    if st.button("Submit and Send Email 📩"):
        if receiver_email and email_subject:
            if 'text_attachment_path' in st.session_state and 'image_attachment_path' in st.session_state:
                text_attachment_path = st.session_state['text_attachment_path']
                image_attachment_path = st.session_state['image_attachment_path']
                subject = email_subject
                body = f"Please find attached the encrypted image and the key for decryption.\n\nSent on {time.strftime('%Y-%m-%d %H:%M:%S')}."
                st.success("Encryption successful! Sending email...")
                success = h.send_email(receiver_email, subject, body, text_attachment_path, image_attachment_path)
                if success:
                    st.success(f"Email sent to {receiver_email}!")
                else:
                    st.error("Failed to send email. Please try again.")
            else:
                st.error("No encrypted file to send. Please encrypt an image first.")
        else:
            st.error("Please enter a recipient's email address and a subject.")

st.set_page_config(page_title="SecurEncrypt", page_icon="🗺️")
config_file = './pages/config.yaml'  
with open(config_file, 'r') as file:
    config = yaml.load(file, Loader=SafeLoader)
authenticator = stauth.Authenticate(
    config['credentials'],
    config['cookie']['name'],
    config['cookie']['key'],
    config['cookie']['expiry_days'],
)
authenticator.login()
if st.session_state["authentication_status"]:
    authenticator.logout()
    st.write(f'Welcome *{st.session_state["name"]}*')
    main()
elif st.session_state["authentication_status"] is False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] is None:
    st.warning('Please Login To Use ')
