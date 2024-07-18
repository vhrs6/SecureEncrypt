import streamlit as st
import yaml
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth
st.set_page_config(page_title="E&D", page_icon="🗺️")
st.logo("map.png")




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
   st.title("Encryption and Decryption")
   st.image('gif.gif')
   st.header("Image Encryption and Decryption")
   st.subheader("How to use")
   with st.expander("**:red[How to use]**"):
      st.markdown('''

   1. **Upload an Image**:
      - Select and upload your image file.

   2. **Provide a 16-Byte Key**:
      - Enter a secure 16-byte encryption key.

   3. **Hit the Encrypt Button**:
      - Click the "Encrypt" button to securely encrypt your image.
      - You will then have the option to:
      - Download the encrypted image and key files.
      - Send the files via email.

   4. **Upload the Encrypted File**:
      - Select and upload your previously encrypted image file.

   5. **Provide a 32-Byte (64 Character) IV and the Previous Key**:
      - Enter the 32-byte Initialization Vector (IV) provided in the files you received.
      - Use the same 16-byte key used for encryption.

   6. **Hit the Decrypt Button**:
      - Click the "Decrypt" button.
      - If the IV matches the encrypted image bytes, the image will be successfully decrypted and converted back into an image file.

   Enjoy secure and easy image encryption and decryption !''')

   st.header("Text Encryption and Decryption")
   st.subheader("How to use")
   with st.expander(":red[How to use]"):
      st.markdown('''


   1. **Encrypt a Message**:
      - **Input**:
      - Enter your message.
      - Provide a keyphrase for encryption.
      - **Hit the Encrypt Button**:
      - Click the "Encrypt" button to securely encrypt your message.
      - After encryption, you will have the option to:
         - Download text files containing the key, salt, IV, and encrypted message.
         - Receive the files via email.

   2. **Decrypt a Message**:
      - **Fill All Fields in the Decryption Tab**:
      - Upload the encrypted message file.
      - Enter the keyphrase used during encryption.
      - Provide the salt and IV from the encrypted files.
      - **Hit the Decrypt Button**:
      - Click the "Decrypt" button to retrieve and view your original message.

   Enjoy secure and easy text encryption and decryption !''')
      
elif st.session_state["authentication_status"] is False:
    st.error('Username/password is incorrect')
elif st.session_state["authentication_status"] is None:
    st.warning('Please enter your username and password')




