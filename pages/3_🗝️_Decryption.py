import streamlit as st
import Helper as h
import yaml
from yaml.loader import SafeLoader
import streamlit_authenticator as stauth


def main():



    st.header("Decrypt Image 🔓")

    encrypted_image_file = st.file_uploader("Upload Encrypted Image 🚀", type=["enc"],key='up')

    iv_input = st.text_input("Enter the IV for decryption 🔐")

    if iv_input and len(iv_input) != 32:
        st.error("IV should be a 16-byte hex string.")
    else:
        try:
            iv = bytes.fromhex(iv_input)
            st.session_state['iv'] = iv
        except ValueError:
            st.error("Invalid IV format. IV should be a 16-byte hex string.")
            st.stop()

        key_input_dec = st.text_input("Enter the 16-byte decryption key 🗝️")

        if key_input_dec and len(key_input_dec) == 16:
            key_dec = key_input_dec.encode()

            if st.button("Decrypt Image 🔓"):
                if encrypted_image_file is not None:
                    encrypted_image_bytes = encrypted_image_file.read()

                    try:
                        decrypted_image, decrypted_hash = h.decrypt_image(encrypted_image_bytes, key_dec, iv)
        
                      
                        st.success("Decryption successful!  🚀")
                        st.balloons()
                        # if st.toggle("Show"):
                        st.image(decrypted_image, channels="BGR", caption="Decrypted Image")

                    except Exception as e:
                        st.error(f"Decryption failed: {e}")
                else:
                    st.warning("Upload an encrypted image file first.")
        else:
            st.warning("Enter the decryption key before decrypting the image.")


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


