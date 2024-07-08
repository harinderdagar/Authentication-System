# this is the main program of the app uses streamlit to control whole app
import streamlit as st
import auth_system #Control the authentication system of the app
import welcome # Shows the welcome page of the app

# Initialize session state for logged_in and current_page
def initialize_session_state():
    if "logged_in" not in st.session_state:
        st.session_state.logged_in = False
    if "current_page" not in st.session_state:
        st.session_state.current_page = "Home"

#Show the home page of the app
def show_home():
    st.session_state.current_page = "Home"
    st.header("Discover the App!!")
    st.write("Access the app by choosing Register or Login in the sidebar.")
   
#Show the Register page of the app
def show_register():
    st.session_state.current_page = "Register"
    st.header("Register")
    username = st.text_input("Enter username:")
    password = st.text_input("Enter password:", type="password")
    password2 = st.text_input("Retype password:", type="password")

    if st.button("Submit"):
        result = auth_system.register(username, password, password2)
        if result == "Registration successful.":
            st.session_state.logged_in = True
            st.session_state.current_page = "Registration"
            st.experimental_rerun()
        else:
            st.warning(result)

#Show the Login page of the app
def show_login():
    st.session_state.current_page = "Login"
    st.header("Login")
    username = st.text_input("Enter username:")
    password = st.text_input("Enter password:", type="password")

    if st.button("Submit"):
        result = auth_system.login(username, password)
        if result == "Login successful.":
            st.session_state.logged_in = True
            st.session_state.current_page = "Welcome"
            st.empty()
            st.experimental_rerun()
        else:
            st.warning(result)


#Show the registration success message and exit button
def show_registration_success():
    st.header("Registration is successfull")
    st.write("Click on Exit button to go to main page")
    if st.button("Exit"):
        st.session_state.logged_in = False
        st.session_state.current_page = "Home"
        st.experimental_rerun()

#Show the Welcome page of the app after successful login
def show_welcome():
    st.empty()
    option = st.sidebar.selectbox(
        "Select the page from dropdown box:",
        ["Welcome", "logout"]
    )
    sidebar_multiselect_placeholder = st.sidebar.empty()
    sidebar_select_placeholder = st.sidebar.empty()
 
    # Display home page content after successful login
    if option == "Welcome":
        st.title('Authentication is successful...')
        st.empty()
    
    # Logout from the app
    elif option == "logout":
        st.session_state.logged_in = False
        st.session_state.current_page = "Home"
        st.warning('Logging Out')
        st.experimental_rerun()
        # Redirect to specific URL
        # redirect_url = "https://kubernetes-pro.com"  # Replace this with the URL you want to redirect to
        # st.write(f'<meta http-equiv="refresh" content="0; URL={redirect_url}">', unsafe_allow_html=True)


# Main function of the app
# def main():
#     initialize_session_state()

#     if not st.session_state.logged_in:
#         show_home()

#     elif st.session_state.current_page == "Registration":
#         show_registration_success()

#     elif st.session_state.current_page == "Home":
#         show_home()

# Main function of the app
def main():
    initialize_session_state()

    if not st.session_state.logged_in:
        option = st.sidebar.selectbox(
            "Choose an option:",
            ["Home", "Register", "Login"],
            index=["Home", "Register", "Login"].index(st.session_state.current_page)
        )

        if option == "Home":
            show_home()
        elif option == "Register":
            show_register()
        elif option == "Login":
            show_login()

    elif st.session_state.current_page == "Registration":
        show_registration_success()

    elif st.session_state.current_page == "Welcome":
        show_welcome()

if __name__ == "__main__":
    main()
