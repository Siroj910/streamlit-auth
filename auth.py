import streamlit as st
import sqlite3
import hashlib

def init_db():
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS database (
            login TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()

def add_user_to_db(login, hashed_password, role='user'):
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO database (login, password, role) VALUES (?, ?, ?)', 
                       (login, hashed_password, role))
        conn.commit()
        st.success("Account created successfully!")
    except sqlite3.IntegrityError:
        st.error("This login already exists. Please choose another.")
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(login, password):
    conn = sqlite3.connect('auth.db')
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute("SELECT role FROM database WHERE login = ? AND password = ?", 
                   (login, hashed_password))
    result = cursor.fetchone()
    conn.close()
    return (result is not None, result[0] if result else None)

def signup():
    st.title("Sign Up")
    login = st.text_input("New User Login")
    new_password = st.text_input("New User Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    role = st.selectbox("Role", options=["user", "admin"])

    if st.button("Create Account"):
        if new_password != confirm_password:
            st.error("Passwords do not match.")
        elif not login or not new_password:
            st.error("Login and Password fields cannot be empty.")
        else:
            hashed_password = hash_password(new_password)
            add_user_to_db(login, hashed_password, role)

def login():
    st.title("Login")
    login = st.text_input("Login")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        is_valid, role = verify_user(login, password)
        if is_valid:
            st.success(f"Welcome back, {login}!")
            st.session_state['role'] = role
            st.session_state['login'] = login
            st.session_state['is_authenticated'] = True
        else:
            st.error("Invalid login or password")

def admin_page():
    st.title("Admin Dashboard")
    st.write("Welcome, Admin!")
    st.write("You can create new user accounts below.")
    signup()

def user_page():
    st.title("User Dashboard")
    st.write("Welcome to the User Dashboard!")
    input = st.text_input("Login")
    btn = st.button("Seaech", type="text")
    


# Main conf
def main():
    if 'is_authenticated' not in st.session_state:
        st.session_state['is_authenticated'] = False

    if not st.session_state['is_authenticated']:
        login()
    else:
        if st.session_state['role'] == 'admin':
            admin_page()
        else:
            user_page()

if __name__ == '__main__':
    init_db()
    main()
