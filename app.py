
import streamlit as st
import hashlib
import sqlite3

# Database connection
def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS database (
            studentid TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()
#adding users
def add_user_to_db(studentid, hashed_password, role='user'):
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO database (studentid, password, role) VALUES (?, ?, ?)', 
                       (studentid, hashed_password, role))
        conn.commit()
    except sqlite3.IntegrityError:
        st.error("Student already exists. Please choose another.")
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_user(studentid, password):
    conn = sqlite3.connect('base.db')
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    cursor.execute("SELECT role FROM users WHERE studentid = ? AND password = ?", 
                   (studentid, hashed_password))
    result = cursor.fetchone()
    conn.close()
    return (result is not None, result[0] if result else None)


def signup():
    #TODO: need to add additional fields for the Student.
    new_studentid = st.text_input("Create student id")
    new_password = st.text_input("Create Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Sign Up"):
        if new_password != confirm_password:
            st.error("Passwords do not match.")
        else:
            hashed_password = hash_password(new_password)
            add_user_to_db(new_studentid, hashed_password)
            st.success("Account created successfully!")

def login():
    studentid = st.text_input("Student ID")
    password = st.text_input("Password", type="password")
    
    if st.button("Login"):
        is_valid, role = verify_user(studentid, password)
        if is_valid:
            st.success(f"Welcome back, {studentid}!")
            st.session_state['role'] = role
            st.session_state['studentid'] = studentid
        else:
            st.error("Invalid studentid or password")


def main():
    st.sidebar.title("Navigation")
    choice = st.sidebar.radio("Go to", ["Sign Up", "Login", "Dashboard"])
    
    if choice == "Sign Up":
        signup()
    elif choice == "Login":
        login()
        
if __name__ == '__main__':
    init_db()
    main()