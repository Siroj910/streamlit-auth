import sqlite3
import streamlit as st

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            studentid TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )
    ''')
    conn.commit()
    conn.close()

def add_user_to_db(studentid, hashed_password, role='user'):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (studentid, password, role) VALUES (?, ?, ?)', 
                       (studentid, hashed_password, role))
        conn.commit()
    except sqlite3.IntegrityError:
        st.error("Student already exists. Please choose another.")
    conn.close()


