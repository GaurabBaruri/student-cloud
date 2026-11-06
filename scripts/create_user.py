"""Create a student account:  python scripts/create_user.py"""
import getpass
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from werkzeug.security import generate_password_hash  # noqa: E402

import app  # noqa: E402

app.init_db()
username = input("Enter username: ").strip()
password = getpass.getpass("Enter password: ")
con = app.db()
try:
    con.execute("INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password)))
    con.commit()
    print("Student account created successfully!")
except Exception as e:
    print(f"Could not create user: {e}")
finally:
    con.close()
