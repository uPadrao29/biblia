import sqlite3
from flask import session, redirect, url_for, render_template
from functools import wraps



def login_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		if not session.get("user_id"):
			return redirect(url_for("login"))
		return f(*args, **kwargs)
	return decorated_function


def create_table():
	try:
		con = sqlite3.connect("./databases/users.sqlite")
		db = con.cursor()
		db.execute("""
CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT, 
username TEXT NOT NULL, 
hash TEXT NOT NULL, 
cache TEXT NOT NULL DEFAULT '',
language TEXT NOT NULL DEFAULT 'en'
account_creation DATE NOT NULL DEFAULT CURRENT_TIMESTAMP,
)
""")
		con.commit()
	except Exception as e:
		raise Exception(e)


def get_register_template_error(msg: str):
	return render_template("register.html", msg=msg, color="red")
