import os
import re
import sqlite3
from flask import Flask, session, redirect, url_for, render_template, request, abort
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import login_required, create_table, get_register_template_error
from tempfile import mkdtemp

# 67 books

app = Flask(__name__)

# Verify table existance in SQL
if not os.path.exists("./users.sqlite"):
	create_table()

@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.urandom(12).hex()
Session(app)

con = sqlite3.connect("users.sqlite", check_same_thread=False)
db = con.cursor()

con2 = sqlite3.connect("blivre.sqlite", check_same_thread=False)
db2 = con2.cursor()


def SQL(query: str, *args):
	rows = db.execute(query, args)
	con.commit()
	return rows.fetchall()


def SQL_BLIVRE(query: str, *args):
	rows = db2.execute(query, args)
	con2.commit()
	return rows.fetchall()



def padronize_text(text):
	buffer_list = []
	if text.__class__ != list:
		return None
	elif len(text) == 0:
		return None
	for i, dt in enumerate(text):
		if dt.__class__ == tuple:
			buffer_list.append({"text": dt[0]})
	return buffer_list


@app.route("/", methods=["GET", "POST"])
def index():
	if request.method == "GET":
		if session.get("user_id"):

			has_left = True
			has_right = True
			cache = SQL("SELECT cache FROM users WHERE id = ?", session["user_id"])[0][0]

			if not cache or int(cache.split("-")[0]) <= 0 or int(cache.split("-")[1]) <= 0:
				cache = '01-01' #chapter-book
				SQL("UPDATE users SET cache = ? WHERE id = ?", cache, session["user_id"])
			cache = cache.split("-")
			info = {
				'chapter': int(cache[0]),
				'book': int(cache[1])
			}
			data = padronize_text(SQL_BLIVRE("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
			if not data: 
				return redirect(url_for("index"), 301)
			if len(data) == 0: data = None
			return render_template("index.html", lines = data, info = info, has_right=has_right, has_left=has_left)
		return render_template("index.html")
	if request.method == "POST":
		if session.get("user_id"):
			back_max = request.form.get("back-max")
			back = request.form.get("back")
			next_max = request.form.get("next-max")
			next = request.form.get("next")
			metadata = request.form.get("meta").split("-")
			data = None
			info = None
			info = {
				"chapter": int(metadata[0]),
				"book": int(metadata[1])
			}
			has_left = True
			has_right = True
			max_chapters = SQL_BLIVRE("SELECT MAX(chapter) FROM verses WHERE book = ?", metadata[1])[0][0]
			if back:
				info["chapter"] -= 1
				if info["chapter"] <= 0:
					info["chapter"] += 1
					has_left = False
				data = padronize_text(SQL_BLIVRE("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
			elif back_max:
				info["chapter"] = 1
				data = padronize_text(SQL_BLIVRE("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
			elif next:
				info["chapter"] += 1
				if info["chapter"] > max_chapters:
					info["chapter"] -= 1
					has_right = False
				data = padronize_text(SQL_BLIVRE("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
			elif next_max:
				info["chapter"] = max_chapters
				data = padronize_text(SQL_BLIVRE("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
			return render_template("index.html", lines = data, info = info, has_left = has_left, has_right = has_right)
		return render_template("index.html")
	return abort(400)


@app.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "GET":
		return render_template("login.html")
	if request.method == "POST":
		session.clear()
		username = request.form.get("username")
		password = request.form.get("password")

		if not username or not password:
			return render_template("login.html", msg="Invalid username/password", color="red")

		rows = SQL("SELECT id, username, hash FROM users WHERE username = ?", username)
		if len(rows) != 1 or not check_password_hash(rows[0][2], password):
			return render_template("login.html", msg="Username/password incorrect.")

		session["user_id"] = rows[0][0]
		session["user_name"] = rows[0][1]
		return redirect(url_for("index"), 301)
	return abort(400)


@app.route("/logout", methods=["GET", "POST"])
def logout():
	session.clear()
	return redirect(url_for("login"))



@app.route("/register", methods=["GET", "POST"])
def register():
	if request.method == "GET":
		return render_template("register.html")
	if request.method == "POST":
		username = request.form.get("username")
		passwords = {
			"first": request.form.get("password"),
			"second": request.form.get("password-2")
		}
		patterns = {
			"name": re.compile(r'^[\w\d\s]{5,15}$'),
			"password": re.compile(r'^.{10,40}$')}
		if not username or not passwords["first"] or not passwords["second"]:
			return get_register_template_error(
				msg="Empty username/password"
			)
		if not patterns['name'].match(username):
			return get_register_template_error(
				msg="Your first name need at least 5 and 15 maximum"
			)
		if passwords["first"] != passwords["second"]:
			return get_register_template_error(
				msg="Passwords do not match"
			)
		if not patterns['password'].match(passwords['first']):
			return get_register_template_error(
				msg="Password need at least 10 characters and 40 maximum",
			)
		rows = SQL("SELECT COUNT(*) FROM users WHERE username = ?", username)
		if rows[0][0] != 0:
			return get_register_template_error(
				msg="Account already exist"
			)
		
		SQL_INSERT_USER_QUERY_RESULT = SQL("""
		INSERT INTO users (username, hash) VALUES (?, ?)""", 
		username, generate_password_hash(passwords["first"]))

		return redirect(url_for("login"), 301)
	return abort(400)


@app.route("/user/", methods=["GET", "POST"])
@login_required
def user():
	return redirect(url_for("index"))
	return render_template("user.html")


@app.route("/users/<name>")
def users(name):
	return redirect(url_for("index"))
	rows = SQL("""
SELECT username FROM users WHERE username = ?""")

@app.route("/configurations", methods=["GET", "POST"])
@login_required
def configurations():
	return redirect(url_for("index"))
	if request.method == "GET":
		return render_template("configurations.html")
	if request.method == "POST":
		username = request.form.get("new-username")
		passwords = {
			'old': request.form.get("old-password"),
			'new': {
				'1': request.form.get('new-password-1'),
				'2': request.form.get('new-password-2')
			}
		}
		if passwords['new']['1'] != passwords['new']['2']:
			return render_template("configurations.html", 
						  msg="New passwords do not match",
						  color="red")
		patterns = {
			'name': {
				'pattern': re.compile(r'^[\w\d\S]{3,30}$'),
				'msg': 'Name must have at last 3 digits and maximum 30. Including only words, digits and non-spaces characters'
			},
			'password': {
				'pattern': re.compile(r'^.{10,40}$'),
				'msg': 'Password must have at least 10 characters and maximum 40.'
			}
		}
		if not patterns["name"]["pattern"].match(username):
			return render_template("configurations.html", 
						  msg=patterns["name"]["msg"],
						  color="red")
		
		if not patterns["password"]["pattern"].match(passwords["new"]["1"]):
			return render_template("configurations.html",
						  msg=patterns["password"]["msg"],
						  color="red")
		
		return redirect(url_for("index"))
	return abort(400)
	


if __name__ == "__main__":
	app.run()
