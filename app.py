import os
import re
import sqlite3
import time
from flask import Flask, session, redirect, url_for, render_template, request, abort
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash
from helpers import login_required, get_register_template_error
from tempfile import mkdtemp


app = Flask(__name__)
max_books = None
max_chapters = None


@app.after_request
def after_request(response):
	response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
	response.headers["Expires"] = 0
	response.headers["Pragma"] = "no-cache"
	response.headers["SameSite"] = "Lax"
	return response


app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = os.urandom(12).hex()
Session(app)


CONNECTION_MAIN = sqlite3.connect("./databases/users.sqlite", check_same_thread=False)
DB_MAIN = CONNECTION_MAIN.cursor()

CONNECTION_SECONDARY = sqlite3.connect("./databases/blivre.sqlite", check_same_thread=False)
DB_SECONDARY = CONNECTION_SECONDARY.cursor()


def SQL(query: str, *args):
	rows = DB_MAIN.execute(query, args)
	CONNECTION_MAIN.commit()
	return rows.fetchall()


def SQL_SECONDARY(query: str, *args):
	rows = DB_SECONDARY.execute(query, args)
	CONNECTION_SECONDARY.commit()
	return rows.fetchall()


def padronize_text(text: list[tuple]):
	buffer_list = []
	try:
		if text.__class__ != list or len(text) == 0:
			return None
	except Exception as e:
		print(f"|{padronize_text.__name__}| ERROR: { e }")

	for i, dt in enumerate(text):
		if dt.__class__ == tuple:
			buffer_list.append({"index": i+1,"text": dt[0]})
	return buffer_list


def get_max_chapters(book_id: int):
	rows = SQL_SECONDARY("SELECT MAX(chapter) FROM verses WHERE book = ?", book_id)[0][0]
	return rows

def load_max_books():
	global max_books
	max_books = SQL_SECONDARY("SELECT MAX(book) FROM verses")[0][0]
load_max_books()


@app.route("/", methods=["GET", "POST"])
def index():
	global max_chapters
	if request.method == "GET":
		if session.get("user_id"):

			has_left = True
			has_right = True
			cache = SQL("SELECT cache FROM users WHERE id = ?", session["user_id"])[0][0]
			reset_cache = False
			if reset_cache or not cache:
				cache = '01-01' #chapter-book
				SQL("UPDATE users SET cache = ? WHERE id = ?", cache, session["user_id"])
			cache = cache.split("-")
			info = {
				'chapter': int(cache[0]),
				'book': int(cache[1])
			}
			data = padronize_text(SQL_SECONDARY("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
			if not data: 
				return redirect(url_for("index"), 301)
			if len(data) == 0: data = None
			return render_template("index.html", lines = data, info = info, has_right=has_right, has_left=has_left)
		return render_template("index.html")
	if request.method == "POST":
		if session.get("user_id"):
			act_buttons = {
				"back_max": request.form.get("back-max"),
				"back": request.form.get("back"),
				"next_max": request.form.get("next-max"),
				"next": request.form.get("next")
			}
			metadata = request.form.get("meta").split("-")
			try:
				range_bar = int(request.form.get("range-bar-meta"))
				if not range_bar: 
					range_bar = 15
			except Exception:
				range_bar = 15
			data = None
			info = None
			info = {
				"chapter": int(metadata[0]),
				"book": int(metadata[1])
			}
			has_left = True
			has_right = True
			if not max_chapters:
				max_chapters = get_max_chapters(metadata[1])
			if act_buttons["back"]:
				info["chapter"] -= 1
				if info["chapter"] <= 0:
					if info["book"] > 1:
						info["book"] -= 1
						max_chapters = get_max_chapters(info["book"])
						info["chapter"] = max_chapters if max_chapters else 1
					else:
						info["chapter"] += 1
						has_left = False
				data = padronize_text(SQL_SECONDARY("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
				max_chapters = get_max_chapters(info["book"])
			elif act_buttons["back_max"]:
				info["chapter"] = 1
				data = padronize_text(SQL_SECONDARY("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
			elif act_buttons["next"]:
				info["chapter"] += 1
				max_chapters = get_max_chapters(info["book"])
				if info["chapter"] > max_chapters:
					info["chapter"] = 1
					info["book"] += 1
				data = padronize_text(SQL_SECONDARY("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
				max_chapters = get_max_chapters(info["book"])
			elif act_buttons["next_max"]:
				max_chapters = get_max_chapters(info["book"])
				info["chapter"] = max_chapters
				data = padronize_text(SQL_SECONDARY("SELECT text FROM verses WHERE chapter = ? AND book = ?", info["chapter"], info["book"]))
				SQL("UPDATE users SET cache = ? WHERE id = ?", f"{info['chapter']}-{info['book']}", session["user_id"])
			return render_template("index.html", lines = data, info = info, has_left = has_left, has_right = has_right, range_bar = range_bar)
		return render_template("index.html")
	return abort(400)


@app.route("/login", methods=["GET", "POST"])
def login():
	if request.method == "GET":
		return render_template("login.html")
	if request.method == "POST":
		session["user_id"] = 6
		session["user_name"] = "foo"
		return redirect(url_for("index"), 301)
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
