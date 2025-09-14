from flask import Flask, request, redirect, make_response, abort
import sqlite3
import urllib
import quoter_templates as templates
from markupsafe import escape

# Run using `poetry install && poetry run flask run --reload`
app = Flask(__name__)
app.static_folder = '.'

# Open the database. Have queries return dicts instead of tuples.
# The use of `check_same_thread` can cause unexpected results in rare cases. We'll
# get rid of this when we learn about SQLAlchemy.
db = sqlite3.connect("db.sqlite3", check_same_thread=False)
db.row_factory = sqlite3.Row

# Log all requests for analytics purposes
log_file = open('access.log', 'a', buffering=1)
@app.before_request
def log_request():
    log_file.write(f"{request.method} {request.path} {dict(request.form) if request.form else ''}\n")


# Set user_id on request if user is logged in, or else set it to None.
@app.before_request
def check_authentication():
    if 'user_id' in request.cookies:
        try:
            request.user_id = int(request.cookies['user_id'])
        except (TypeError, ValueError):
            request.user_id = None
    else:
        request.user_id = None


# Basic input validation and cleaning
def clean_text(s: str, max_len: int) -> str:
    if s is None:
        raise ValueError("Missing value")
    s = s.strip()
    if not s:
        raise ValueError("Empty value")
    return s[:max_len]


@app.after_request
def set_security_headers(resp):
    resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'; base-uri 'self'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


# The main page
@app.route("/")
def index():
    quotes = db.execute("select id, text, attribution from quotes order by id").fetchall()
    return templates.main_page(quotes, request.user_id, request.args.get('error'))


# The quote comments page
@app.route("/quotes/<int:quote_id>")
def get_comments_page(quote_id):
    quote = db.execute("select id, text, attribution from quotes where id = ?", (quote_id,)).fetchone()
    comments = db.execute(
        """
        select text, datetime(time,'localtime') as time, name as user_name
        from comments c
        left join users u on u.id = c.user_id
        where quote_id = ?
        order by c.id
        """,
        (quote_id,)
    ).fetchall()
    return templates.comments_page(quote, comments, request.user_id)


# Post a new quote
@app.route("/quotes", methods=["POST"])
def post_quote():
    try:
        text = clean_text(request.form.get('text'), 1000)
        attribution = clean_text(request.form.get('attribution'), 120)
    except ValueError as e:
        abort(400, description=str(e))

    with db:
        db.execute(
            "insert into quotes(text, attribution) values(?, ?)",
            (text, attribution),
        )
    return redirect("/#bottom")


# Post a new comment
@app.route("/quotes/<int:quote_id>/comments", methods=["POST"])
def post_comment(quote_id):
    try:
        text = clean_text(request.form.get('text'), 1000)
    except ValueError as e:
        abort(400, description=str(e))

    with db:
        db.execute(
            "insert into comments(text, quote_id, user_id) values(?, ?, ?)",
            (text, quote_id, request.user_id),
        )
    return redirect(f"/quotes/{quote_id}#bottom")


# Sign in user
@app.route("/signin", methods=["POST"])
def signin():
    username = request.form.get("username", "").lower().strip()
    password = request.form.get("password", "")

    if not username or not password:
        return redirect('/?error='+urllib.parse.quote("Username and password required"))

    user = db.execute("select id, password from users where name = ?", (username,)).fetchone()
    if user: # user exists
        if password != user['password']:
            # wrong! redirect to main page with an error message
            return redirect('/?error='+urllib.parse.quote("Invalid password!"))
        user_id = user['id']
    else: # new sign up
        with db:
            cursor = db.execute("insert into users(name, password) values(?, ?)", (username, password))
            user_id = cursor.lastrowid
    
    response = make_response(redirect('/'))
    response.set_cookie('user_id', str(user_id))
    return response


# Sign out user
@app.route("/signout", methods=["GET"])
def signout():
    response = make_response(redirect('/'))
    response.delete_cookie('user_id')
    return response
