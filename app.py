import os
import re

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    stocks = db.execute(f'SELECT symbol,SUM(shares),price,transacted FROM history WHERE id = {session["user_id"]} GROUP BY symbol HAVING SUM(shares) > 0')
    print(stocks)

    cash_remaining = db.execute('SELECT * FROM users WHERE id = ?',session["user_id"])[0]["cash"]

    return render_template("index.html", stocks=stocks , cash_remaining=cash_remaining)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        details = lookup(request.form.get("symbol"))
        shares = float(request.form.get("share"))

        if not details:
            return apology("No such symbol!",400)

        cash = float(db.execute(f'SELECT * FROM users WHERE id = {session["user_id"]}')[0]["cash"])
        spent = shares*details["price"]
        if cash < spent:
            return apology("Not enough money!",400)

        available_cash = cash - spent
        dt_string = datetime.now().strftime(f'%d/%m/%Y %H:%M:%S')
        db.execute(f'UPDATE users SET cash = {available_cash} WHERE id = {session["user_id"]}')
        db.execute('INSERT INTO history (id,symbol,shares,price,transacted) VALUES(?,?,?,?,?)',session["user_id"],details["symbol"],shares,details["price"],dt_string)
        return redirect("/")

    else:
        return render_template("buy.html")




@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    stocks = db.execute(f'SELECT * FROM history WHERE id = {session["user_id"]}')
    return render_template("history.html",stocks=stocks)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""


    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == 'POST':
        details = lookup(request.form.get("symbol"))
        if details == {}:
            return apology("No such stock!",400)
        return render_template("quoted.html",details=details)

    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method =='POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_again = request.form.get('password_again')

        if username == "" or len(db.execute('SELECT username FROM users WHERE username = ?', username)) > 0:
            return apology("Invalid Username: Blank, or already exists")
        if password == "" or password != password_again:
            return apology("Invalid Password: Blank, or does not match")
        # Add new user to users db (includes: username and HASH of password)
        db.execute('INSERT INTO users (username, hash) VALUES(?, ?)', username, generate_password_hash(password))

        return redirect('/login')

    else:
        return render_template('register.html')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'POST':
        details = lookup(request.form.get("symbol"))
        stocks = db.execute(f'SELECT symbol,SUM(shares),price,transacted FROM history WHERE id = ? AND symbol = ? GROUP BY symbol HAVING SUM(shares) > 0',session["user_id"],details["symbol"])
        if stocks[0]["SUM(shares)"] < float(request.form.get("share")):
            return apology("over selling stocks")
        sell_stock = 0 - float(request.form.get("share"))


        dt_string = datetime.now().strftime(f'%d/%m/%Y %H:%M:%S')
        available_cash = db.execute(f'SELECT * FROM users WHERE id = ?',session["user_id"])[0]["cash"] + details["price"]*(-sell_stock)
        db.execute(f'UPDATE users SET cash = ? WHERE id = ?',available_cash,session["user_id"])
        db.execute('INSERT INTO history (id,symbol,shares,price,transacted) VALUES(?,?,?,?,?)',session["user_id"],details["symbol"],sell_stock,details["price"],dt_string)


        return redirect('/')

    else:
        symbols = []
        stocks = db.execute(f'SELECT * FROM history WHERE id = {session["user_id"]} GROUP BY symbol HAVING SUM(shares) > 0')

        for stock in stocks:
            symbols.append(stock["symbol"])

        return render_template("sell.html",symbols=symbols)
