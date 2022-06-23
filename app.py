from flask import Flask, flash,redirect,render_template,request,session
from flask_session import Session
import pyrebase
from functools import wraps


app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)



config = {
  "apiKey": "AIzaSyBcQr-xm0gqX0C0eB025v63feoRXRyx6dM",
  "authDomain": "team-expansion-54ae7.firebaseapp.com",
  "databaseURL": "https://team-expansion-54ae7-default-rtdb.firebaseio.com",
  "projectId": "team-expansion-54ae7",
  "storageBucket": "team-expansion-54ae7.appspot.com",
  "messagingSenderId": "932038990518",
  "appId": "1:932038990518:web:b67532c58cf678c6bfa417",
  "measurementId": "G-W310M4WJL0"
    }


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("UserID") is None:
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function



firebase = pyrebase.initialize_app(config)
auth = firebase.auth()


@app.route('/',methods=['POST','GET'])
def index():
    if session.get("UserID") is None:
        return render_template('index.html')
    return redirect('/homepage')


@app.route('/signup',methods=['POST','GET'])
def signup():
    if session.get("UserID") is None:
        if request.method=='POST':
            email = request.form.get('email')
            password = request.form.get('password')
            cnf_password = request.form.get('cnf_password')
            if password != cnf_password:
                flash('Password does not match !!!')
                return redirect('/signup')
            try:
                user = auth.create_user_with_email_and_password(email,password)
                session['UserID'] = user['localId']
            except:
                flash('Account already exists !!!')
                return redirect('/login')
            return redirect('/login')
        else:
            return render_template('signup.html')
    return redirect('/homepage')


@app.route('/login',methods=['POST','GET'])
def signin():
    if session.get("UserID") is None:
        if request.method=='POST':
            email = request.form.get('email')
            password = request.form.get('password')
            try:
            # if there is no error then signin the user with given email and password
                user=auth.sign_in_with_email_and_password(email,password)
                session['UserID'] = user['localId']
            except:
                flash('Email and Password does not match !!!')
                return redirect('/login')
            return redirect('/homepage')
        return render_template('login.html')
    return redirect('/homepage')


@app.route('/homepage',methods=['POST','GET'])
@login_required
def homepage():
    return render_template('homepage.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')





if __name__ == '__main__':
    app.run(debug=True)

