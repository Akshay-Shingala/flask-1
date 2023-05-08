from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import random
import validate
from dataBase import UserTable

app = Flask(__name__)


app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 465
app.config["MAIL_USE_SSL"] = True
app.config["MAIL_USERNAME"] = "gokulfarm056@gmail.com"
app.config["MAIL_PASSWORD"] = "upvaozwdapbeclfl"
mail = Mail(app)
app.secret_key = "appsecretkey"
try:
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///dbs.sqlite3"
    db = SQLAlchemy(app)
except:
    pass


class user(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String, unique=True, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    phone = db.Column(db.String(10), unique=True, nullable=False)
    password = db.Column(db.Text, nullable=False)
    OTP = db.Column(db.String(6), default=0)


userTable = UserTable(db, user)


@app.route("/Get email")
def getEmail():
    return render_template("getMail.html")


@app.route("/sendEmail", methods=["post"])
def sendEmail():
    sendMailId = request.form["emailId"]
    msg = Message()
    msg.subject = "forgot password?"
    msg.sender = "gokulfarm056@gmail.com"
    msg.recipients = [sendMailId]
    msg.body = "hello "
    msg.html = render_template("mailBody.html", email=sendMailId)
    mail.send(msg)
    return "check your mail "


@app.route("/verify OTP", methods=["POST", "GET"])
def verifyOTP():
    if request.method == "POST":
        OTPf = request.form["OTP"]
        obj = session["OTP"]
        if str(obj["OTP"]) == OTPf:
            session["checkOTP"] = True
            print(session["OTP"])
            return redirect(url_for("OTPforgot_pass"))
        return render_template("verifyOTP.html")
    return render_template("verifyOTP.html")


@app.route("/OTPforgot_pass", methods=["GET", "POST"])
def OTPforgot_pass():
    if request.method == "POST":
        newPassword = request.form["newPassword"]
        comPassword = request.form["comPassword"]
        OTP = session["OTP"]
        print(session.keys())
        if not "checkOTP" in session.keys():
            flash("user not found")
        elif newPassword != comPassword:
            flash("both password not match")
        else:
            forgetUser = userTable.getUser(email=OTP["email"])
            forgetUser.password = newPassword
            db.session.commit()
            flash("password changed")
            return redirect("/login")
    return render_template("ForgotPasswordOTP.html")


@app.route("/OTP email")
def getOTPemail():
    return render_template("emailForOTP.html")


@app.route("/sendOTP", methods=["POST"])
def sendOTP():
    sendEmailID = request.form["emailId"]
    OTPuser = userTable.getUser(email=sendEmailID)
    if OTPuser != None:
        OTP = random.randint(100000, 999999)
        msg = Message()
        msg.subject = "forgot password?"
        msg.sender = "gokulfarm056@gmail.com"
        msg.recipients = [sendEmailID]
        msg.body = str(OTP)
        mail.send(msg)
        session["OTP"] = {"OTP": OTP, "email": sendEmailID}
        return redirect(url_for("verifyOTP"))
    else:
        flash("user email not found")
        return redirect(url_for("getOTPemail"))


@app.route("/")
def Home():
    return render_template("home.html")


@app.route("/logout", methods=["POST"])
def Logout():
    if "user" in session.keys():
        session.pop("user")
    return redirect("/login")


# @app.errorhandler(404)
# def page404(error):
#     return render_template("page404.html"), 404


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user" in session.keys():
        flash("already logged in")
        return redirect("/")
    if request.method == "POST":
        username = request.form["username"]
        if not validate.checkString(username) and not validate.checkEmail(username):
            flash("enter proper username")
        else:
            password = request.form["password"]
            userLoginEmail = user.query.filter_by(
                email=username, password=password
            ).first()
            print(userLoginEmail)
            if userLoginEmail != None:
                session["user"] = userLoginEmail.email
                flash("login successful")
                return redirect("/")
            else:
                flash("wrong username or password")
    return render_template("login.html")


@app.route("/Registrations", methods=["GET", "POST"])
def Register():
    if "user" in session.keys():
        flash("already logged in")
        return redirect("/")
    if request.method == "POST":
        valid = True
        firstName = request.form["Username"]
        if not validate.checkString(firstName):
            valid = False
            flash("enter proper username")

        email = request.form["emailId"]
        if not validate.checkEmail(email):
            valid = False
            flash("enter proper email address")

        phone = request.form["phoneNumber"]
        if not validate.checkNumber(phone) and len(phone) != 10:
            valid = False
            flash("enter proper phone number")

        password = request.form["password"]
        coPassword = request.form["cpassword"]
        if password != coPassword:
            flash("password and conform password not match")
        if valid:
            try:
                userTable.addUser(
                    username=firstName, email=email, password=password, phone=phone
                )
                return redirect(url_for("login"))
            except Exception as e:
                flash("sorry, some error happened")
                print(e)

    return render_template("Registration.html")


@app.route("/forgot password", methods=["POST"])
def forgot_pass():
    if request.method == "POST":
        try:
            email = request.form["emailId"]
            newPassword = request.form["newPassword"]
            comPassword = request.form["comPassword"]
            forgetUser = UserTable.getUser(email=email)
            if forgetUser == None:
                flash("user not found")
            else:
                if newPassword == comPassword:
                    forgetUser.password = newPassword
                    db.session.commit()
                    flash("password changed")
                    return redirect("/login")
        except Exception as e:
            email = request.form["emailId"]
            return render_template("ForgotPassword.html", email=email)


@app.route("/change password", methods=["POST", "Get"])
def changePassword():
    if "user" not in session.keys():
        flash("login first", "error")
        return redirect("/login")
    if request.method == "POST":
        oldPassword = request.form["oldPassword"]
        newPassword = request.form["newPassword"]
        comPassword = request.form["comPassword"]
        print(session["user"])
        updateUser = userTable.getUser(email=session["user"])
        if updateUser.password == oldPassword:
            if newPassword == comPassword:
                updateUser.password = newPassword
                db.session.commit()
                flash("Password change", "success")
                return redirect("/")
            else:
                flash("new Password and confirmation password not match", "error")
        else:
            flash("Password not match", "error")
    return render_template("ChangePassword.html")


with app.app_context():
    db.create_all()
