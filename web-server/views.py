import os
from flask import render_template, request, redirect, Flask, send_file
import logging
from flask_login import (
    login_user,
    fresh_login_required,
    logout_user,
    current_user,
    LoginManager,
)
from db_queries import *
from ca_queries import *
from utils import *


app = Flask(__name__)
app.config.from_pyfile("config.py")
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.session_protection = "strong"


@login_manager.user_loader
def load_user(user_id):
    user = getUserById(user_id)
    return User(user)


@app.route("/login")
def login():
    logging.info("login")
    return render_template("login.html")


@app.route("/logout")
@fresh_login_required
def logout():
    logout_user()
    return redirect("/login")


@app.route("/login", methods=["POST"])
def login_post():
    uid = request.form.get("uid")
    password = request.form.get("password")
    user = User(getUserByUid(uid))
    if not user or not checkPassword(password, user.pwd):
        return render_template("login.html")

    login_user(user)
    if current_user.is_admin():
        return redirect("/admin")
    return redirect("/profile")


@app.route("/login_cert")
def login_cert():
    return render_template("login_cert.html")


@app.route("/get_challenge", methods=["POST"])
def challenge():
    serial_number = int(request.json.get("serial"))
    deleteChallengesBySerialNumber(serial_number)
    # challenge = os.urandom(64).hex()
    challenge = (b"a" * 64).hex()
    createChallenge(serial_number, challenge)
    return {"challenge": challenge}


@app.route("/solve_challenge", methods=["POST"])
def solve_challenge():
    signature = request.json.get("signature")
    serial = request.json.get("serial")

    challenge = getChallengeBySerial(serial)

    if not challenge:
        print("No challenge found")
        return {"error": "Error"}, 404

    email = verifyChallenge(challenge, signature, serial)
    if not email:
        print("Challenge not verified")
        return {"error": "Error"}, 404

    user = User(getUserByEmail(email))
    if not user:
        print("User not found")
        return {"error": "Error"}, 404

    login_user(user)
    if current_user.is_admin():
        return redirect("/admin")
    return redirect("/profile")


@app.route("/profile")
@fresh_login_required
def profile():
    return render_template("profile.html")


@app.route("/profile", methods=["POST"])
@fresh_login_required
def profile_post():
    last_name = request.form.get("lastname")
    first_name = request.form.get("firstname")
    email = request.form.get("email")
    password = request.form.get("password")
    updateUser(current_user.uid, first_name, last_name, email)
    return redirect("/profile")


@app.route("/certificates")
@fresh_login_required
def certificates():
    serials = getSerialNumbersByUid(current_user.uid)
    certs = getCertificatesBySerialNumbers(serials)
    return render_template("certificates.html", certs=certs)


@app.route("/certificates", methods=["POST"])
@fresh_login_required
def certificates_post():
    cert = getNewCertificate(
        current_user.uid,
        current_user.firstname,
        current_user.lastname,
        current_user.email,
    )

    serial = cert["serial"]
    addCertificate(serial, current_user.uid)

    data = cert["data"]

    if not os.path.exists("certs"):
        os.makedirs("certs")

    filename = f"client_certs/{serial}.p12"
    with open(filename, "wb") as f:
        f.write(data.encode("utf-8"))

    new_cert = send_file(filename, as_attachment=True)
    os.remove(filename)
    return new_cert


@app.route("/revoke", methods=["POST"])
@fresh_login_required
def revoke():
    for _, serial in request.form.items():
        if current_user.uid == getUidBySerial(serial):
            revokeCertificate(serial)
            removeCertificate(serial)
    return redirect("/certificates")


@app.route("/admin")
@fresh_login_required
def admin():
    if not current_user.is_admin():
        return redirect("/profile")
    return render_template("admin.html", admin_info=getAdminInfo())
