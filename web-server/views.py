import os
from flask import render_template, request, redirect, send_file
import logging
from flask.blueprints import Blueprint
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
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates, serialize_key_and_certificates
from cryptography.hazmat.primitives.serialization import NoEncryption
import base64
web = Blueprint(
    "web",
    __name__,
    template_folder="templates",
)

login_manager = LoginManager()


@login_manager.user_loader
def load_user(uid):
    user = getUserByUid(uid)
    return user


@web.route("/login")
def login():
    logging.info("Page: Login")
    return render_template("login.html")


@web.route("/logout")
@fresh_login_required
def logout():
    logging.info("Page: Login, User: %s", current_user.uid)
    logout_user()
    return redirect("/login")


@web.route("/login", methods=["POST"])
def login_post():
    uid = request.form.get("uid")
    logging.info("Page: Login, User: %s", uid)
    password = request.form.get("password")
    user = getUserByUid(uid)
    if not user or not checkPassword(password, user.pwd):
        logging.info("Page: Login, User: %s not found", uid)
        return render_template("login.html", error="Invalid credentials")

    login_user(user)
    logging.info("Page: Login Successful, User: %s", uid)
    if current_user.is_admin():
        logging.info("Page: Login Successful, Redirect to Admin, User: %s", uid)
        return redirect("/admin")
    return redirect("/profile")


@web.route("/login_cert")
def login_cert():
    logging.info("Page: Login")
    return render_template("login_cert.html")


@web.route("/get_challenge", methods=["POST"])
def challenge():
    serial_number = request.json.get("serial")
    logging.info("Page: Get challenge, Serial: %s", serial_number)
    deleteChallengesBySerialNumber(serial_number)
    challenge = os.urandom(64).hex()
    createChallenge(serial_number, challenge)
    return {"challenge": challenge}


@web.route("/solve_challenge", methods=["POST"])
def solve_challenge():
    signature = request.json.get("signature")
    serial = request.json.get("serial")
    logging.info("Page: Solve challenge, Serial: %s", serial)
    challenge = getChallengeBySerial(serial)

    if not challenge:
        logging.info("Page: Solve challenge, Serial: %s not found", serial)
        return render_template("login_credentials.html", error="Invalid credentials")

    if not verifyChallenge(challenge.challenge, signature, serial):
        logging.info("Page: Solve challenge, Serial: %s not verified", serial)
        return render_template("login_credentials.html", error="Invalid credentials")

    user_uid = getUidBySerial(serial)
    user = getUserByUid(user_uid)

    if not user:
        logging.info("Page: Solve challenge, User: %s not found", user_uid)
        return render_template("login_credentials.html", error="Invalid credentials")

    login_user(user)
    logging.info("Page: Login Successful, User: %s", user_uid)
    if current_user.is_admin():
        logging.info("Page: Login Successful, Redirect to Admin, User: %s", user_uid)
        return redirect("/admin")
    return redirect("/profile")


@web.route("/profile")
@fresh_login_required
def profile():
    logging.info("Page: Profile, User: %s", current_user.uid)
    if current_user.is_admin():
        logging.info("Page: Profile, Redirect to Admin, User: %s", current_user.uid)
        return redirect("/admin")
    return render_template("profile.html")


@web.route("/profile", methods=["POST"])
@fresh_login_required
def profile_post():
    logging.info("Page: Profile, User: %s", current_user.uid)
    if current_user.is_admin():
        logging.info("Page: Profile, Redirect to Admin, User: %s", current_user.uid)
        return redirect("/admin")
    last_name = request.form.get("lastname")
    first_name = request.form.get("firstname")
    email = request.form.get("email")
    password = request.form.get("password")
    updateUser(current_user.uid, first_name, last_name, email)
    return redirect("/profile")


@web.route("/certificates")
@fresh_login_required
def certificates():
    logging.info("Page: Certificates, User: %s", current_user.uid)
    if current_user.is_admin():
        logging.info("Page: Certificates, Redirect to Admin, User: %s", current_user.uid)
        return redirect("/admin")
    serials = getSerialNumbersByUid(current_user.uid)
    certs = getCertificatesBySerialNumbers([serial.serial_number for serial in serials])
    certs = certs if certs else []
    return render_template("certificates.html", certs=certs)


@web.route("/certificates", methods=["POST"])
@fresh_login_required
def certificates_post():
    logging.info("Page: New Certificate, User: %s", current_user.uid)
    if current_user.is_admin():
        logging.info("Page: New Certificate, Redirect to Admin, User: %s", current_user.uid)
        return redirect("/admin")
    cert = getNewCertificate(
        current_user.uid,
        current_user.firstname,
        current_user.lastname,
        current_user.email,
    )

    serial = cert["serial"]
    addCertificate(serial, current_user.uid)


    # TODO: cert needs to be written to file correctly  
    data = cert["data"].encode()
   
    if not os.path.exists("client_certs"):
        os.makedirs("client_certs")

    filename = f"client_certs/{serial}.p12"
    with open(filename, "wb") as f:
        f.write(data)

    new_cert = send_file(filename, as_attachment=True)
    os.remove(filename)
    return new_cert


@web.route("/revoke", methods=["POST"])
@fresh_login_required
def revoke():
    logging.info("Page: Revoke, User: %s", current_user.uid)
    if current_user.is_admin():
        logging.info("Page: Revoke, Redirect to Admin, User: %s", current_user.uid)
        return redirect("/admin")
    for _, serial in request.form.items():
        if current_user.uid == getUidBySerial(serial):
            revokeCertificate(serial)
            removeCertificate(serial)
    return redirect("/certificates")


@web.route("/admin")
@fresh_login_required
def admin():
    logging.info("Page: Admin, User: %s", current_user.uid)
    if not current_user.is_admin():
        logging.info("Page: Admin, Redirect to Profile, User: %s", current_user.uid)
        return redirect("/profile")
    return render_template("admin.html", admin_info=getAdminInfo())
