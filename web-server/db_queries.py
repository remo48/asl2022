from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
import logging


db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = "users"
    uid = db.Column(db.String, primary_key=True)
    lastname = db.Column(db.String, nullable=False)
    firstname = db.Column(db.String, nullable=False)
    email = db.Column(db.String, nullable=False)
    pwd = db.Column(db.String, nullable=False)

    def get_id(self):
        return self.uid

    def is_admin(self):
        return False

    def is_admin(self):
        return self.uid == "ad"


class Challenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String, nullable=False)
    challenge = db.Column(db.String, nullable=False)


class Certificate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    serial_number = db.Column(db.String, nullable=False)
    uid = db.Column(db.String, nullable=False)




def getUserByUid(uid):
    logging.info("DB: Get User by UID, UID: %s", uid)
    user = User.query.filter_by(uid=uid).first()
    return user


def updateUser(uid, firstName, lastName, email):
    logging.info("DB: Update User, UID: %s", uid)
    user = getUserByUid(uid)
    user.firstname = firstName
    user.lastname = lastName
    user.email = email
    db.session.commit()


def createChallenge(serial_number, challenge):
    logging.info("DB: Create Challenge, Serial Number: %s", serial_number)
    challenge = Challenge(serial_number=serial_number, challenge=challenge)
    db.session.add(challenge)
    db.session.commit()


def deleteChallengesBySerialNumber(serial_number):
    logging.info("DB: Delete Challenges by Serial Number, Serial Number: %s", serial_number)
    Challenge.query.filter_by(serial_number=serial_number).delete()


def getChallengeBySerial(serial_number):
    logging.info("DB: Get Challenge by Serial Number, Serial Number: %s", serial_number)
    challenge = Challenge.query.filter_by(serial_number=serial_number).first()
    return challenge


def getSerialNumbersByUid(uid):
    logging.info("DB: Get Serial Numbers by UID, UID: %s", uid)
    serials = Certificate.query.filter_by(uid=uid).all()
    return serials


def getUidBySerial(serial_number):
    logging.info("DB: Get UID by Serial Number, Serial Number: %s", serial_number)
    cert = Certificate.query.filter_by(serial_number=serial_number).first()
    return cert.uid


def addCertificate(serial_number, uid):
    logging.info("DB: Add Certificate, Serial Number: %s, UID: %s", serial_number, uid)
    certificate = Certificate(serial_number=serial_number, uid=uid)
    db.session.add(certificate)
    db.session.commit()


def removeCertificate(serial_number):
    logging.info("DB: Remove Certificate, Serial Number: %s", serial_number)
    Certificate.query.filter_by(serial_number=serial_number).delete()
    db.session.commit()
