from flask_login import UserMixin


class User(UserMixin):
    def __init__(self, data):
        self.uid = data["uid"]
        self.firstname = data["firstname"]
        self.lastname = data["lastname"]
        self.email = data["email"]
        self.pwd = data["pwd"]

    def get_id(self):
        return self.uid

    def is_admin(self):
        return self.uid == "ps"


test_data = {
    "uid": "ps",
    "firstname": "Patrick",
    "lastname": "Schaller",
    "email": "ps@imovies.ch",
    "pwd": "6e58f76f5be5ef06a56d4eeb2c4dc58be3dbe8c7",
}


def getUserByUid(uid):
    return test_data


def getUserByEmail(email):
    return test_data


def getUserById(id):
    return test_data


def updateUser(uid, firstName, lastName, email):
    pass


def createChallenge(serial_number, challenge):
    pass


def deleteChallengesBySerialNumber(serial_number):
    pass


def getChallengeBySerial(serial):
    challenge = (b"a" * 64).hex()
    return challenge


def getSerialNumbersByUid(uid):
    return ["1", "2"]

def getUidBySerial(serial):
    return "ps"

def addCertificate(serial, uid):
    pass

def removeCertificate(serial):
    pass
