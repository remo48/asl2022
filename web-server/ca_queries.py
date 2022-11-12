def verifyChallenge(challenge, signature, serial):
    return "ps@imovies.ch"


def getCertificatesBySerialNumbers(serials):
    return [
        {"serial": "1", "certificate": "-----BEGIN CERTIFICATE-----\r"},
        {"serial": "2", "certificate": "-----BEGIN CERTIFICATE-----\r"},
    ]


def revokeCertificate(serial):
    print("Revoked certificate with serial number: " + serial)
    pass


def getNewCertificate(uid, firstname, lastname, email):
    return {"serial": "1", "data": "-----BEGIN CERTIFICATE-----\r"}

def getAdminInfo():
    return {
      "num_certs": 2,
      "num_revoked": 0,
      "current_serial": 3,
    }
