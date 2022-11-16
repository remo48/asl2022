import logging

def verifyChallenge(challenge, signature, serial):
    print(challenge, signature, serial)
    logging.info("CA: Verify challenge, Serial: %s", serial)
    return "ps@imovies.ch"


def getCertificatesBySerialNumbers(serials):
    logging.info("CA: Get Certificates by Serial Numbers, Serials: %s", serials)
    return [
        {"serial": "1", "certificate": "-----BEGIN CERTIFICATE-----\r"},
        {"serial": "2", "certificate": "-----BEGIN CERTIFICATE-----\r"},
    ]


def revokeCertificate(serial):
    logging.info("CA: Revoke Certificate, Serial: %s", serial)
    print("Revoked certificate with serial number: " + serial)
    pass


def getNewCertificate(uid, firstname, lastname, email):
    logging.info("CA: Get New Certificate, UID: %s", uid)
    return {"serial": "01", "data": "-----BEGIN CERTIFICATE-----\r"}

def getAdminInfo():
    logging.info("CA: Get Admin Info")
    return {
      "num_certs": 2,
      "num_revoked": 0,
      "current_serial": 3,
    }
