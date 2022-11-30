import os
import logging
import requests
from config import CORE_CA_URL, CA_CERT, SERVER_CERT, SERVER_KEY


def caPost(url, data=None):
    url = os.path.join(CORE_CA_URL, url)
    return requests.post(
        url, data=data, verify=CA_CERT, cert=(SERVER_CERT, SERVER_KEY)
    ).json()


def verifyChallenge(challenge, signature, serial):
    logging.info("CA: Verify challenge, Serial: %s", serial)
    res = caPost(
        "eca/verify_signature",
        data={"challenge": challenge, "signature": signature, "serial": serial},
    )
    return res["verified"]


def getCertificatesBySerialNumbers(serials):
    logging.info("CA: Get Certificates by Serial Numbers, Serials: %s", serials)
    res = caPost("get_certificates_by_serial_numbers", data={"numbers": serials or None})
    return res["certificates"]


def revokeCertificate(serial):
    logging.info("CA: Revoke Certificate, Serial: %s", serial)
    res = caPost("revoke_certificate", data={"serialNumber": serial})
    return res["status"]


def getNewCertificate(uid, firstname, lastname, email):
    logging.info("CA: Get New Certificate, UID: %s", uid)
    res = caPost(
        "create_certificate",
        data={"firstName": firstname, "lastName": lastname, "email": email, "uid": uid},
    )
    return res["status"]


def getAdminInfo():
    logging.info("CA: Get Admin Info")
    res = caPost("adminInfo")
    return res["status"]
