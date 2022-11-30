import os
import datetime
from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import load_der_parameters
from cryptography.x509 import load_pem_x509_certificate
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256

import logging
from logging.config import dictConfig
from cryptography.hazmat.primitives.serialization import NoEncryption, Encoding


LOG_CONFIG = {
    "version": 1,
    "formatters": {
        "default": {
            "format": "[%(asctime)s] %(levelname)s in %(module)s: %(message)s",
        }
    },
    "handlers": {
        "wsgi": {
            "class": "logging.handlers.RotatingFileHandler",
            "formatter": "default",
            "filename": "ca-server.log",
            "maxBytes": 1024,
        }
    },
    "root": {"level": "INFO", "handlers": ["wsgi"]},
}
dictConfig(LOG_CONFIG)

def get_time(day = 0):
    time = datetime.datetime.now() + datetime.timedelta(days=day-1)
    return (time.strftime('%Y%m%d%H%M%S')+'Z').encode()

def get_serial_number(inc:int=1) -> int:
    with open("eca/serial", 'r+') as serial:
        serialnr = serial.read()
        if inc == 1:
            serial.seek(0)
            serial.write(str(int(serialnr) + inc))
            serial.truncate()
    logging.info(f"Update serial number to {serialnr}")
    return int(serialnr)

def write_index(serialnr):
    with open("eca/index.txt", 'a') as index:
        index.write(f"{serialnr}, V, {datetime.datetime.now()}\n")

def create_key(name) -> crypto.PKey():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    with open(f"keys/{name}_key.pem", "wt") as _key:
        _key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode())
    return key

def create_request(name, key) -> crypto.X509Req():
    req = crypto.X509Req()
    req.get_subject().CN = name
    req.get_subject().O = "iMovies"
    req.set_pubkey(key)
    req.sign(key, 'sha256')
    return req

class CA:
    def __init__(self) -> None:
        with open("certs/root_cert.pem", "rt") as root_certificate:
            self.root_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, root_certificate.read())

        with open("certs/eca_cert.pem", "rt") as certificate:
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate.read())
        with open("keys/eca_key.pem", "rt") as key:
            self.key = crypto.load_privatekey(crypto.FILETYPE_PEM, key.read())
        with open("crl/eca_crl.pem", "rt") as root_crl:
            self.crl = crypto.load_crl(crypto.FILETYPE_PEM, root_crl.read())

    def save_key(self, serialnr, key):
        with open(f"eca/keys/{serialnr}_key.pem", "wt") as _key:
            _key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode())
            logging.info(f"Saved key with serialnr: {serialnr}")
    
    def save_cert(self, serialnr, certificates):
        cert = ""
        for certificate in certificates:
            cert += crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode()
        with open(f"eca/certs/{serialnr}_cert.pem", "wt") as _certificate:
            _certificate.write(cert)
            logging.info(f"Saved certificate with serialnr: {serialnr}")

    def load_cert(self, serialnr):
        logging.info(f"Loading Certificate with serialnr: {serialnr}")
        try:
            with open(f"eca/certs/{serialnr}_cert.pem", "rt") as cert:
                return crypto.load_certificate(crypto.FILETYPE_PEM, cert.read())
        except:
            return None

    def create_certificate(self, firstName, lastName, email, uid):
        serialnr = get_serial_number()

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        self.save_key(serialnr, key)

        req = crypto.X509Req()
        req.get_subject().CN = str(serialnr)
        req.get_subject().O = "iMovies"
        req.get_subject().emailAddress  = email
        req.set_pubkey(key)
        req.sign(key, 'sha256')

        cert = crypto.X509()
        cert.set_version(2)
        cert.set_subject(req.get_subject())
        cert.set_serial_number(serialnr)
        cert.set_notBefore(get_time(0))
        cert.set_notAfter(get_time(365))
        cert.set_issuer(self.certificate.get_subject())
        cert.set_subject(req.get_subject())
        cert.set_pubkey(req.get_pubkey())
        cert.add_extensions([
            crypto.X509Extension(
                b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
        ])
        cert.sign(self.key, 'sha256')
        logging.info(f"Created new certificate with serialnr: {serialnr}")
        self.save_cert(serialnr ,[cert, self.certificate])
        write_index(serialnr)

        pkc = crypto.PKCS12()
        pkc.set_ca_certificates([self.root_certificate, self.certificate])
        pkc.set_certificate(cert)
        pkc.set_privatekey(key)
        return pkc.export(), serialnr

    def update_crl(self, revoke:crypto.Revoked, lastUpdate, nextUpdate):
        crl = crypto.CRL()
        crl.set_version(2)
        crl.set_lastUpdate(lastUpdate)
        crl.set_nextUpdate(nextUpdate)
        curr_revkd = self.crl.get_revoked()
        if curr_revkd:
            for rvkd in curr_revkd:
                crl.add_revoked(rvkd)
        crl.add_revoked(revoke)
        crl.sign(self.certificate, self.key, b'sha256')
        with open("crl/eca_crl.pem", "wt") as _crl:
            _crl.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode())
        self.crl = crl

    def verifySignature(self, challenge, signature, serialnr) -> bool:
        try:
            certificate = self.load_cert(serialnr)
            signature = base64.b64decode(signature)
            crypto.verify(certificate, signature, challenge.encode(), "SHA256")
            logging.info(f"Verify signature: SUCCESS {serialnr}")
            return True
        except Exception as e:
            logging.info(f"Verify signature: FAILURE {serialnr}, {e}")
            return False

    def revoke_index(self, serialnr) -> bool:
        with open("eca/index.txt", 'r') as file:
            data = file.readlines()
            for i, line in enumerate(data):
                if f"{serialnr}, V" in line:
                    data[i] = f"{serialnr}, R, {datetime.datetime.now()}\n"
                    with open("eca/index.txt", 'w') as file:
                        file.writelines(data)
                        return True
        return False

    def is_revoked(self, serialnr) -> bool:
        revoked_certs = self.crl.get_revoked()
        if not revoked_certs:
            return False
        for rvk in revoked_certs:
            if rvk.get_serial() == str(serialnr).encode():
                logging.info(f"Check Certificate {serialnr} revoked: TRUE")
                return True
        logging.info(f"Check Certificate {serialnr} revoked: FALSE")
        return False

    def getCertificatesBySerialNumbers(self, numbers) -> list:
        certificates = []
        if not numbers:
            return certificates
        for number in numbers:
            if not self.is_revoked(number):
                certificates.append(self.load_cert(number).to_cryptography().public_bytes(Encoding.PEM).hex())
            else:
                certificates.append(None)
        return certificates

    def revoke_certificate(self, serialnr) -> bool:
        if os.path.exists(f"eca/certs/{serialnr}_cert.pem"):
            lastUpdate = get_time(0)
            nextUpdate = get_time(365)
            revoke = crypto.Revoked()
            revoke.set_serial(str(serialnr).encode())
            revoke.set_rev_date(lastUpdate)
            self.update_crl(revoke, lastUpdate, nextUpdate)
            if(self.revoke_index(serialnr)):
                logging.info(f"Revoke certificate {serialnr}: SUCCESS")
                return True
        logging.info(f"Revoke certificate {serialnr}: FAILURE")
        return False

    def adminInfo(self):
        admin_info = {
            'certificates': len([name for name in os.listdir("eca/certs")]) -1,
            'revocations': len(self.crl.get_revoked()) if self.crl.get_revoked() else 0,
            'serial_nr': get_serial_number(0)
        }
        logging.info(f"Admin Info: REQUESTED ({admin_info['certificates']}, {admin_info['revocations']}, {admin_info['serial_nr']}")
        return admin_info