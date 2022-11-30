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
    time = datetime.datetime.now() + datetime.timedelta(days=day) - datetime.timedelta(days=1)
    res = time.strftime('%Y%m%d%H%M%S') + 'Z'
    return res.encode('utf-8')

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

class CA:
    def __init__(self) -> None:
        with open("certs/root_cert.pem", "rt") as root_certificate:
            self.root_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, root_certificate.read())
        with open("keys/root_key.pem", "rt") as root_key:
            self.root_key = crypto.load_privatekey(crypto.FILETYPE_PEM, root_key.read())
        with open("crl/root_crl.pem", "rt") as root_crl:
            self.root_crl = crypto.load_crl(crypto.FILETYPE_PEM, root_crl.read())

        with open("eca/certs/eca_cert.pem", "rt") as certificate:
            self.certificate = crypto.load_certificate(crypto.FILETYPE_PEM, certificate.read())
        with open("eca/keys/eca_key.pem", "rt") as key:
            self.key = crypto.load_privatekey(crypto.FILETYPE_PEM, key.read())
        with open("eca/crl/eca_crl.pem", "rt") as root_crl:
            self.crl = crypto.load_crl(crypto.FILETYPE_PEM, root_crl.read())

    def save_key(self, serialnr, key):
        with open(f"eca/keys/{serialnr}_key.pem", "wt") as _key:
            _key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'))
            logging.info(f"Saved key with serialnr: {serialnr}")
    
    def save_cert(self, serialnr, certificates):
        cert = ""
        for certificate in certificates:
            cert += crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode('utf-8')
        with open(f"eca/certs/{serialnr}_cert.pem", "wt") as _certificate:
            _certificate.write(cert)
            logging.info(f"Saved certificate with serialnr: {serialnr}")

    def load_cert(self, serialnr):
        with open(f"eca/certs/{serialnr}_cert.pem", "rt") as cert:
            return crypto.load_certificate(crypto.FILETYPE_PEM, cert.read())

    def create_certificate(self):
        serialnr = get_serial_number()

        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        self.save_key(serialnr, key)

        req = crypto.X509Req()
        req.get_subject().CN = str(serialnr)
        req.get_subject().O = "iMovies"
        req.set_pubkey(key)
        req.sign(key, 'sha256')

        cert = crypto.X509()
        cert.set_version(2)
        cert.set_subject(req.get_subject())
        cert.set_serial_number(serialnr)
        cert.set_notBefore(get_time(0))
        cert.set_notAfter(get_time(100))
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
        crl.sign(self.certificate, self.privatekey, b'sha256')
        with open("eca/crl/eca_crl.pem", "wt") as _crl:
            _crl.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))
        self.crl = crl

    def verifySignature(self, challenge, signature, serialnr) -> bool:
        try:
            certificate = self.load_cert(serialnr)
            signature = base64.b64decode(signature)
            challenge = challenge.encode()
            certificate = load_pem_x509_certificate(bytes.fromhex(certificate))
            publickey = certificate.public_key()
            publickey.verify(signature, challenge, padding.PKCS1v15(), SHA256())
            logging.info(f"Verify signature: SUCCESS {serialnr}")
            return True
        except:
            logging.info(f"Verify signature: FAILURE {serialnr}")
            return False

    def revoke_index(self, serialnr):
        with open("eca/index.txt", 'r') as file:
            data = file.readlines()
            for i, line in enumerate(data):
                print(line)
                if f"{serialnr}, Valid" in line:
                    data[i] = f"{serialnr}, R, {datetime.datetime.now()}\n"
                    with open("eca/index.txt", 'w') as file:
                        file.writelines(data)
                        return

    def is_revoked(self, serialnr) -> bool:
        revoked_certs = self.crl.get_revoked()
        for rvk in revoked_certs:
            if rvk.get_serial() == str(serialnr).encode():
                logging.info(f"Check Certificate {serialnr} revoked: TRUE")
                return True
        logging.info(f"Check Certificate {serialnr} revoked: FALSE")
        return False

    def getCertificatesBySerialNumbers(self, numbers) -> list:
        certificates = []
        for number in numbers:
            if not self.is_revoked(number):
                certificates.append()

    def revoke_certificate(self, serialnr) -> bool:
        for file in os.listdir("eca/certs"):
            with open(file, "rt") as cert: 
                if cert.get_serial_number() == int(serialnr):
                    lastUpdate = get_time(0)
                    nextUpdate = get_time(365)
                    revoke = crypto.Revoked()
                    revoke.set_serial(str(serialnr).encode())
                    revoke.set_rev_date(lastUpdate)
                    self.update_crl(revoke, lastUpdate, nextUpdate)
                    self.revoke_index(serialnr)
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

#     def __init__(self, dir: str, name: str) -> None:
#         """
#         Creates a ca interface with important functionalities

#         :param dir: The directory of the ca. For the root CA it should be "/ca" and for intermediate ca's it should be "/ca/inter_ca"

#         :param name: The name of the CA. In our case one of the following: "root", "eca", "ica"
#         """
#         self.dir = dir
#         self.name = name
#         self.root = self

#         self.keys = self.create_folder("keys")
#         self.certs = self.create_folder("certs")
#         self.crldir = self.create_folder("crl")
#         self.index = self.create_folder("index.txt", folder=False)
#         self.serial = self.create_folder("serial", folder=False)


#     def write_index(self, serialnr):
#         """
#         Writes down the serialnr of the issued certificate and its state ('V': valid)
#         """
#         with open(self.index, 'a') as index:
#             index.write(f"{serialnr}, Valid, {datetime.datetime.now()}\n")

#     def revoke_index(self, serialnr):
#         """
#         Writes a 'R' (revoked) to the line with the matching serialnr
#         """
#         with open(self.index, 'r') as file:
#             data = file.readlines()
#             for i, line in enumerate(data):
#                 print(line)
#                 if f"{serialnr}, Valid" in line:
#                     data[i] = f"{serialnr}, Revoked, {datetime.datetime.now()}\n"
#                     with open(self.index, 'w') as file:
#                         file.writelines(data)
#                         return
#         raise Exception("Could not revoke index!")

#     def update_crl(self, revoke:crypto.Revoked, lastUpdate, nextUpdate):
#         """
#         Updates the crl (certificate revocation list) with newly revoked certificates
#         """
#         crl = crypto.CRL()
#         crl.set_version(2)
#         crl.set_lastUpdate(lastUpdate)
#         crl.set_nextUpdate(nextUpdate)
#         curr_revkd = self.crl.get_revoked()
#         if curr_revkd:
#             for rvkd in curr_revkd:
#                 crl.add_revoked(rvkd)
#         crl.add_revoked(revoke)
#         crl.sign(self.certificate, self.privatekey, b'sha256')
#         location = os.path.join(self.crldir, self.name + "_crl.pem")
#         self.write_crl(location, crl)
#         self.crl = crl


#     def get_key(self):
#         """
#         Fetches or creates a new keypair of the ca and returns it.
#         """
#         location = os.path.join(self.keys, "ca_key.pem")
#         if os.path.exists(location):
#             privatekey = self.load_key(location)
#         else:
#             privatekey = self.create_key()
#             self.write_key(location, privatekey)
#         return privatekey

#     def get_cert(self):
#         """
#         Creates a new CA certificate if there is none or fetches one if it exists.
#         """
#         location = os.path.join(self.certs, self.name + "_cert.pem")
#         if os.path.exists(location):
#             certificate = self.load_cert(location)
#         else:
#             serialnr = self.get_serial_number()
#             certificate = crypto.X509()
#             subject = certificate.get_subject()
#             subject.CN = self.name + " CA"
#             subject.O = "iMovies"
#             if self.root == self:
#                 certificate.set_issuer(subject)
#             else:
#                 certificate.set_issuer(self.root.certificate.get_subject())

#             certificate.add_extensions([crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE')])

#             certificate.set_version(2)
#             certificate.set_subject(subject)
#             certificate.gmtime_adj_notBefore(0)
#             certificate.gmtime_adj_notAfter(31536000)
#             certificate.set_serial_number(serialnr)
#             certificate.set_pubkey(self.privatekey)
#             certificate.sign(self.root.privatekey, 'sha256')
#             self.write_cert(location, certificate)
#             self.write_index(serialnr)
#         return certificate

#     def get_crl(self):
#         """
#         Creates a crl (certificate revocation list) or returns an existing one
#         """
#         location = os.path.join(self.crldir, "ca_crl.pem")
#         if os.path.exists(location):
#             crl = self.load_crl(location)
#         else:
#             lastUpdate, nextUpdate = self.get_times()
#             crl = crypto.CRL()
#             crl.set_version(2)
#             crl.set_lastUpdate(lastUpdate)
#             crl.set_nextUpdate(nextUpdate)
#             crl.sign(self.certificate, self.privatekey, b'sha256')
#             self.write_crl(location, crl)
#         return crl

#     def get_serial_number(self, inc:int=1) -> int:
#         """
#         Returns the current serial number and increments the file by the param "inc"

#         :param inc: The amount the serial number should be increased. If the value is not equal to one, then only a simple lookup happens.
#         """
#         location = os.path.join(self.dir, 'serial')
#         with open(location, 'r+') as serial:
#             serialnr = serial.read()
#             if inc == 1:
#                 serial.seek(0)
#                 serial.write(str(int(serialnr) + inc))
#                 serial.truncate()
#         logging.info(f"({self.name}) Update serial number to {serialnr}")
#         return int(serialnr)

#     def get_times(self):
#         """
#         Returns the current time and the time in one year.
#         """
#         lastUpdate = datetime.datetime.now()
#         nextUpdate = lastUpdate + datetime.timedelta(days=365)
#         lastUpdate = lastUpdate.strftime('%Y%m%d%H%M%S') + 'Z'
#         nextUpdate = nextUpdate.strftime('%Y%m%d%H%M%S') + 'Z'
#         return lastUpdate.encode(), nextUpdate.encode()

#     def get_cert_by_serial_nr(self, serialnr):
#         """
#         Iterates through all certificates and returns the one matching the serial nr.
#         """
#         for file in os.listdir(self.certs):
#             certificate = self.load_cert(os.path.join(self.certs, file))
#             if certificate.get_serial_number() == int(serialnr):
#                 return crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).hex()
#         return None

#     def create_key(self):
#         """
#         Creates a simple RSA2048 key pair.
#         """
#         key = crypto.PKey()
#         key.generate_key(crypto.TYPE_RSA, 2048)
#         return key

#     def load_key(self, location):
#         with open(os.path.join(self.keys, location), "rt") as _private_key:
#             return crypto.load_privatekey(crypto.FILETYPE_PEM, _private_key.read())

#     def load_cert(self, location):
#         with open(os.path.join(self.certs, location), "rt") as _certificate:
#             return crypto.load_certificate(crypto.FILETYPE_PEM, _certificate.read())
    
#     def load_crl(self, location):
#         with open(os.path.join(self.crldir, location), "rt") as _crl:
#             return crypto.load_crl(crypto.FILETYPE_PEM, _crl.read())

#     def write_key(self, location, key):
#          with open(location, "wb") as _key:
#             _key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

#     def write_cert(self, location, certificate):
#         with open(location, "wb") as _certificate:
#             _certificate.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
    
#     def write_crl(self, location, crl):
#         with open(location, "wb") as _crl:
#             _crl.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))


# class RootCA(CA):
#     """
#     An implementation of the root CA. It is on purpose that this class has little functionality as it shouldn't be in contact with clients, only ca's.
#     """
#     def __init__(self) -> None:
#         super().__init__(os.getcwd(), "root")
#         self.privatekey = self.get_key()
#         self.certificate = self.get_cert()
#         self.crl = self.get_crl()

# class InterCA(CA):
#     """
#     An implementation of the external CA used for certificates for users.
#     """
#     def __init__(self, root: RootCA, name: str) -> None:
#         super().__init__(os.path.join(os.getcwd(), name), name)
#         self.root = root
#         self.privatekey = self.get_key()
#         self.certificate = self.get_cert()
#         self.crl = self.get_crl()
