import os
import datetime
from OpenSSL import crypto
from ca import get_serial_number, write_index, CA

def get_time(day = 0):
    time = datetime.datetime.now() + datetime.timedelta(days=day) - datetime.timedelta(days=1)
    res = time.strftime('%Y%m%d%H%M%S') + 'Z'
    return res.encode('utf-8')

def create_folderstructure():
    os.makedirs("certs")
    os.makedirs("keys")
    os.makedirs("crl")
    os.makedirs("ica")
    os.makedirs("ica/certs")
    os.makedirs("ica/keys")
    os.makedirs("ica/crl")
    os.makedirs("eca")
    os.makedirs("eca/certs")
    os.makedirs("eca/keys")
    os.makedirs("eca/crl")
    f = open("eca/serial", "w")
    f.write(str(0))
    f = open("eca/index.txt", "w")
    f.write("serialnr, status, time \n")

def save_key(location, key):
    with open(location + ".pem", "wt") as _key:
        _key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'))

def save_cert(location, certificates):
    cert = ""
    for certificate in certificates:
        cert += crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).decode('utf-8')
    with open(location + ".pem", "wt") as _certificate:
        _certificate.write(cert)

def save_crl(location, crl):
    with open(location + ".pem", "wt") as _crl:
        _crl.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode('utf-8'))

def load_key(location):
    with open(location, "rt") as _private_key:
        return crypto.load_privatekey(crypto.FILETYPE_PEM, _private_key.read())

def load_cert(location):
    with open(location, "rt") as _certificate:
        return crypto.load_certificate(crypto.FILETYPE_PEM, _certificate.read())

def load_crl(location):
    with open(location, "rt") as _crl:
        return crypto.load_crl(crypto.FILETYPE_PEM, _crl.read())

def createRootCA():
    valid_from = get_time(0)
    valid_until = get_time(100)
    serialnr = get_serial_number()

    root_key = crypto.PKey()
    root_key.generate_key(crypto.TYPE_RSA, 2048)
    save_key("keys/root_key", root_key)

    root_cert = crypto.X509()
    root_cert.set_version(2)
    root_cert.get_subject().CN = "root CA"
    root_cert.get_subject().O = "iMovies"
    root_cert.set_serial_number(serialnr)
    root_cert.set_notBefore(valid_from)
    root_cert.set_notAfter(valid_until)
    root_cert.set_issuer(root_cert.get_subject())
    root_cert.set_pubkey(root_key)
    root_cert.add_extensions([
    crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:1"),
    crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
    crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=root_cert),
    ])
    root_cert.sign(root_key, 'sha256')
    save_cert("certs/root_cert", [root_cert])
    write_index(serialnr)

    crl = crypto.CRL()
    crl.set_lastUpdate(valid_from)
    crl.set_nextUpdate(valid_until)
    crl.set_version(1)
    crl.sign(root_cert, root_key, b'sha256')
    save_crl("crl/root_crl", crl)

def createIntermediateCA(name: str):
    serialnr = get_serial_number()

    root_cert = load_cert("certs/root_cert.pem")
    root_key = load_key("keys/root_key.pem")

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    save_key(f"{name}/keys/{name}_key", key)

    req = crypto.X509Req()
    req.get_subject().CN = name
    req.get_subject().O = "iMovies"
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_subject(req.get_subject())
    cert.set_serial_number(serialnr)
    cert.set_notBefore(get_time(0))
    cert.set_notAfter(get_time(100))
    cert.set_issuer(root_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.add_extensions([
    crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
    crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
    crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=cert),
    ])
    cert.sign(root_key, 'sha256')
    save_cert(f"{name}/certs/{name}_cert", [cert])
    write_index(serialnr)

def createICACert(name: str):
    serialnr = get_serial_number()

    ica_cert = load_cert("ica/certs/ica_cert.pem")
    ica_key = load_key("ica/keys/ica_key.pem")

    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    save_key(f"ica/keys/{name}_key", key)

    req = crypto.X509Req()
    req.get_subject().CN = name
    req.get_subject().O = "iMovies"
    req.set_pubkey(key)
    req.sign(key, 'sha256')

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_subject(req.get_subject())
    cert.set_serial_number(serialnr)
    cert.set_notBefore(get_time(0))
    cert.set_notAfter(get_time(100))
    cert.set_issuer(ica_cert.get_subject())
    cert.set_subject(req.get_subject())
    cert.set_pubkey(req.get_pubkey())
    cert.add_extensions([
        crypto.X509Extension(
            b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
    ])
    cert.sign(ica_key, 'sha256')
    save_cert(f"ica/certs/{name}_cert", [cert, ica_cert])
    write_index(serialnr)

if __name__ == "__main__":
    create_folderstructure()
    createRootCA()
    createIntermediateCA("ica")
    createIntermediateCA("eca")
    createICACert("web")
    createICACert("db")
    createICACert("ca")

    ca = CA()
    ca.create_certificate()

    #     def verifySignature(self, challenge, signature, serialnr) -> bool:
#         """
#         Verifies that a given signature matches a challenge signed by the certificate holder given the serial number.
#         """
#         logging.info(f"({self.name}) Attempt to verify signature for certificate with serial number {serialnr}")
#         try:
#             certificate = self.get_cert_by_serial_nr(serialnr)
#             signature = base64.b64decode(signature)
#             challenge = challenge.encode()
#             certificate = load_pem_x509_certificate(bytes.fromhex(certificate))
#             publickey = certificate.public_key()
#             publickey.verify(signature, challenge, padding.PKCS1v15(), SHA256())
#             logging.info(f"({self.name}) Verify signature: SUCCESS ")
#             return True
#         except Exception:
#             logging.info(f"({self.name}) Verify signature: FAILURE ")
#             return False

#     def is_revoked(self, serial_nr: int) -> bool:
#         """
#         Checks wheter a certificate with a given serial number has already been revoked
#         """
#         revoked_certs = self.crl.get_revoked()
#         logging.info(f"({self.name}) Check if revoked: {serial_nr}")
#         for rvk in revoked_certs:
#             if rvk.get_serial() == str(serial_nr).encode():
#                 logging.info(f"{self.name}: Certificate is revoked")
#                 return True
#         logging.info(f"({self.name}) Certificate is not revoked")
#         return False

#     def getCertificatesBySerialNumbers(self, numbers) -> list:
#         """
#         Returns a list of certificates given a list of serial numbers. Certificates that are not found are represented by a "None" object.
#         """
#         logging.info(f"({self.name}) Request Certificates: {numbers}")
#         certificates = []
#         for number in numbers:
#             if not self.is_revoked(number):
#                 certificates.append(self.get_cert_by_serial_nr(number))
#         return certificates

#     def create_certificate(self, firstName, lastName, email, uid):
#         """
#         Creates a certificate
#         """
#         key = self.create_key()
#         lastUpdate, nextUpdate = self.get_times()
#         serialnr = self.get_serial_number()
#         issuer = self.root.certificate.get_subject()

#         request = crypto.X509Req()
#         request.get_subject().CN = firstName
#         request.get_subject().O = "iMovies"
#         request.set_pubkey(key)
#         request.sign(key, 'sha256')
        
#         certificate = crypto.X509()
#         certificate.set_version(3)
#         certificate.set_notBefore(lastUpdate)
#         certificate.set_notAfter(nextUpdate)
#         certificate.set_serial_number(serialnr)
#         certificate.set_issuer(issuer)
#         certificate.set_subject(request.get_subject())
#         certificate.set_pubkey(key)
#         certificate.sign(self.root.privatekey, 'sha256')

#         pkc = crypto.PKCS12()
#         pkc.set_ca_certificates([self.root.certificate])
#         pkc.set_certificate(certificate)
#         pkc.set_privatekey(key)

#         if self.name == "ica":
#             self.write_cert(os.path.join(self.certs, f"{firstName}") + "_cert.pem", certificate)
#             self.write_key(os.path.join(self.keys, f"{firstName}") + "_key.pem", key)
#         else:
#             self.write_cert(os.path.join(self.certs, f"{serialnr}") + "_cert.pem", certificate)
#             self.write_key(os.path.join(self.keys, f"{serialnr}") + "_key.pem", key)
#         self.write_index(serialnr)

#         logging.info(f"({self.name}) Create Certificate {serialnr}: SUCCESS ")

#         return pkc.export(), serialnr

#         # key = self.create_key()
#         # lastUpdate, nextUpdate = self.get_times()
#         # serialnr = self.get_serial_number()
#         # issuer = self.root.certificate.get_subject()

#         # request = crypto.X509Req()
#         # request.get_subject().CN = self.name
#         # request.get_subject().O = "iMovies"
#         # request.set_pubkey(key)
#         # request.sign(key, 'sha256')
        
#         # certificate = crypto.X509()
#         # certificate.set_version(3)
#         # certificate.set_notBefore(lastUpdate)
#         # certificate.set_notAfter(nextUpdate)
#         # certificate.set_serial_number(serialnr)
#         # certificate.set_issuer(issuer)
#         # certificate.set_subject(request.get_subject())
#         # certificate.set_pubkey(key)
#         # certificate.sign(self.privatekey, 'sha256')

#         # pkc = crypto.PKCS12()
#         # pkc.set_ca_certificates([self.root.certificate, self.certificate])
#         # pkc.set_certificate(certificate)
#         # pkc.set_privatekey(key)

#         # if self.name == "ica":
#         #     self.write_cert(os.path.join(self.certs, f"{firstName}") + "_cert.pem", certificate)
#         #     self.write_key(os.path.join(self.keys, firstName) + "_key.pem", key)
#         # else:
#         #     self.write_cert(os.path.join(self.certs, f"{serialnr}") + "_cert.pem", certificate)
#         #     self.write_key(os.path.join(self.keys, str(serialnr)) + "_key.pem", key)
#         # self.write_index(serialnr)

#         # logging.info(f"({self.name}) Create Certificate {serialnr}: SUCCESS ")

#         # return pkc.export(), serialnr

#     def revoke_certificate(self, serialnr) -> bool:
#         """
#         Revokes the certificate with the given serial number. Returns a bool indicating wheter the revocation has been successful or not
#         """
#         logging.info(f"({self.name}) Attempt to revoke certificate with the following number: {serialnr}")
#         for file in os.listdir(self.certs):
#             certificate = self.load_cert(file)
#             if certificate.get_serial_number() == int(serialnr):
#                 lastUpdate, nextUpdate = self.get_times()
#                 revoke = crypto.Revoked()
#                 revoke.set_serial(str(serialnr).encode())
#                 revoke.set_rev_date(lastUpdate)
#                 self.update_crl(revoke, lastUpdate, nextUpdate)                
#                 self.revoke_index(serialnr)
#                 logging.info(f"({self.name}) Revoke certificate: SUCCESS")
#                 return True
#         logging.info(f"({self.name}) Revoke certificate: SUCCESS")
#         return False

#     def adminInfo(self):
#         """
#         Returns basic admin info as specified in the project description
#         """
#         logging.info(f"({self.name}) Admin Info: REQUESTED")
#         return {
#             'certificates': len([name for name in os.listdir(self.certs)]) if self.certs else 0,
#             'revocations': len(self.crl.get_revoked()) if self.crl.get_revoked() else 0,
#             "serial_nr": self.get_serial_number(0)
#         }