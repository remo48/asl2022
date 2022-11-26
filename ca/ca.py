import os
import datetime
from OpenSSL import crypto
from cryptography.hazmat.primitives.serialization import load_der_parameters
from cryptography.x509 import load_pem_x509_certificate
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
class CA:
    def __init__(self, dir: str, name: str) -> None:
        """
        Creates a ca interface with important functionalities

        :param dir: The directory of the ca. For the root CA it should be "/ca" and for intermediate cas it should be "/ca/inter_ca"

        :param name: The name of the CA. In our case one of the following: "root", "eca", "ica"
        """
        self.dir = dir
        self.name = name
        self.root = self

        self.keys = self.create_folder("keys")
        self.certs = self.create_folder("certs")
        self.crldir = self.create_folder("crl")
        self.index = self.create_folder("index.txt", folder=False)
        self.serial = self.create_folder("serial", folder=False)

    def create_folder(self, name, folder: bool = True) -> str:
        """
        Looks for a file or folder and if there is none creates a new one. This should only be the case when setting up the ca.
        """
        newDir = os.path.join(self.dir, name)
        if not os.path.exists(newDir):
            if folder:
                os.makedirs(newDir)
            else:
                f = open(newDir, "w")
                if name == "serial":
                    f.write(str(1))
        return newDir

    def write_index(self, serialnr):
        """
        Writes down the serialnr of the issued certificate and its state ('V': valid)
        """
        with open(self.index, 'a') as index:
            index.write(f"{serialnr} V")

    def revoke_index(self, serialnr):
        """
        Writes a 'R' (revoked) to the line with the matching serialnr
        """
        file = open(self.index, 'r')
        for line in file:
            line = line.strip()
            if(line == f"{serialnr} V"):
                line.replace(f"{serialnr} V", f"{serialnr} R")

    def update_crl(self, revoke:crypto.Revoked, lastUpdate, nextUpdate):
        """
        Updates the crl (certificate revocation list) with newly revoked certificates
        """
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
        location = os.path.join(self.crldir, self.name + "_crl.pem")
        self.write_crl(location, crl)
        self.crl = crl


    def get_key(self):
        """
        Fetches or creates a new keypair of the ca and returns it.
        """
        location = os.path.join(self.keys, self.name + "_key.pem")
        if os.path.exists(location):
            privatekey = self.load_key(location)
        else:
            privatekey = self.create_key()
            self.write_key(location, privatekey)
        return privatekey

    def get_cert(self):
        """
        Creates a new CA certificate if there is none or fetches one if it exists.
        """
        location = os.path.join(self.certs, self.name + "_cert.pem")
        if os.path.exists(location):
            certificate = self.load_cert(location)
        else:
            serialnr = self.get_serial_number()
            certificate = crypto.X509()
            subject = certificate.get_subject()
            subject.CN = self.name + " CA"
            subject.O = "iMovies"
            if self.root == self:
                certificate.set_issuer(subject)
            else:
                certificate.set_issuer(self.root.certificate.get_subject())
            certificate.set_version(2)
            certificate.set_subject(subject)
            certificate.gmtime_adj_notBefore(0)
            certificate.gmtime_adj_notAfter(31536000)
            certificate.set_serial_number(serialnr)
            certificate.set_pubkey(self.privatekey)
            certificate.sign(self.privatekey, 'sha256')
            self.write_cert(location, certificate)
        return certificate

    def get_crl(self):
        """
        Creates a crl (certificate revocation list) or returns an existing one
        """
        location = os.path.join(self.crldir, self.name + "_crl.pem")
        if os.path.exists(location):
            crl = self.load_crl(location)
        else:
            lastUpdate, nextUpdate = self.get_times()
            crl = crypto.CRL()
            crl.set_version(2)
            crl.set_lastUpdate(lastUpdate)
            crl.set_nextUpdate(nextUpdate)
            crl.sign(self.certificate, self.privatekey, b'sha256')
            self.write_crl(location, crl)
        return crl

    def get_serial_number(self, inc:int=1) -> int:
        """
        Returns the current serial number and increments the file by the param "inc"

        :param inc: The amount the serial number should be increased. If the value is not equal to one, then only a simple lookup happens.
        """
        location = os.path.join(self.dir, 'serial')
        with open(location, 'r+') as serial:
            serialnr = serial.read()
            if inc == 1:
                serial.seek(0)
                serial.write(str(int(serialnr) + inc))
                serial.truncate()
        return int(serialnr)

    def get_times(self):
        """
        Returns the current time and the time in one year.
        """
        lastUpdate = datetime.datetime.now()
        nextUpdate = lastUpdate + datetime.timedelta(days=365)
        lastUpdate = lastUpdate.strftime('%Y%m%d%H%M%S') + 'Z'
        nextUpdate = nextUpdate.strftime('%Y%m%d%H%M%S') + 'Z'
        return lastUpdate.encode(), nextUpdate.encode()

    def get_cert_by_serial_nr(self, serialnr):
        """
        Iterates through all certificates and returns the one matching the serial nr.
        """
        for file in os.listdir(self.certs):
            certificate = self.load_cert(os.path.join(self.certs, file))
            if certificate.get_serial_number() == int(serialnr):
                return crypto.dump_certificate(crypto.FILETYPE_PEM, certificate).hex()
        return None

    def create_key(self):
        """
        Creates a simple RSA2048 key pair.
        """
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        return key

    def load_key(self, location):
        with open(os.path.join(self.keys, location), "rt") as _private_key:
            return crypto.load_privatekey(crypto.FILETYPE_PEM, _private_key.read())

    def load_cert(self, location):
        with open(os.path.join(self.certs, location), "rt") as _certificate:
            return crypto.load_certificate(crypto.FILETYPE_PEM, _certificate.read())
    
    def load_crl(self, location):
        with open(os.path.join(self.crldir, location), "rt") as _crl:
            return crypto.load_crl(crypto.FILETYPE_PEM, _crl.read())

    def write_key(self, location, key):
         with open(location, "wb") as _key:
            _key.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

    def write_cert(self, location, certificate):
        with open(location, "wb") as _certificate:
            _certificate.write(crypto.dump_certificate(crypto.FILETYPE_PEM, certificate))
    
    def write_crl(self, location, crl):
        with open(location, "wb") as _crl:
            _crl.write(crypto.dump_crl(crypto.FILETYPE_PEM, crl))


class RootCA(CA):
    """
    An implementation of the root CA. It is on purpose that this class has little functionality as it shouldn't be in contact with clients, only ca's.
    """
    def __init__(self) -> None:
        super().__init__(os.getcwd(), "root")
        self.privatekey = self.get_key()
        self.certificate = self.get_cert()
        self.crl = self.get_crl()


class InterCA(CA):
    """
    An implementation of the external CA used for certificates for users.
    """
    def __init__(self, root: RootCA, name: str) -> None:
        super().__init__(os.path.join(os.getcwd(), name), name)
        self.root = root
        self.privatekey = self.get_key()
        self.certificate = self.get_cert()
        self.crl = self.get_crl()

    def verifySignature(self, challenge, signature, serialnr) -> bool:
        """
        Verifies that a given signature matches a challenge signed by the certificate holder given the serial number.
        """
        try:
            certificate = self.get_cert_by_serial_nr(serialnr)
            signature = base64.b64decode(signature)
            challenge = challenge.encode()
            certificate = load_pem_x509_certificate(bytes.fromhex(certificate))
            publickey = certificate.public_key()
            publickey.verify(signature, challenge, padding.PKCS1v15(), SHA256())
            return True
        except Exception:
            return False

    def is_revoked(self, serial_nr: int) -> bool:
        """
        Checks wheter a certificate with a given serial number has already been revoked
        """
        revoked_certs = self.crl.get_revoked()
        for rvk in revoked_certs:
            if rvk.get_serial() == str(serial_nr).encode():
                return True
        return False

    def getCertificatesBySerialNumbers(self, numbers) -> list:
        """
        Returns a list of certificates given a list of serial numbers. Certificates that are not found are represented by a "None" object.
        """
        certificates = []
        for number in numbers:
            if not self.is_revoked(number):
                certificates.append(self.get_cert_by_serial_nr(number))
        return certificates

    def create_certificate(self, firstName, lastName, email, uid):
        """
        Creates a certificate
        """
        key = self.create_key()
        lastUpdate, nextUpdate = self.get_times()
        serialnr = self.get_serial_number()
        issuer = self.certificate.get_subject()

        request = crypto.X509Req()
        request.get_subject().CN = f"{firstName} {lastName}, {email}, {uid}"
        request.get_subject().O = "iMovies"
        request.set_pubkey(key)
        request.sign(key, 'sha256')
        
        certificate = crypto.X509()
        certificate.set_version(2)
        certificate.set_notBefore(lastUpdate)
        certificate.set_notAfter(nextUpdate)
        certificate.set_serial_number(serialnr)
        certificate.set_issuer(issuer)
        certificate.set_subject(request.get_subject())
        certificate.set_pubkey(key)
        certificate.sign(self.privatekey, 'sha256')
        pkc = crypto.PKCS12()
        pkc.set_ca_certificates([self.root.certificate, self.certificate])
        pkc.set_certificate(certificate)
        pkc.set_privatekey(key)

        self.write_cert(os.path.join(self.certs, f"{serialnr}") + "_cert.pem", certificate)
        self.write_key(os.path.join(self.keys, str(serialnr)) + "_key.pem", key)
        return pkc.export(), serialnr

    def revoke_certificate(self, serialnr) -> bool:
        """
        Revokes the certificate with the given serial number. Returns a bool indicating wheter the revocation has been successful or not
        """
        for file in os.listdir(self.certs):
            certificate = self.load_cert(file)
            if certificate.get_serial_number() == int(serialnr):
                lastUpdate, nextUpdate = self.get_times()
                revoke = crypto.Revoked()
                revoke.set_serial(str(serialnr).encode())
                revoke.set_rev_date(lastUpdate)
                self.update_crl(revoke, lastUpdate, nextUpdate)                
                self.revoke_index(serialnr)
                return True
        return False

    def adminInfo(self):
        """
        Returns basic admin info as specified in the project description
        """
        return {
            'certificates': len([name for name in os.listdir(self.certs)]) if self.certs else 0,
            'revocations': len(self.crl.get_revoked()) if self.crl.get_revoked() else 0,
            "serial_nr": self.get_serial_number(0)
        }