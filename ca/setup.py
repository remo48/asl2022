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
    valid_from = get_time(0)
    valid_until = get_time(100)
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
    cert.set_notBefore(valid_from)
    cert.set_notAfter(valid_until)
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

    crl = crypto.CRL()
    crl.set_lastUpdate(valid_from)
    crl.set_nextUpdate(valid_until)
    crl.set_version(1)
    crl.sign(cert, key, b'sha256')
    save_crl(f"{name}/crl/{name}_crl", crl)

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
    dns = ["DNS:*.imovies.ch"]
    cert.add_extensions([
        crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth, clientAuth'),
        crypto.X509Extension(b'subjectAltName', False, ", ".join(dns).encode())
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