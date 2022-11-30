import os
import datetime
from OpenSSL import crypto

DIR = os.path.join(os.curdir, 'certs')
VERSION = 2
ROOT_PK = 'root_pk.pem'
ROOT_CERT = 'root_cert.pem'
ROOT_CERT2 = 'root_cert.txt'
ROOT_CRL = 'root_crl.pem'
CRL_FILE = 'crl.txt'
SRNR_FILE = 'srlnr.txt'
CERT_FILE = 'imovies_cert.pem'
CERT_FILE2 = 'imovies_cert.txt'
PK_FILE = 'imovies_pk.pem' 
NET_DIR = 'keys_and_certificates'
NET_CERT_FILE = 'network_ca_cert.pem'
NET_PK_FILE = 'network_ca_pk.pem'
CERTHOST_CERT = 'certhost_cert.pem'
CERTHOST_PK = 'certhost_pk.pem'
WEBSERV_CERT = 'webserver_cert.pem'
WEBSERV_PK = 'webserver_pk.pem'

def get_asn1_time(offset = datetime.timedelta(days=0)):
  time = datetime.datetime.now()
  time += offset
  time -= datetime.timedelta(hours=1)
  res = time.strftime('%Y%m%d%H%M%S') + 'Z'
  return res.encode('utf-8')

# Get timestamps
t_now = get_asn1_time()
t_after = get_asn1_time(datetime.timedelta(days=5*365))
t_update = get_asn1_time(datetime.timedelta(days=100))

if not os.path.exists(DIR):
    os.makedirs(DIR)

# Create Root pk and store it in main dir (s.t. it is kept offline)
root_k = crypto.PKey()
root_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(NET_DIR, ROOT_PK)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, root_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

# Create self-signed root certificate
root_cert = crypto.X509()
root_cert.set_version(VERSION)
root_cert.get_subject().CN = "root"
root_cert.get_subject().O = "iMovies"
root_cert.set_serial_number(0)
root_cert.set_notBefore(t_now)
root_cert.set_notAfter(t_after)
root_cert.set_issuer(root_cert.get_subject())
root_cert.set_pubkey(root_k)
root_cert.add_extensions([
  crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:1"),
  crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign")
])
root_cert.sign(root_k, 'sha256')

filename = os.path.join(NET_DIR, ROOT_CERT)
root_c = crypto.dump_certificate(crypto.FILETYPE_PEM, root_cert).decode("utf-8")
f = open(filename, "wt").write(root_c)
filename = os.path.join(DIR, ROOT_CERT)
f = open(filename, "wt").write(root_c)
filename = os.path.join(NET_DIR, ROOT_CERT2)
c = crypto.dump_certificate(crypto.FILETYPE_TEXT, root_cert).decode("utf-8")
f = open(filename, "wt").write(c)

crl = crypto.CRL()
crl.set_lastUpdate(t_now)
crl.set_nextUpdate(t_update)
crl.set_version(1)
crl.sign(root_cert, root_k, b'sha256')

filename = os.path.join(DIR, ROOT_CRL)
c = crypto.dump_crl(crypto.FILETYPE_PEM, crl).decode("utf-8")
f = open(filename, "wt").write(c)
filename = os.path.join(DIR, 'root_crl.txt')
c = crypto.dump_crl(crypto.FILETYPE_TEXT, crl).decode("utf-8")
f = open(filename, "wt").write(c)

net_ca_k = crypto.PKey()
net_ca_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(NET_DIR, NET_PK_FILE)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, net_ca_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

req = crypto.X509Req()
req.get_subject().CN = 'ica'
req.get_subject().O = "iMovies"
req.set_pubkey(net_ca_k)
req.sign(net_ca_k, 'sha256')
cert = crypto.X509()
cert.set_version(VERSION)
cert.set_subject(req.get_subject())
cert.set_serial_number(2)
cert.set_notBefore(t_now)
cert.set_notAfter(t_after)
cert.set_issuer(root_cert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
cert.add_extensions([
  crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE, pathlen:0"),
  crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign")
])
cert.sign(root_k, 'sha256')
net_ca_cert = cert

filename = os.path.join(NET_DIR, NET_CERT_FILE)
net_c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8")
f = open(filename, "wt").write(net_c)
filename = os.path.join(NET_DIR, 'network_ca_cert.txt')
c = crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode("utf-8")
f = open(filename, "wt").write(c)

host_k = crypto.PKey()
host_k.generate_key(crypto.TYPE_RSA, 2048)
filename = os.path.join(NET_DIR, WEBSERV_PK)
k_dump = crypto.dump_privatekey(crypto.FILETYPE_PEM, host_k).decode("utf-8")
f = open(filename, "wt").write(k_dump)

req = crypto.X509Req()
req.get_subject().CN = 'web'
req.get_subject().O = 'iMovies'
req.set_pubkey(host_k)
req.sign(host_k, 'sha256')
t_after = get_asn1_time(datetime.timedelta(days=5*365))
cert = crypto.X509()
cert.set_version(VERSION)
cert.set_subject(req.get_subject())
cert.set_serial_number(1)
cert.set_notBefore(t_now)
cert.set_notAfter(t_after)
cert.set_issuer(net_ca_cert.get_subject())
cert.set_subject(req.get_subject())
cert.set_pubkey(req.get_pubkey())
cert.add_extensions([
    crypto.X509Extension(
        b'extendedKeyUsage', False, b'serverAuth, clientAuth')
])

cert.sign(net_ca_k, 'sha256')

filename = os.path.join(NET_DIR, WEBSERV_CERT)
c = crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode("utf-8") + net_c
f = open(filename, "wt").write(c)