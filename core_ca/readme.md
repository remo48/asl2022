--------------------------------------
**Sign server and client certificates**
--------------------------------------

**Create directory**
mkdir /root/ca/
cd /root/ca
mkdir certs crl newcerts private ica eca
chmod 700 private
touch index.txt [keep track of signed certs]
echo 1000 > serial

**Create config file**
[copy the contents of openssl.cnf to /root/ca/openssl.cnf]

**Create and verify Root key/cert pair**
openssl genrsa -aes256 -out private/ca.key.pem 2048 (passphrase: root)
chmod 400 private/ca.key.pem
openssl req -config openssl.cnf -key private/ca.key.pem -new -x509 -days 1000 -sha256 -extensions v3_ca -out certs/ca.cert.pem (passphrase: root)
chmod 444 certs/ca.cert.pem
openssl x509 -noout -text -in certs/ca.cert.pem

**Create internal ca directory**
cd /root/ca/ica
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > /root/ca/ica/crlnumber [crlnumber is used to keep track of revoked certs]
vim openssl.cnf

**Create config file**
[copy the contents of openssl.cnf to /root/ca/ica/openssl.cnf]

**Create and verify ica key and cert**
cd /root/ca
openssl genrsa -aes256 -out ica/private/ica.key.pem 2048
chmod 400 ica/private/ica.key.pem
openssl req -config ica/openssl.cnf -new -sha256 -key ica/private/ica.key.pem -out ica/csr/ica.csr.pem (passphrase: root, commonName: Internal CA)
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 500 -notext -md sha256 -in ica/csr/ica.csr.pem -out ica/certs/ica.cert.pem
chmod 444 ica/certs/ica.cert.pem
openssl x509 -noout -text -in ica/certs/ica.cert.pem

**Create cert chain file**
cat ica/certs/ica.cert.pem certs/ca.cert.pem > ica/certs/ca-chain.cert.pem
chmod 444 ica/certs/ca-chain.cert.pem

**Create internal ca directory**
cd /root/ca/eca
mkdir certs crl csr newcerts private
chmod 700 private
touch index.txt
echo 1000 > serial
echo 1000 > /root/ca/eca/crlnumber
touch openssl.cnf
vim openssl.cnf

**Create config file**
[copy the contents of openssl.cnf to /root/ca/eca/openssl.cnf]

**Create and verify eca key and cert**
cd /root/ca
openssl genrsa -aes256 -out eca/private/eca.key.pem 2048
chmod 400 eca/private/eca.key.pem
openssl req -config eca/openssl.cnf -new -sha256 -key eca/private/eca.key.pem -out eca/csr/eca.csr.pem (passphrase: root)
openssl ca -config openssl.cnf -extensions v3_intermediate_ca -days 500 -notext -md sha256 -in eca/csr/eca.csr.pem -out eca/certs/eca.cert.pem
chmod 444 eca/certs/eca.cert.pem
openssl x509 -noout -text -in eca/certs/eca.cert.pem

**Create cert chain file**
cat eca/certs/eca.cert.pem certs/ca.cert.pem > eca/certs/ca-chain.cert.pem
chmod 444 eca/certs/ca-chain.cert.pem


--------------------------------------
**Sign server and client certificates using ECA (ICA is analogously)**
--------------------------------------

**Create Key: Example using www.example.com**
cd /root/ca
openssl genrsa -aes256 -out eca/private/www.example.com.key.pem 2048
chmod 400 eca/private/www.example.com.key.pem

**Create Cert**
openssl req -config eca/openssl.cnf -key eca/private/www.example.com.key.pem -new -sha256 -out eca/csr/www.example.com.csr.pem

openssl ca -config eca/openssl.cnf -extensions server_cert -days 375 -notext -md sha256 -in eca/csr/www.example.com.csr.pem -out eca/certs/www.example.com.cert.pem
chmod 444 ica/certs/www.example.com.cert.pem

**Verify Cert**
openssl x509 -noout -text -in ica/certs/www.example.com.cert.pem
openssl verify -CAfile ica/certs/ca-chain.cert.pem \ica/certs/www.example.com.cert.pem

**Revoke Certificate: Create CRL (Certificate Revocation List)**
openssl ca -config ica/openssl.cnf -gencrl -out ica/crl/ica.crl.pem
openssl crl -in ica/crl/ica.crl.pem -noout -text