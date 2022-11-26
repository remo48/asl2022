import os
import OpenSSL
from ca import RootCA, InterCA

# Create or load the three CA's
root = RootCA()
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

# Create certificates
# tlscert = ica.create_certificate(name = "tls")
# interncert = ica.create_certificate(name = "intern")
# dbcert = ica.create_certificate(name = "db")

print(eca.crl.get_revoked())
revoked = eca.crl.get_revoked()
for rvk in revoked:
    print(rvk.get_serial() == str(21).encode(), str(21).encode(), rvk.get_serial())