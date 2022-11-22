import os
import OpenSSL
from ca import RootCA, InterCA

# Create or load the three CA's
root = RootCA()
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

# Create certificates
tlscert = ica.create_certificate(name = "tls")
interncert = ica.create_certificate(name = "intern")
dbcert = ica.create_certificate(name = "db")

