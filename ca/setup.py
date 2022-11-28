import os
import OpenSSL
from ca import RootCA, InterCA

# Create or load the three CA's
root = RootCA()
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

ica.create_certificate("web", "server", "webserver@imovies.ch", 1)
#ica.revoke_certificate(2)