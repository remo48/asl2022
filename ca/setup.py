import os
import OpenSSL
from ca import RootCA, InterCA

# Create or load the three CA's
root = RootCA()
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

# Create the certificate for the webserver
firstname = "web"
lastname = "server"
email = "web@server.ch"
uid = 1
webcert = eca.create_certificate(firstname, lastname, email, uid)
