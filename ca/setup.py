import os
import OpenSSL
from ca import RootCA, InterCA

# Create or load the three CA's
root = RootCA()
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

ica.create_certificate("ca", "server", "ca@imovies.ch", 3)
ica.create_certificate("db", "server", "db@imovies.ch", 3)
ica.create_certificate("web", "server", "web@imovies.ch", 2)

