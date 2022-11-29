import os
import OpenSSL
from ca import RootCA, InterCA

# Create or load the three CA's
root = RootCA()
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

#ica.create_certificate("ca", "server", "ca@imovies.ch", 3)
#ica.create_certificate("web", "server", "webserver@imovies.ch", 2)
#ica.revoke_certificate(2)


eca.create_certificate("ca", "admin", "caadmin@imovies.ch", 14351345)
eca.create_certificate("remo", "admin", "caadmin@imovies.ch", 1232134)
eca.create_certificate("tobias", "admin", "caadmin@imovies.ch", 3252534)

eca.revoke_certificate(2)