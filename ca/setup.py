from ca import RootCA, InterCA

# Create or load the three CA's
root = RootCA()
ica = InterCA(root, "ica")
eca = InterCA(root, "eca")

# Create the certificate for the webserver
webcert = ica.create_certificate("wev", "server", "web@server", 1)