from ca import RootCA, InterCA
if __name__ == '__main__':
    root = RootCA()
    eca = InterCA(root, "eca")
    ica = InterCA(root, "ica")

    newcert = eca.create_certificate("Hans", "Ruedi", "hans@ruedi.ch", 12)
