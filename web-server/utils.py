from cryptography.hazmat.primitives import hashes


def checkPassword(password, hash):
    digest = hashes.Hash(hashes.SHA1())
    digest.update(password.encode())
    return digest.finalize().hex() == hash


def createHash(password):
    digest = hashes.Hash(hashes.SHA1())
    digest.update(password.encode())
    return digest.finalize().hex()
