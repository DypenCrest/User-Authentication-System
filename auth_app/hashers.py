import hashlib
from django.contrib.auth.hashers import PBKDF2PasswordHasher
import binascii
import os
import secrets

SHA256_DIGEST_SIZE = hashlib.sha256().digest_size

class CustomPBKDF2SHA256PasswordHasher(PBKDF2PasswordHasher):
    # Custom password hasher that uses PBKDF2 with SHA256 algorithm for hashing passwords.

    algorithm = 'pbkdf2_sha256'
    digest = hashlib.sha256
    iterations = 10000
    digest_size = SHA256_DIGEST_SIZE

    def salt(self):
        return binascii.hexlify(os.urandom(16)).decode()

    def encode(self, password, salt, iterations=None):
        if not salt:
            salt = self.salt()
        if not iterations:
            iterations = self.iterations
        hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations, dklen=self.digest_size)
        hash = binascii.hexlify(hash).decode()
        return "%s$%s$%s" % (self.algorithm, salt, hash)

    def verify(self, password, encoded):
        algorithm, salt, hash = encoded.split('$', 2)
        assert algorithm == self.algorithm
        encoded_2 = self.encode(password, salt, iterations=self.iterations)
        return secrets.compare_digest(encoded, encoded_2)
