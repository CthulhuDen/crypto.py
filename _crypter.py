'''
Created on Aug 8, 2015

@author: cthulhu
'''
from cryptography.hazmat.backends import default_backend
from posix import urandom
from cryptography.hazmat.primitives.ciphers.base import Cipher
from cryptography.hazmat.primitives.ciphers import algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

'''
Configurable parameters - encryption algorithms/modes, tag length...
'''

_KEY_LENGTH = 16 # 16 for AES-128, 24 for AES-192, 32 for AES-256
_IV_LENGTH = 12
_AUTH_TAG_LENGTH = 16

def _get_cipher(key, iv, backend, tag = None):
    return Cipher(algorithms.AES(key), modes.GCM(iv, tag, _AUTH_TAG_LENGTH), backend)

def _get_paddings():
    sha1 = hashes.SHA1()
    return padding.OAEP(padding.MGF1(sha1), sha1, None)

'''
End of configurable parameters
'''

class Encrypter(object):
    '''
    Encrypter is used to encrypt text, using public key.
    The encrytion is done with generated random aes key, which is RSA-encrypted and prepended to the ciphertext.
    IV is pseudorandom key of 12 bytes, prepended to the ciphertext.
    The cipher used is aes-xxx-gcm. Authentication tag (128 bit) gets prepended to the ciphertext as well.
    '''

    def __init__(self, pubkeyFile):
        self._backend = default_backend()
        self._key = urandom(_KEY_LENGTH)

        pubkey = serialization.load_pem_public_key(open(pubkeyFile, "rb").read(), self._backend)
        self._encrypted_key = pubkey.encrypt(self._key, _get_paddings())

    def encrypt(self, data, metadata = None):
        if not isinstance(data, bytes):
            raise TypeError("data must be in bytes")

        if metadata is not None:
            raise NotImplementedError("metadata storage is not implemented yet")

        iv = urandom(_IV_LENGTH)
        encryptor = _get_cipher(self._key, iv, self._backend).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return self._encrypted_key + iv + encryptor.tag + ciphertext

class Decrypter(object):
    '''
    Decrypter descypts
    '''

    def __init__(self, privkeyFile):
        self._privkeyFile = privkeyFile
        self._backend = default_backend()

    def decrypt(self, data):
        if not isinstance(data, bytes):
            raise TypeError("encoded data must be in bytes")

        privkey = serialization.load_pem_private_key(open(self._privkeyFile, "rb").read(), None, self._backend)
        key_size = (privkey.key_size + 7) // 8
        encrypted_key, data = data[:key_size], data[key_size:]
        key = privkey.decrypt(encrypted_key, _get_paddings())
        iv, authentication_tag, ciphertext = \
            data[:_IV_LENGTH], data[_IV_LENGTH:_IV_LENGTH + _AUTH_TAG_LENGTH], data[_IV_LENGTH + _AUTH_TAG_LENGTH:]
        decryptor = _get_cipher(key, iv, self._backend, authentication_tag).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
