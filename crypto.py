#!/usr/bin/env python3
# encoding: utf-8

import sys
from _crypter import Encrypter, Decrypter
from cryptography.exceptions import InvalidTag

def encrypt(keyfile):
    encrypter = Encrypter(keyfile)
    data = encrypter.encrypt(sys.stdin.buffer.read())
    sys.stdout.buffer.write(data)
    return 0

def decrypt(keyfile):
    decrypter = Decrypter(keyfile)
    try:
        data = decrypter.decrypt(sys.stdin.buffer.read())
    except InvalidTag:
        sys.stderr.write("DECRYPTION FAILED: CIPHERTEXT INTEGRITY VIOLATED")
        return 1
    sys.stdout.buffer.write(data)
    return 0

def main():
    if len(sys.argv) < 3:
        print("Syntax: <method> <keyfile>")
        return 1
    methods = {
        'encrypt' : encrypt,
        'decrypt' : decrypt
    }
    if sys.argv[1] in methods:
        return methods[sys.argv[1]](sys.argv[2])
    print("First argument must be a method: either 'encrypt' or 'decrypt'")
    return 1

if __name__ == "__main__":
    sys.exit(main())
